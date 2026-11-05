# AvastTrace v1.1.0 - Windows PowerShell 5.1, Windows 10/11
# Purpose: observe process starts and correlate them with Avast log changes.
# This is a read-only collector except for its own files, scheduled task, and
# the optional -EnableAudit flag. It never disables or excludes protection.
[CmdletBinding()]
param(
    [ValidateSet('Install','Monitor','Capture','Status','Uninstall','SelfTest')]
    [string]$Mode = 'Install',
    [switch]$EnableAudit,
    [datetime]$At = [datetime]::MinValue,
    [datetime]$DetectionAt = [datetime]::MinValue,
    [string]$TargetImage = ''
)

$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:ProgramData 'AvastTrace'
$ScriptTarget = Join-Path $Root 'AvastTrace.ps1'
$TaskName = 'AvastTrace-Collector'
$TaskPath = '\AvastTrace\'
$PSExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Utf8 = [System.Text.UTF8Encoding]::new($false)
$InterestingNames = '(?i)^(conhost|cmd|powershell|pwsh|wsl|wslhost|ssh|sshd|node|python|pythonw|ollama|opencode|codex|git|bash|wt|windowsterminal|webpnode\.controller|docker|docker desktop)\.exe$'
$AvastRoots = @(
    (Join-Path $env:ProgramData 'AVAST Software\Avast\report'),
    (Join-Path $env:ProgramData 'AVAST Software\Avast\log'),
    (Join-Path $env:ProgramData 'AVAST Software\Persistent Data\Avast\Logs')
)
$script:Offsets = @{}
$script:LastAutoCapture = [datetime]::MinValue

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (Is-Admin) { return }
    Write-Host 'Administrator access is needed; requesting UAC elevation...'
    $argv = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $PSCommandPath + '"'),'-Mode',$Mode)
    if ($EnableAudit) { $argv += '-EnableAudit' }
    if ($At -ne [datetime]::MinValue) { $argv += @('-At',('"' + $At.ToString('yyyy-MM-dd HH:mm:ss') + '"')) }
    if ($DetectionAt -ne [datetime]::MinValue) { $argv += @('-DetectionAt',('"' + $DetectionAt.ToString('yyyy-MM-dd HH:mm:ss') + '"')) }
    if ($TargetImage) { $argv += @('-TargetImage',('"' + $TargetImage + '"')) }
    $result = Start-Process -FilePath $PSExe -ArgumentList ($argv -join ' ') -Verb RunAs -Wait -PassThru
    if ($result.ExitCode -ne 0) { throw "Elevated child exited with code $($result.ExitCode)" }
    exit 0
}

function Ensure-Folder {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
}

function Secure-Folder {
    # SIDs work on non-English Windows. No ACL inheritance, no standard users.
    & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 1>$null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict C:\ProgramData\AvastTrace ACLs.' }
}

function Log-Json([string]$Name, [object]$Value) {
    $file = Join-Path $Root ($Name + '-' + (Get-Date).ToString('yyyyMMdd') + '.jsonl')
    $line = ConvertTo-Json -InputObject $Value -Compress -Depth 7
    [IO.File]::AppendAllText($file, $line + [Environment]::NewLine, $Utf8)
}

function Log-Error([string]$Description) {
    try {
        Ensure-Folder
        Log-Json 'errors' ([pscustomobject]@{At=(Get-Date).ToString('o'); Message=$Description})
    } catch { Write-Warning $Description }
}

function Get-AvastFiles {
    $list = @()
    foreach ($dir in $AvastRoots) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        try {
            $list += @(Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop |
                Where-Object { $_.Extension -match '^(?i)\.(log|txt|xml|json)$' })
        } catch { Log-Error "Avast folder inaccessible: $dir : $($_.Exception.Message)" }
    }
    return @($list | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 60)
}

function Read-FileBytes([string]$Path, [long]$Start, [int]$MaxBytes) {
    $fs = $null
    try {
        $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $fs = [System.IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        $actualStart = [Math]::Max(0L, [Math]::Min($Start,$fs.Length))
        if (($fs.Length - $actualStart) -gt $MaxBytes) {
            $actualStart = $fs.Length - $MaxBytes
        }
        [void]$fs.Seek($actualStart,[IO.SeekOrigin]::Begin)
        $count = [int][Math]::Min($MaxBytes, ($fs.Length - $actualStart))
        if ($count -le 0) { return [pscustomobject]@{Text=''; Length=$fs.Length; Dropped=0L} }
        $buffer = New-Object byte[] $count
        $n = $fs.Read($buffer,0,$count)
        $zeroes = 0
        for($i=1; $i -lt [Math]::Min($n,256); $i+=2) { if($buffer[$i] -eq 0){$zeroes++} }
        if($zeroes -gt 20) {
            $str = [Text.Encoding]::Unicode.GetString($buffer,0,$n)
        } else {
            $str = [Text.Encoding]::UTF8.GetString($buffer,0,$n)
        }
        return [pscustomobject]@{Text=$str; Length=$fs.Length; Dropped=([long]$actualStart - [long]$Start)}
    } finally { if($null -ne $fs) { $fs.Dispose() } }
}

function Get-WindowsProcess([int]$Id) {
    if ($Id -le 0) { return $null }
    try {
        $p = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $Id" -ErrorAction Stop
        if ($null -eq $p) { return $null }
        return [pscustomobject]@{
            PID=$p.ProcessId
            Name=$p.Name
            Path=$p.ExecutablePath
            CommandLine=$p.CommandLine
            ParentPID=$p.ParentProcessId
            Started=if ($p.CreationDate) { ([datetime]$p.CreationDate).ToString('o') } else { $null }
        }
    } catch { return $null }
}

function Get-Event4688([datetime]$From, [datetime]$To) {
    $events = @()
    $errorText = $null
    try {
        $query = @{LogName='Security';Id=4688;StartTime=$From;EndTime=$To}
        $events = @(Get-WinEvent -FilterHashtable $query -MaxEvents 3000 -ErrorAction Stop)
    } catch { $errorText = $_.Exception.Message }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ev in $events) {
        try {
            $xml = [xml]$ev.ToXml()
            $v = @{}
            foreach ($field in $xml.Event.EventData.Data) { $v[[string]$field.GetAttribute('Name')] = [string]$field.InnerText }
            $rows.Add([pscustomobject]@{
                At=$ev.TimeCreated.ToString('o'); EventRecordId=$ev.RecordId
                ProcessIdHex=$v['NewProcessId']; Process=$v['NewProcessName']
                ParentIdHex=$v['ProcessId']; Parent=$v['ParentProcessName']
                CommandLine=$v['CommandLine']; User=$v['SubjectUserName']
            })
        } catch { }
    }
    return [pscustomobject]@{Rows=@($rows.ToArray()); Error=$errorText; Truncated=($events.Count -ge 3000)}
}

# Process IDs in 4688 are hexadecimal strings; normalise them before joining
# creation events. This is an event-time join, not a current-process snapshot.
function Convert-PidKey([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        if ($Value -match '^0x[0-9a-fA-F]+$') {
            return ([Convert]::ToUInt64($Value.Substring(2),16)).ToString()
        }
        if ($Value -match '^[0-9]+$') { return ([UInt64]::Parse($Value)).ToString() }
    } catch { }
    return $null
}

function Get-ProcessChains([object[]]$Events,[datetime]$Anchor,[string]$TargetImage) {
    # Generic candidate selection: a caller may supply the alert's reported
    # executable (any name). Without it, show nearby process starts only.
    $ordered = @($Events | Where-Object { $_.At -and $_.Process } |
        Sort-Object { [datetime]$_.At })
    $byPid = @{}
    foreach($item in $ordered) {
        $key = Convert-PidKey ([string]$item.ProcessIdHex)
        if(-not $key) { continue }
        if(-not $byPid.ContainsKey($key)) {
            $byPid[$key] = New-Object 'System.Collections.Generic.List[object]'
        }
        $byPid[$key].Add($item)
    }
    $selection = @(
        foreach($item in $ordered) {
            $delta = (([datetime]$item.At) - $Anchor).TotalSeconds
            if ([math]::Abs($delta) -gt 30) { continue }
            if ($TargetImage) {
                $leaf = [IO.Path]::GetFileName([string]$item.Process)
                if (-not [string]::Equals($leaf,$TargetImage,[StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }
            } elseif ([math]::Abs($delta) -gt 5) {
                continue
            }
            [pscustomobject]@{Event=$item;DeltaSeconds=[math]::Round($delta,3)}
        }
    )
    $selection = @($selection | Sort-Object {
        [math]::Abs($_.DeltaSeconds)
    } | Select-Object -First 40)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach($candidate in $selection) {
        $trace = New-Object 'System.Collections.Generic.List[object]'
        $current = $candidate.Event
        $seen = @{}
        $unresolved = $null
        for($depth=0;$depth -lt 8 -and $null -ne $current;$depth++) {
            $recordKey = [string]$current.EventRecordId
            if($seen.ContainsKey($recordKey)) { break }
            $seen[$recordKey] = $true
            $trace.Add([pscustomobject]@{
                At=$current.At
                EventRecordId=$current.EventRecordId
                Process=$current.Process
                PID=$current.ProcessIdHex
                Parent=$current.Parent
                ParentPID=$current.ParentIdHex
                CommandLine=$current.CommandLine
            })
            $parentKey = Convert-PidKey ([string]$current.ParentIdHex)
            if(-not $parentKey) { $unresolved=$current.Parent; break }
            if(-not $byPid.ContainsKey($parentKey)) { $unresolved=$current.Parent; break }
            $older = @($byPid[$parentKey] | Where-Object {
                ([datetime]$_.At) -le ([datetime]$current.At) -and
                ([datetime]$_.At) -ge ([datetime]$current.At).AddHours(-4)
            } | Sort-Object { [datetime]$_.At } -Descending | Select-Object -First 1)
            if($older.Count -eq 0) { $unresolved=$current.Parent; break }
            # PID reuse guard: the 4688 parent's image path must agree with the
            # actual recorded name if both are supplied.
            if($current.Parent -and $older[0].Process -and
               -not [string]::Equals([string]$current.Parent,[string]$older[0].Process,[StringComparison]::OrdinalIgnoreCase)) {
                $unresolved=$current.Parent
                break
            }
            $current = $older[0]
        }
        $chain = @($trace.ToArray())
        [array]::Reverse($chain)
        $out.Add([pscustomobject]@{
            DeltaSeconds=$candidate.DeltaSeconds
            EventRecordId=$candidate.Event.EventRecordId
            Process=$candidate.Event.Process
            PID=$candidate.Event.ProcessIdHex
            Parent=$candidate.Event.Parent
            CommandLine=$candidate.Event.CommandLine
            Chain=$chain
            UnresolvedParent=$unresolved
            Interpretation='PROCESS_START_PROXIMITY_AND_4688_ANCESTRY_ONLY_NOT_AVAST_CAUSALITY'
        })
    }
    return [pscustomobject]@{
        TargetImage=if($TargetImage){$TargetImage}else{$null}
        SelectedCount=$out.Count
        Truncated=($selection.Count -ge 40)
        Candidates=$out.ToArray()
        Evidence='Windows Security Event 4688; PID + preceding timestamp + parent image path'
        Attribution='Not established without an Avast event-to-process identifier or controlled reproduction'
    }
}

function Capture-Incident([datetime]$When,[string]$Reason,[string]$TargetImage='', [datetime]$DetectionAt=[datetime]::MinValue) {
    Ensure-Folder
    # -When is a human-observed popup time, NOT necessarily Avast detection time.
    $anchor = $When
    if($DetectionAt -ne [datetime]::MinValue) { $anchor = $DetectionAt }
    $from = $anchor.AddMinutes(-3)
    $to = $anchor.AddMinutes(3)
    $id = $env:COMPUTERNAME + '-' + (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
    $dest = Join-Path $Root ('incident-' + $id + '.json')
    $processRows = New-Object 'System.Collections.Generic.List[object]'
    foreach($file in @(Get-ChildItem -LiteralPath $Root -Filter 'process-*.jsonl' -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 3)) {
        foreach($line in @(Get-Content -LiteralPath $file.FullName -Tail 15000 -ErrorAction SilentlyContinue)) {
            try {
                $r = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                $t = [datetime]$r.At
                if($t -ge $from -and $t -le $to) { $processRows.Add($r) }
            } catch { }
        }
    }
    $security = Get-Event4688 -From $from -To $to
    $correlations = Get-ProcessChains -Events $security.Rows -Anchor $anchor -TargetImage $TargetImage
    $avastMatches = New-Object 'System.Collections.Generic.List[object]'
    $fileInventory = New-Object 'System.Collections.Generic.List[object]'
    foreach($file in @(Get-AvastFiles)) {
        try {
            if($file.LastWriteTime -lt $When.AddDays(-2)) { continue }
            $chunk = Read-FileBytes -Path $file.FullName -Start 0 -MaxBytes 2097152
            $fileInventory.Add([pscustomobject]@{File=$file.FullName; LastWrite=$file.LastWriteTime.ToString('o'); Bytes=$file.Length; TailTruncated=($file.Length -gt 2097152)})
            foreach($line in @($chunk.Text -split '[\r\n]+')) {
                if($line -match '(?i)IDP\.Generic|conhost\.exe|Behavior\s*Shield|blocked\b|threat\b') {
                    $avastMatches.Add([pscustomobject]@{File=$file.FullName; Line=$line.Substring(0,[Math]::Min(1000,$line.Length))})
                    if($avastMatches.Count -ge 250) { break }
                }
            }
        } catch {
            $fileInventory.Add([pscustomobject]@{File=$file.FullName; Error=$_.Exception.Message})
        }
    }
    $live = @()
    try {
        $live = @(Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { $_.Name -match $InterestingNames } |
            Select-Object -First 120 ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate)
    } catch { Log-Error "Live process snapshot unavailable: $($_.Exception.Message)" }
    $signature = $null
    $windowsConhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
    try {
        if (Test-Path -LiteralPath $windowsConhost -PathType Leaf) {
            $sig = Get-AuthenticodeSignature -LiteralPath $windowsConhost
            $hash = Get-FileHash -LiteralPath $windowsConhost -Algorithm SHA256
            $signature = [pscustomobject]@{
                Path=$windowsConhost; SHA256=$hash.Hash
                SignatureStatus=[string]$sig.Status
                Signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null}
            }
        }
    } catch { $signature = [pscustomobject]@{Error=$_.Exception.Message} }
    $report = [pscustomobject]@{
        Version='1.1.0'; Host=$env:COMPUTERNAME; Generated=(Get-Date).ToString('o')
        AlertAt=$When.ToString('o') # deprecated: observation only, NOT proven detection
        PopupObservedAt=$When.ToString('o')
        AvastDetectionAt=if($DetectionAt -ne [datetime]::MinValue){$DetectionAt.ToString('o')}else{$null}
        DetectionTimestampStatus=if($DetectionAt -ne [datetime]::MinValue){'SUPPLIED_NOT_INDEPENDENTLY_VERIFIED'}else{'UNKNOWN'}
        AnalysisAnchorAt=$anchor.ToString('o')
        WindowFrom=$from.ToString('o');WindowTo=$to.ToString('o')
        Trigger=$Reason; WindowsConhost=$signature
        Security4688=[pscustomobject]@{
            Count=$security.Rows.Count; Error=$security.Error
            Truncated=$security.Truncated
            CommandLineCount=@($security.Rows | Where-Object { $_.CommandLine }).Count
            Records=$security.Rows
        }
        WMIProcessStarts=$processRows.ToArray()
        ProcessCorrelation=$correlations
        AvastFileInventory=$fileInventory.ToArray()
        AvastKeywordMatches=@($avastMatches.ToArray() | Select-Object -First 250)
        LiveProcesses=$live
        Limitations=@(
          'Keyword matches in Avast logs are NOT proof that a given process caused a block.',
          'Popup observation time may be later than actual detection; an unknown Avast detection time is never inferred.',
          'A PID-based ancestor chain with nearby timestamps is a candidate, not a confirmed Avast trigger.',
          'If 4688 auditing was disabled at the event time, historical command lines cannot be reconstructed.',
          'Avast internal detection rules are not necessarily included in its plaintext log files.',
          'Very short-lived or pre-execution-blocked processes may not appear in WMI logs.'
        )
    }
    [IO.File]::WriteAllText($dest,(ConvertTo-Json -InputObject $report -Depth 9),$Utf8)
    # Small human-readable index; raw detailed evidence remains in the JSON.
    $near = @($security.Rows | Where-Object {
        $t = [datetime]$_.At
        ($t -ge $When.AddSeconds(-30)) -and ($t -le $When.AddSeconds(30))
    } | Select-Object -First 100)
    $conhosts = @($security.Rows | Where-Object { $_.Process -match '(?i)\\conhost\.exe$' })
    $summary = New-Object 'System.Collections.Generic.List[string]'
    $summary.Add("HOST: $env:COMPUTERNAME")
    $summary.Add("POPUP OBSERVED: $($When.ToString('o')) | $Reason")
    $summary.Add("AVAST DETECTION TIME: $(if($DetectionAt -ne [datetime]::MinValue){$DetectionAt.ToString('o')}else{'UNKNOWN (popup may be delayed)'})")
    $summary.Add("TARGET IMAGE: $(if($TargetImage){$TargetImage}else{'unspecified; nearest process starts shown'})")
    $summary.Add("CORRELATION: CANDIDATES ONLY (never an attribution verdict)")
    $summary.Add("Window: $($from.ToString('o')) to $($to.ToString('o'))")
    $summary.Add("4688 Count: $($security.Rows.Count); Command lines present: $(@($security.Rows | Where-Object { $_.CommandLine }).Count)")
    $summary.Add("WMI Starts: $($processRows.Count); Avast Matches: $($avastMatches.Count)")
    $summary.Add('')
    $summary.Add('CONHOST PROCESS CREATIONS IN +/-3 MIN (NOT automatically the cause):')
    foreach($r in $conhosts | Select-Object -First 50) {
        $summary.Add("[$($r.At)] PID=$($r.ProcessIdHex) Parent=$($r.Parent) Command=$($r.CommandLine)")
    }
    $summary.Add('')
    $summary.Add('OTHER PROCESS CREATIONS IN +/-30 SEC:')
    foreach($r in $near) {
        $summary.Add("[$($r.At)] $($r.Process) Parent=$($r.Parent) Command=$($r.CommandLine)")
    }
    $summary.Add('')
    $summary.Add('')
    $summary.Add('CLOSEST EXECUTION CHAINS (4688 RECORDS, NOT PROVEN AVAST CAUSE):')
    foreach($c in @($correlations.Candidates | Select-Object -First 20)) {
        $summary.Add("Delta=$($c.DeltaSeconds)s PID=$($c.PID) Image=$($c.Process)")
        if($c.UnresolvedParent) {
            $summary.Add("  Missing recorded ancestor: $($c.UnresolvedParent)")
        }
        foreach($step in $c.Chain) {
            $summary.Add("  -> [$($step.At)] $($step.Process) PID=$($step.PID)")
            if($step.CommandLine) { $summary.Add("     CMD: $($step.CommandLine)") }
        }
    }
    $summary.Add('NOTE: source-code call sites cannot be recovered from 4688 alone; locate the recorded commands in project source.')
    $summary.Add('NOTE: raw Avast keyword matches have unverified event times; 250 lines are NOT 250 detections.')
    $summary.Add('Avast text matches are only possible context, not attribution evidence.')
    $summaryPath = [IO.Path]::ChangeExtension($dest,'.summary.txt')
    [IO.File]::WriteAllLines($summaryPath,$summary.ToArray(),$Utf8)
    Write-Host "Summary report: $summaryPath"
    Write-Host "Incident report: $dest"
    Write-Host "  4688: $($security.Rows.Count); WMI: $($processRows.Count); Avast text matches: $($avastMatches.Count)"
    if($security.Error){ Write-Warning "4688 unavailable: $($security.Error)" }
    return $dest
}

function Scan-AvastAppend {
    foreach($file in @(Get-AvastFiles)) {
        try {
            if(-not $script:Offsets.ContainsKey($file.FullName)) {
                $script:Offsets[$file.FullName] = [long]$file.Length
                continue
            }
            $offset = [long]$script:Offsets[$file.FullName]
            if($file.Length -eq $offset) { continue }
            if($file.Length -lt $offset) { $offset = 0L }
            $chunk = Read-FileBytes -Path $file.FullName -Start $offset -MaxBytes 131072
            $script:Offsets[$file.FullName] = [long]$chunk.Length
            if($chunk.Dropped -gt 0){ Log-Error "Skipped $($chunk.Dropped) bytes in $($file.FullName) due to unusually large log append." }
            foreach($line in @($chunk.Text -split '[\r\n]+')) {
                if($line -match '(?i)IDP\.Generic|Behavior\s*Shield.*(block|threat|infect|detect)') {
                    Log-Json 'signals' ([pscustomobject]@{At=(Get-Date).ToString('o'); File=$file.FullName; Line=$line.Substring(0,[Math]::Min(1000,$line.Length))})
                    if(((Get-Date) - $script:LastAutoCapture).TotalSeconds -ge 60) {
                        $script:LastAutoCapture = Get-Date
                        $hint = ''
                        if($line -match '(?i)\b([a-z0-9_.-]+\.exe)\b') { $hint = $Matches[1] }
                        try { [void](Capture-Incident -When (Get-Date) -Reason ('Avast log append observed (detection time unverified): ' + $file.Name) -TargetImage $hint) }
                        catch { Log-Error "Auto capture failed: $($_.Exception.Message)" }
                    }
                }
            }
        } catch { Log-Error "Avast log scan failed for $($file.FullName): $($_.Exception.Message)" }
    }
}

function Monitor {
    Ensure-Folder
    Write-Host "AvastTrace monitoring $env:COMPUTERNAME"
    $source = 'AvastTrace.ProcessStart'
    try {
        Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier $source -ErrorAction Stop | Out-Null
        $lastScan = [datetime]::MinValue
        $lastBeat = [datetime]::MinValue
        while($true) {
            # A busy host may deliver an unbounded process-event stream. Yield after
            # each batch so heartbeat and Avast log scanning never starve.
            $ev = Wait-Event -SourceIdentifier $source -Timeout 2
            $processed = 0
            while($null -ne $ev -and $processed -lt 100) {
                try {
                    $ne = $ev.SourceEventArgs.NewEvent
                    $id = [int]$ne.ProcessID
                    $parentId = [int]$ne.ParentProcessID
                    $name = [string]$ne.ProcessName
                    $observed = Get-Date
                    $started = $observed
                    try {
                        $ticks = [long][string]$ne.TIME_CREATED
                        if ($ticks -gt 0) {
                            $started = [datetime]::FromFileTimeUtc($ticks).ToLocalTime()
                        }
                    } catch { }
                    # Do not synchronously query Win32_Process for every event.
                    # On busy machines it stalls the event consumer and can fetch a
                    # DIFFERENT process after a short-lived PID is reused. For exact
                    # command lines and full image paths use Security event 4688.
                    Log-Json 'process' ([pscustomobject]@{
                        At=$started.ToString('o')
                        ObservedAt=$observed.ToString('o')
                        QueueDelaySeconds=[math]::Round(($observed - $started).TotalSeconds,3)
                        Name=$name; PID=$id; ParentPID=$parentId
                        WmiEventTime=[string]$ne.TIME_CREATED
                        Path=$null; CommandLine=$null; ParentName=$null
                        ParentCommandLine=$null; ParentStarted=$null
                    })
                } catch { Log-Error "Process event handling failed: $($_.Exception.Message)" }
                finally {
                    Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue
                    $processed++
                }
                $ev = @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Select-Object -First 1)
                if($ev -is [array]) {
                    if($ev.Count -eq 0){$ev=$null}else{$ev=$ev[0]}
                }
            }
            if(((Get-Date) - $lastScan).TotalSeconds -ge 5) {
                Scan-AvastAppend
                $lastScan = Get-Date
            }
            if(((Get-Date) - $lastBeat).TotalSeconds -ge 30) {
                [IO.File]::WriteAllText((Join-Path $Root 'heartbeat.txt'), (Get-Date).ToString('o'), $Utf8)
                $lastBeat = Get-Date
            }
        }
    } finally { Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue }
}

function Enable-ProcessAudit {
    Write-Warning 'OPT-IN: Windows Security Event 4688 will include plaintext command lines (possibly passwords/tokens).'
    $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $old = $null
    try { $old = Get-ItemPropertyValue -Path $policy -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction Stop } catch {}
    $before = [pscustomobject]@{
        At=(Get-Date).ToString('o'); PreviousCommandLinePolicy=$old
        PreviousAuditpol=(& auditpol.exe /get '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}' 2>&1 | Out-String)
    }
    $backup = Join-Path $Root ('audit-before-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.json')
    [IO.File]::WriteAllText($backup, (ConvertTo-Json -InputObject $before -Depth 4), $Utf8)
    & auditpol.exe /set '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}' /success:enable | Out-Null
    if($LASTEXITCODE -ne 0){ throw 'auditpol process creation audit failed; audit settings not confirmed.' }
    if(-not (Test-Path -LiteralPath $policy)) { New-Item -Path $policy -Force | Out-Null }
    New-ItemProperty -Path $policy -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "4688 auditing opt-in enabled; previous state saved: $backup"
    Write-Host 'Domain policies can override these settings; Status/Capture will reveal missing events.'
}

function Install {
    Ensure-Admin
    Ensure-Folder
    Secure-Folder
    if ($PSCommandPath -ne $ScriptTarget) { Copy-Item -LiteralPath $PSCommandPath -Destination $ScriptTarget -Force }
    if($EnableAudit) { Enable-ProcessAudit }
    $action = New-ScheduledTaskAction -Execute $PSExe -Argument ('-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $ScriptTarget + '" -Mode Monitor')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    try { Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue } catch {}
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    Write-Host "Installed on $env:COMPUTERNAME. Script: $ScriptTarget"
    Write-Host "Scheduled task: $TaskPath$TaskName (SYSTEM, startup + started now)"
    Write-Host "Records: $Root"
    Write-Host "Check: powershell.exe -NoProfile -File `"$ScriptTarget`" -Mode Status"
}

function Status {
    Ensure-Admin
    Write-Host "HOST: $env:COMPUTERNAME"
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath
        Write-Host "Task: $($task.State); LastResult: $($info.LastTaskResult); LastRun: $($info.LastRunTime)"
    } catch { Write-Warning "Task unavailable: $($_.Exception.Message)" }
    $beat = Join-Path $Root 'heartbeat.txt'
    if(Test-Path $beat) { Write-Host "Heartbeat: $(Get-Content -LiteralPath $beat -Raw)" }
    else { Write-Warning 'No heartbeat yet; monitor may not be running.' }
    try {
        & auditpol.exe /get '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}'
        $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        $v = Get-ItemPropertyValue -Path $policy -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
        Write-Host "Command-line policy flag: $v (1 means enabled)"
    } catch { Write-Warning "Audit status not readable: $($_.Exception.Message)" }
    if(Test-Path $Root) {
        Get-ChildItem -LiteralPath $Root -File | Sort-Object LastWriteTime -Descending |
            Select-Object -First 12 Name,Length,LastWriteTime | Format-Table -AutoSize
    }
}

function Uninstall {
    Ensure-Admin
    try {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
        Write-Host 'Collector task removed.'
    } catch { Write-Warning "Task was not removed or not present: $($_.Exception.Message)" }
    Write-Host "Evidence retained: $Root"
    Write-Warning 'Any opt-in 4688 auditing is NOT reverted automatically; inspect audit-before-*.json before changing system policy.'
}


function Invoke-CorrelationSelfTest {
    $start = [datetime]'2026-01-01T12:00:00'
    $records = @(
        [pscustomobject]@{At=$start.AddSeconds(-3).ToString('o');EventRecordId=11;ProcessIdHex='0x10';ParentIdHex='0x04';Process='C:\test\DemoController.exe';Parent='C:\Windows\explorer.exe';CommandLine='DemoController.exe'},
        [pscustomobject]@{At=$start.AddSeconds(-2).ToString('o');EventRecordId=12;ProcessIdHex='0x20';ParentIdHex='0x10';Process='C:\Windows\cmd.exe';Parent='C:\test\DemoController.exe';CommandLine='cmd.exe /c npm.cmd run runtime:status'},
        [pscustomobject]@{At=$start.AddSeconds(-1).ToString('o');EventRecordId=13;ProcessIdHex='0x30';ParentIdHex='0x20';Process='C:\Program Files\nodejs\node.exe';Parent='C:\Windows\cmd.exe';CommandLine='node scripts/runtime/runtime-manager.js status --json'},
        [pscustomobject]@{At=$start.AddMilliseconds(250).ToString('o');EventRecordId=14;ProcessIdHex='0x40';ParentIdHex='0x30';Process='C:\Windows\conhost.exe';Parent='C:\Program Files\nodejs\node.exe';CommandLine='conhost.exe 0xffffffff -ForceV1'}
    )
    $result = Get-ProcessChains -Events $records -Anchor $start -TargetImage 'conhost.exe'
    if($result.SelectedCount -ne 1) { throw 'Expected one target candidate' }
    $chain = @($result.Candidates[0].Chain)
    if($chain.Count -ne 4) { throw "Wrong ancestry length: $($chain.Count)" }
    if($chain[0].CommandLine -ne 'DemoController.exe' -or
       $chain[2].CommandLine -notmatch 'runtime-manager\.js' -or
       $chain[3].Process -notmatch 'conhost.exe') { throw 'Expected command ancestry missing' }
    $none = Get-ProcessChains -Events $records -Anchor $start -TargetImage 'notpresent.exe'
    if($none.SelectedCount -ne 0) { throw 'Unexpected target false positive' }
    Write-Host 'PASS synthetic 4688 process ancestry and target filtering'
}

try {
    switch ($Mode) {
        'Install'   { Install }
        'Monitor'   { Monitor }
        'Capture'   {
            Ensure-Admin
            if($At -eq [datetime]::MinValue){$At=Get-Date}
            [void](Capture-Incident -When $At -Reason 'Manual popup observation' -TargetImage $TargetImage -DetectionAt $DetectionAt)
        }
        'Status'    { Status }
        'SelfTest' { Invoke-CorrelationSelfTest }
        'Uninstall' { Uninstall }
    }
} catch {
    Log-Error "$Mode FATAL: $($_.Exception.Message)"
    Write-Error $_
    exit 1
}
