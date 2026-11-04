# AvastTrace v1.0 - Windows PowerShell 5.1, Windows 10/11
# Purpose: observe process starts and correlate them with Avast log changes.
# This is a read-only collector except for its own files, scheduled task, and
# the optional -EnableAudit flag. It never disables or excludes protection.
[CmdletBinding()]
param(
    [ValidateSet('Install','Monitor','Capture','Status','Uninstall')]
    [string]$Mode = 'Install',
    [switch]$EnableAudit,
    [datetime]$At = [datetime]::MinValue
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

function Capture-Incident([datetime]$When,[string]$Reason) {
    Ensure-Folder
    $from = $When.AddMinutes(-3)
    $to = $When.AddMinutes(3)
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
        Version='1.0'; Host=$env:COMPUTERNAME; Generated=(Get-Date).ToString('o')
        AlertAt=$When.ToString('o'); WindowFrom=$from.ToString('o');WindowTo=$to.ToString('o')
        Trigger=$Reason; WindowsConhost=$signature
        Security4688=[pscustomobject]@{
            Count=$security.Rows.Count; Error=$security.Error
            Truncated=$security.Truncated
            CommandLineCount=@($security.Rows | Where-Object { $_.CommandLine }).Count
            Records=$security.Rows
        }
        WMIProcessStarts=$processRows.ToArray()
        AvastFileInventory=$fileInventory.ToArray()
        AvastKeywordMatches=@($avastMatches.ToArray() | Select-Object -First 250)
        LiveProcesses=$live
        Limitations=@(
          'Keyword matches in Avast logs are NOT proof that a given process caused a block.',
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
    $summary.Add("ALERT: $($When.ToString('o')) | $Reason")
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
                if($line -match '(?i)IDP\.Generic|conhost\.exe|Behavior\s*Shield.*(block|threat|infect|detect)') {
                    Log-Json 'signals' ([pscustomobject]@{At=(Get-Date).ToString('o'); File=$file.FullName; Line=$line.Substring(0,[Math]::Min(1000,$line.Length))})
                    if(((Get-Date) - $script:LastAutoCapture).TotalSeconds -ge 60) {
                        $script:LastAutoCapture = Get-Date
                        try { [void](Capture-Incident -When (Get-Date) -Reason ('Avast log keyword: ' + $file.Name)) }
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
            $ev = Wait-Event -SourceIdentifier $source -Timeout 2
            while($null -ne $ev) {
                try {
                    $ne = $ev.SourceEventArgs.NewEvent
                    $id = [int]$ne.ProcessID
                    $parentId = [int]$ne.ParentProcessID
                    $name = [string]$ne.ProcessName
                    $extra = $null
                    $parent = $null
                    if($name -match $InterestingNames) {
                        $extra = Get-WindowsProcess -Id $id
                        $parent = Get-WindowsProcess -Id $parentId
                    }
                    Log-Json 'process' ([pscustomobject]@{
                        At=(Get-Date).ToString('o'); Name=$name; PID=$id; ParentPID=$parentId
                        WmiEventTime=[string]$ne.TIME_CREATED
                        Path=if($extra){$extra.Path}else{$null}
                        CommandLine=if($extra){$extra.CommandLine}else{$null}
                        ParentName=if($parent){$parent.Name}else{$null}
                        ParentCommandLine=if($parent){$parent.CommandLine}else{$null}
                        ParentStarted=if($parent){$parent.Started}else{$null}
                    })
                } catch { Log-Error "Process event handling failed: $($_.Exception.Message)" }
                finally { Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue }
                $ev = @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Select-Object -First 1)
                if($ev -is [array]) { if($ev.Count -eq 0){$ev=$null}else{$ev=$ev[0]} }
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

try {
    switch ($Mode) {
        'Install'   { Install }
        'Monitor'   { Monitor }
        'Capture'   {
            Ensure-Admin
            if($At -eq [datetime]::MinValue){$At=Get-Date}
            [void](Capture-Incident -When $At -Reason 'Manual capture')
        }
        'Status'    { Status }
        'Uninstall' { Uninstall }
    }
} catch {
    Log-Error "$Mode FATAL: $($_.Exception.Message)"
    Write-Error $_
    exit 1
}
