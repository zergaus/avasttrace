# AvastTrace public HTTPS bootstrapper (Windows PowerShell 5.1)
# Downloads the collector and verifies its SHA-256 before invoking Install.
# No Invoke-Expression, no antivirus exclusions, no remote log uploads.
[CmdletBinding()]
param(
    [switch]$EnableAudit
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'https://raw.githubusercontent.com/zergaus/avasttrace/main'
$work = Join-Path ([IO.Path]::GetTempPath()) ('AvastTrace-' + [guid]::NewGuid().ToString('N'))
$collector = Join-Path $work 'AvastTrace.ps1'
$manifest = Join-Path $work 'SHA256SUMS.txt'
$exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

try {
    if (-not [Environment]::OSVersion.Platform.Equals([PlatformID]::Win32NT)) {
        throw 'AvastTrace requires Windows.'
    }
    [void](New-Item -ItemType Directory -Path $work -Force)

    # Explicit HTTPS sources; no arguments from an untrusted manifest become URLs.
    Invoke-WebRequest -Uri ($base + '/AvastTrace.ps1') -OutFile $collector -UseBasicParsing
    Invoke-WebRequest -Uri ($base + '/SHA256SUMS.txt') -OutFile $manifest -UseBasicParsing

    $expected = $null
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        if ($line -match '^([a-fA-F0-9]{64})\s+\*?AvastTrace\.ps1\s*$') {
            if ($null -ne $expected) { throw 'SHA256SUMS.txt contains duplicate AvastTrace.ps1 entries.' }
            $expected = $matches[1].ToUpperInvariant()
        }
    }
    if ($null -eq $expected) {
        throw 'Expected SHA-256 for AvastTrace.ps1 is missing from the manifest.'
    }
    $actual = (Get-FileHash -LiteralPath $collector -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -cne $expected) {
        throw "SHA-256 mismatch. Expected $expected; downloaded $actual. Installation aborted."
    }

    Write-Host "AvastTrace SHA-256 verified: $actual"
    Write-Host 'Downloaded collector verified against repository manifest.'
    Write-Warning 'Both file and checksum come from the same GitHub repository; review the source before execution.'

    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                   $collector, '-Mode', 'Install')
    if ($EnableAudit) { $arguments += '-EnableAudit' }
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Collector installer failed with exit code $LASTEXITCODE"
    }
    Write-Host 'Installer finished. Use -Mode Status on C:\ProgramData\AvastTrace\AvastTrace.ps1 to verify collection.'
}
finally {
    # Avoid leaving a second executable copy in a broadly accessible temp folder.
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
