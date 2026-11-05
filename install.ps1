#requires -Version 5.1
<#
.SYNOPSIS
  WinAudit one-command launcher from the official GitHub repository.
.NOTES
  Downloads the main script and its modules into a temporary directory.
  No persistent installation, privilege elevation, or RSAT installation.
#>
$ErrorActionPreference = 'Stop'
$base = 'https://raw.githubusercontent.com/DarkCristian/WinAudit/main'
$root = Join-Path ([IO.Path]::GetTempPath()) ('WinAudit-' + [guid]::NewGuid().ToString('N'))
$modules = Join-Path $root 'Modules'
$paths = @('WinAudit.ps1','Modules/Reputation.psm1','Modules/Core.psm1','Modules/Events.psm1','Modules/Directory.psm1')
try {
    [void](New-Item -Path $modules -ItemType Directory -Force)
    foreach ($path in $paths) {
        $url = "$base/$($path.Replace('\\','/'))"
        $destination = Join-Path $root ($path.Replace('/', [IO.Path]::DirectorySeparatorChar))
        Write-Host "Downloading $path..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing -ErrorAction Stop
        if ((Get-Item -LiteralPath $destination).Length -eq 0) { throw "Empty download: $path" }
    }
    Write-Host 'Starting WinAudit...' -ForegroundColor Green
    & (Join-Path $root 'WinAudit.ps1')
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
