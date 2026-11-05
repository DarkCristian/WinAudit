#requires -Version 5.1
<#
.SYNOPSIS
  Checks or installs Microsoft's RSAT Active Directory PowerShell module.
.DESCRIPTION
  On Windows client uses the Windows Capability. On Windows Server uses
  the ServerManager feature. No third-party downloads or WinRM changes.
#>
[CmdletBinding()]
param([switch]$Install)
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host 'ActiveDirectory PowerShell module is already installed.' -ForegroundColor Green
    return
}
if (-not $Install) {
    Write-Warning 'RSAT Active Directory module is missing.'
    Write-Host 'To install, open Windows PowerShell as Administrator and run:'
    Write-Host '  .\Install-Prerequisites.ps1 -Install'
    return
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Installation requires an elevated PowerShell session.'
}
$os=Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) {
    $capability='Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    if (-not (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue)) {
        throw 'Windows capability installation is unavailable. Use supported Windows 10/11 Pro, Enterprise or Education.'
    }
    $status=Get-WindowsCapability -Online -Name $capability
    if ($status.State -ne 'Installed') {
        Write-Host 'Installing Microsoft RSAT Active Directory capability...'
        Add-WindowsCapability -Online -Name $capability | Out-Host
    }
} else {
    Import-Module ServerManager -ErrorAction Stop
    Write-Host 'Installing RSAT-AD-PowerShell Windows Server feature...'
    Install-WindowsFeature -Name RSAT-AD-PowerShell | Out-Host
}
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host 'ActiveDirectory module available.' -ForegroundColor Green
} else {
    Write-Warning 'Installation completed or is pending, but the module is not yet visible. Review installation output and reboot if requested.'
}
