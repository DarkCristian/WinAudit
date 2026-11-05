#requires -Version 5.1
<#
.SYNOPSIS
  WinAudit - read-only Windows security auditing console.
.DESCRIPTION
  Interactive local, remote and Active Directory inventory auditing.
  Requires Windows. Remote access requires authorized PowerShell Remoting.
#>
[CmdletBinding()]
param(
    [int]$PIDToAudit = 0,
    [switch]$FullScan,
    [string]$ComputerName,
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [string]$ReportDirectory = (Join-Path $env:USERPROFILE 'WinAudit-Reports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $script:Root 'Modules\Core.psm1') -Force
Import-Module (Join-Path $script:Root 'Modules\Events.psm1') -Force
Import-Module (Join-Path $script:Root 'Modules\Directory.psm1') -Force

function Show-Header {
    Clear-Host
    Write-Host '  __        ___         _             _ _ _   ' -ForegroundColor Cyan
    Write-Host '  \ \      / (_)_ __   / \  _   _  __| (_) |_ ' -ForegroundColor Cyan
    Write-Host '   \ \ /\ / /| | ''_ \ / _ \| | | |/ _` | | __|' -ForegroundColor Cyan
    Write-Host '    \ V  V / | | | | / ___ \ |_| | (_| | | |_ ' -ForegroundColor Cyan
    Write-Host '     \_/\_/  |_|_| |_/_/   \_\__,_|\__,_|_|\__|' -ForegroundColor Cyan
    Write-Host '  WINDOWS SECURITY & FORENSIC AUDITOR' -ForegroundColor Gray
    Write-Host '  ------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  READ-ONLY | Local / Remote / Active Directory' -ForegroundColor Green
    Write-Host ''
}
function Pause-Menu { [void](Read-Host 'Press ENTER to continue') }
function Read-Number([string]$Prompt) {
    $value = Read-Host $Prompt
    $number = 0
    if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1) { throw 'Enter a positive integer.' }
    return $number
}
function Show-Result($Data) {
    if ($null -eq $Data -or @($Data).Count -eq 0) { Write-Host 'No results.' -ForegroundColor Yellow; return }
    $Data | Format-Table -AutoSize | Out-Host
}
function Invoke-LocalProcesses {
    $items = @(Get-WAProcesses)
    Show-Result ($items | Select-Object -First 40 Name,ProcessId,ParentProcessId,ExecutablePath)
    Write-Host ("Found {0} processes. Showing first 40." -f $items.Count) -ForegroundColor Gray
    return $items
}
function Invoke-PidInvestigation {
    $id = Read-Number 'Enter PID (e.g. 1234)'
    $proc = @(Get-WAProcesses | Where-Object { $_.ProcessId -eq $id })
    if ($proc.Count -eq 0) {
        Write-Host 'PID not running. Historical events may still be available.' -ForegroundColor Yellow
    } else {
        $proc | Format-List | Out-Host
        if ($proc[0].ExecutablePath) {
            Get-WAFileEvidence -Path $proc[0].ExecutablePath | Format-List | Out-Host
        }
    }
    $events = @(Get-WAEvents -TargetPid $id -StartTime $StartTime -EndTime $EndTime)
    Show-Result ($events | Select-Object -First 35 TimeCreated,LogName,Id,MatchedField,Summary)
    return [pscustomobject]@{ Process=$proc; Events=$events }
}
function Invoke-RemoteAudit {
    $hostName = Read-Host 'Computer FQDN (e.g. pc001.ad.example.com)'
    if ([string]::IsNullOrWhiteSpace($hostName)) { throw 'Computer name is required.' }
    $credential = Get-Credential -Message 'Authorized remote Windows credentials'
    $result = Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    } -ErrorAction Stop
    Show-Result ($result | Select-Object -First 40 Name,ProcessId,ParentProcessId,ExecutablePath)
    return $result
}
function Invoke-DirectoryInventory {
    $server = Read-Host 'Domain/DC FQDN (e.g. dc01.ad.example.com)'
    $base = Read-Host 'Optional OU DN (blank for default naming context)'
    $credential = Get-Credential -Message 'Authorized directory read credentials'
    $args = @{ Server=$server; Credential=$credential }
    if (-not [string]::IsNullOrWhiteSpace($base)) { $args.SearchBase=$base }
    $items = @(Get-WADirectoryComputers @args)
    Show-Result ($items | Select-Object -First 100 Name,DNSHostName,OperatingSystem,Enabled)
    Write-Host ("Directory objects: {0}. AD inventory does not establish remote reachability." -f $items.Count)
    return $items
}
function Save-Report($Data, [string]$Name) {
    if ($null -eq $Data) { return }
    $path = Export-WAReport -Data $Data -Directory $ReportDirectory -Prefix $Name
    Write-Host "Report saved: $path" -ForegroundColor Green
}
if ($EndTime -lt $StartTime) { throw 'EndTime must be later than StartTime.' }
if ($PIDToAudit -gt 0) {
    Save-Report -Data (Get-WAEvents -TargetPid $PIDToAudit -StartTime $StartTime -EndTime $EndTime) -Name 'pid-events'
    return
}
if ($ComputerName) {
    $credential = Get-Credential -Message 'Authorized remote Windows credentials'
    $data = Invoke-Command -ComputerName $ComputerName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    }
    Save-Report -Data $data -Name 'remote-processes'
    return
}
if ($FullScan) {
    Save-Report -Data (Get-WAProcesses) -Name 'local-processes'
    return
}
while ($true) {
    Show-Header
    Write-Host '  [1] List local processes'
    Write-Host '  [2] Investigate PID + Windows event logs'
    Write-Host '  [3] Remote process inventory (WinRM)'
    Write-Host '  [4] Active Directory computer inventory'
    Write-Host '  [5] Full local process inventory + JSON report'
    Write-Host '  [0] Exit'
    Write-Host ''
    $choice = Read-Host 'Select an option'
    try {
        switch ($choice) {
            '1' { [void](Invoke-LocalProcesses) }
            '2' { $result = Invoke-PidInvestigation; Save-Report -Data $result -Name 'pid-investigation' }
            '3' { $result = Invoke-RemoteAudit; Save-Report -Data $result -Name 'remote-processes' }
            '4' { $result = Invoke-DirectoryInventory; Save-Report -Data $result -Name 'ad-inventory' }
            '5' { Save-Report -Data (Get-WAProcesses) -Name 'local-processes' }
            '0' { return }
            default { Write-Host 'Invalid option.' -ForegroundColor Yellow }
        }
    } catch {
        Write-Host ("Operation failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
    Pause-Menu
}
