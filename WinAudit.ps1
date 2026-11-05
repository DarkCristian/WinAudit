#requires -Version 5.1
<#
.SYNOPSIS
  WinAudit: inventario y consulta de eventos de Windows en modo de solo lectura.
.DESCRIPTION
  Consulta historica por PID o ejecutable y captura futura local en la sesion actual.
#>
[CmdletBinding()]
param(
    [Alias('PID')][ValidateRange(0,2147483647)][int]$PIDToAudit = 0,
    [Alias('ProcessName')][ValidatePattern('^[^\\/:*?"<>|]+\.exe$')][string]$FindProcess,
    [string]$FilePath,
    [ValidateSet('SHA256','MD5','Both')][string]$HashAlgorithm = 'SHA256',
    [switch]$Monitor,
    [switch]$FullScan,
    [string]$ComputerName,
    [Alias('Start')][object]$StartTime,
    [Alias('End')][object]$EndTime,
    [ValidateRange(1,300)][int]$PollSeconds = 5,
    [string]$ReportDirectory = (Join-Path $env:USERPROFILE 'WinAudit-Reports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot
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
function Pause-Menu { [void](Read-Host 'Presiona ENTER para continuar') }
function Read-Number([string]$Prompt) {
    $value = Read-Host $Prompt
    $number = 0
    if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1) { throw 'Ingresa un entero positivo.' }
    return $number
}
function Read-ExecutableName {
    $name = Read-Host 'Nombre exacto del ejecutable (ej.: example.exe)'
    if ($name -notmatch '^[^\\/:*?"<>|]+\.exe$') { throw 'Ingresa solo el nombre, por ejemplo example.exe, sin ruta ni comodines.' }
    return $name
}
function Read-EventWindow([switch]$Capture) {
    $start = Read-Host $(if ($Capture) {'Inicio (dd-MM-yyyy HH:mm:ss; vacio = ahora)'} else {'Inicio (dd-MM-yyyy HH:mm:ss; vacio = ultimas 24 h)'})
    $end = Read-Host 'Fin (dd-MM-yyyy HH:mm:ss; vacio = ahora)'
    $from = if ([string]::IsNullOrWhiteSpace($start)) { if ($Capture) {Get-Date} else {(Get-Date).AddHours(-24)} } else { ConvertTo-WADateTime $start }
    $until = if ([string]::IsNullOrWhiteSpace($end)) { Get-Date } else { ConvertTo-WADateTime $end }
    if ($until -le $from) { throw 'El fin debe ser posterior al inicio.' }
    return @{StartTime=$from; EndTime=$until}
}
function Show-Result($Data) {
    if ($null -eq $Data -or @($Data).Count -eq 0) { Write-Host 'Sin coincidencias. Revisa tambien la disponibilidad de los registros.' -ForegroundColor Yellow; return }
    $Data | Format-Table -AutoSize | Out-Host
}
function Save-Report($Data, [string]$Name) {
    if ($null -eq $Data) { return }
    $path = Export-WAReport -Data $Data -Directory $ReportDirectory -Prefix $Name
    Write-Host "Informe guardado: $path" -ForegroundColor Green
}
function Invoke-LocalProcesses([string]$Name) {
    $items = @(Get-WAProcesses -Name $Name)
    Show-Result ($items | Select-Object -First 40 Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath)
    Write-Host ("Procesos: {0}. Se muestran hasta 40." -f $items.Count)
    return $items
}
function Invoke-EventInvestigation {
    param([int]$TargetPid = 0,[string]$Name,[datetime]$From,[datetime]$Until,[switch]$Capture)
    if ($Capture) {
        [void](Start-WAEventCapture -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -Directory $ReportDirectory -PollSeconds $PollSeconds)
        return
    }
    if ($Until -gt (Get-Date)) { throw 'Para un fin futuro usa -Monitor o la opcion 7 del menu.' }
    $processes = @(Get-WAProcesses -Name $Name | Where-Object { $TargetPid -eq 0 -or $_.ProcessId -eq $TargetPid })
    Show-Result $processes
    $evidence = @($processes | ForEach-Object {
        if ($_.ExecutablePath) {
            try { Get-WAFileEvidence -Path $_.ExecutablePath -HashAlgorithm $HashAlgorithm } catch { Write-Warning $_.Exception.Message }
        }
    })
    $status = New-Object 'System.Collections.Generic.List[object]'
    $events = @(Get-WAEvents -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -QueryStatus $status)
    Show-Result ($events | Select-Object -First 35 TimeCreated,LogName,Id,MatchedField,Summary)
    Show-Result $status.ToArray()
    Save-Report ([pscustomobject]@{
        TargetPid=$TargetPid; ProcessName=$Name; StartTime=$From.ToString('o'); EndTime=$Until.ToString('o')
        TimeZone=[TimeZoneInfo]::Local.Id; CurrentProcesses=$processes; FileEvidence=$evidence
        Events=$events; Sources=@($status.ToArray())
    }) 'event-investigation'
}
function Invoke-InteractiveEvents([switch]$Capture) {
    $selector = Read-Host 'Buscar por [1] PID o [2] nombre de ejecutable'
    $query = @{}
    if ($selector -eq '1') { $query.TargetPid = Read-Number 'PID (ej.: 1234)' }
    elseif ($selector -eq '2') { $query.Name = Read-ExecutableName }
    else { throw 'Opcion invalida.' }
    $window = Read-EventWindow -Capture:$Capture
    Invoke-EventInvestigation @query -From $window.StartTime -Until $window.EndTime -Capture:$Capture
}
function Invoke-RemoteAudit {
    $hostName = Read-Host 'FQDN del equipo (ej.: pc001.ad.example.com)'
    if ([string]::IsNullOrWhiteSpace($hostName)) { throw 'El nombre del equipo es obligatorio.' }
    $credential = Get-Credential -Message 'Credenciales autorizadas para el equipo remoto'
    $result = Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    } -ErrorAction Stop
    Show-Result $result
    Save-Report $result 'remote-processes'
}
function Invoke-DirectoryInventory {
    $server = Read-Host 'Dominio o DC (ej.: dc01.ad.example.com)'
    $base = Read-Host 'DN de OU opcional (vacio = contexto predeterminado)'
    $credential = Get-Credential -Message 'Credenciales autorizadas de lectura del directorio'
    $query = @{Server=$server; Credential=$credential}
    if (-not [string]::IsNullOrWhiteSpace($base)) { $query.SearchBase=$base }
    $items = @(Get-WADirectoryComputers @query)
    Show-Result ($items | Select-Object -First 100 Name,DNSHostName,OperatingSystem,Enabled)
    Save-Report $items 'ad-inventory'
}
function Invoke-FileEvidenceMenu {
    $path = (Read-Host 'Ruta del archivo a verificar').Trim('"')
    $option = Read-Host 'Hash: [1] SHA-256 [2] MD5 [3] Ambos'
    $algorithm = switch ($option) { '1' {'SHA256'} '2' {'MD5'} '3' {'Both'} default {throw 'Opcion invalida.'} }
    $evidence = Get-WAFileEvidence -Path $path -HashAlgorithm $algorithm
    $evidence | Format-List | Out-Host
    Save-Report $evidence 'file-evidence'
}
$hasWindow = $PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime')
$from = if ($null -eq $StartTime) { if ($Monitor) {Get-Date} else {(Get-Date).AddHours(-24)} } else { ConvertTo-WADateTime $StartTime }
$until = if ($null -eq $EndTime) { Get-Date } else { ConvertTo-WADateTime $EndTime }
if ($until -le $from) { throw 'El fin debe ser posterior al inicio.' }
if ($FilePath) {
    if ($FindProcess -or $PIDToAudit -gt 0 -or $Monitor -or $ComputerName -or $FullScan -or $hasWindow) { throw '-FilePath solo admite -HashAlgorithm y -ReportDirectory.' }
    $evidence = Get-WAFileEvidence -Path $FilePath -HashAlgorithm $HashAlgorithm
    $evidence | Format-List | Out-Host
    Save-Report $evidence 'file-evidence'
    return
}
if ($PIDToAudit -gt 0 -and $FindProcess) { throw 'Usa -PIDToAudit o -FindProcess, no ambos.' }
if ($ComputerName -and ($Monitor -or $FindProcess -or $PIDToAudit -gt 0 -or $hasWindow -or $FullScan)) { throw '-ComputerName solo admite inventario remoto en esta version.' }
if ($FullScan -and ($Monitor -or $FindProcess -or $PIDToAudit -gt 0 -or $hasWindow)) { throw '-FullScan solo admite inventario local en esta version.' }
if (($Monitor -or $hasWindow) -and $PIDToAudit -eq 0 -and -not $FindProcess) { throw 'Para consultar o capturar eventos indica -PIDToAudit o -FindProcess.' }
if ($Monitor -and -not $PSBoundParameters.ContainsKey('EndTime')) { throw '-Monitor requiere -EndTime explicito.' }
if ($Monitor -or $PIDToAudit -gt 0 -or ($FindProcess -and $hasWindow)) {
    Invoke-EventInvestigation -TargetPid $PIDToAudit -Name $FindProcess -From $from -Until $until -Capture:$Monitor
    return
}
if ($FindProcess) { Save-Report ([pscustomobject]@{Query=$FindProcess; CurrentProcesses=@(Invoke-LocalProcesses -Name $FindProcess)}) 'process-search'; return }
if ($FullScan) { Save-Report ([pscustomobject]@{CurrentProcesses=@(Get-WAProcesses)}) 'local-processes'; return }
if ($ComputerName) {
    $credential = Get-Credential -Message 'Credenciales autorizadas para el equipo remoto'
    $data = Invoke-Command -ComputerName $ComputerName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    }
    Save-Report $data 'remote-processes'
    return
}
while ($true) {
    Show-Header
    Write-Host '  [1] Mostrar procesos locales'
    Write-Host '  [2] Consultar eventos historicos por PID o nombre'
    Write-Host '  [3] Inventario remoto de procesos (WinRM)'
    Write-Host '  [4] Inventario de equipos de Active Directory'
    Write-Host '  [5] Inventario local completo + informe JSON'
    Write-Host '  [6] Buscar proceso activo por nombre (example.exe)'
    Write-Host '  [7] Capturar eventos hasta un horario futuro'
    Write-Host '  [8] Verificar archivo: firma, SHA-256, MD5 o ambos'
    Write-Host '  [0] Salir'
    $choice = Read-Host 'Selecciona una opcion'
    try {
        switch ($choice) {
            '1' { [void](Invoke-LocalProcesses) }
            '2' { Invoke-InteractiveEvents }
            '3' { Invoke-RemoteAudit }
            '4' { Invoke-DirectoryInventory }
            '5' { Save-Report ([pscustomobject]@{CurrentProcesses=@(Get-WAProcesses)}) 'local-processes' }
            '6' { $name = Read-ExecutableName; Save-Report ([pscustomobject]@{Query=$name; CurrentProcesses=@(Invoke-LocalProcesses -Name $name)}) 'process-search' }
            '7' { Invoke-InteractiveEvents -Capture }
            '8' { Invoke-FileEvidenceMenu }
            '0' { return }
            default { Write-Host 'Opcion invalida.' -ForegroundColor Yellow }
        }
    } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    Pause-Menu
}
