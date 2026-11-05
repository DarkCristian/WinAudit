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

function Get-WAProcesses {
    [CmdletBinding()]
    param([string]$Name)
    Get-CimInstance -ClassName Win32_Process | Where-Object { -not $Name -or $_.Name -ieq $Name } | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            ProcessId = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            CreationDate = $_.CreationDate
            ExecutablePath = $_.ExecutablePath
            CommandLine = $_.CommandLine
        }
    }
}
function Get-WAFileEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not accessible: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    [pscustomobject]@{
        Path = $Path
        SHA256 = $hash.Hash
        SignatureStatus = [string]$signature.Status
        Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        SignerThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
        VerifiedAt = (Get-Date).ToString('o')
    }
}
function Export-WAReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data,[Parameter(Mandatory)][string]$Directory,[string]$Prefix='audit')
    if (-not (Test-Path -LiteralPath $Directory)) { [void](New-Item -ItemType Directory -Path $Directory -Force) }
    $safe = $Prefix -replace '[^a-zA-Z0-9_-]','-'
    $file = Join-Path $Directory ('{0}-{1}-{2}.json' -f $safe,(Get-Date -Format 'yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    $payload = [pscustomobject]@{
        Tool = 'WinAudit'
        CreatedAt = (Get-Date).ToString('o')
        Host = $env:COMPUTERNAME
        Data = @($Data)
    }
    $payload | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $file -Encoding UTF8
    return $file
}


function ConvertTo-WADateTime {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [datetime]) { return $Value }
    $parsed = [datetime]::MinValue
    $formats = [string[]]@('dd-MM-yyyy HH:mm:ss','yyyy-MM-dd HH:mm:ss','dd-MM-yyyy HH:mm','yyyy-MM-dd HH:mm')
    if (-not [datetime]::TryParseExact([string]$Value, $formats, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw 'Fecha invalida. Usa dd-MM-yyyy HH:mm:ss o yyyy-MM-dd HH:mm:ss (hora local del equipo).'
    }
    return $parsed
}

function Get-WAEvents {
    <#
    .SYNOPSIS
      Consulta eventos disponibles por PID o nombre exacto de ejecutable.
    .NOTES
      Se etiqueta el campo coincidente: emisor, sujeto o proceso relacionado.
      Un PID puede reutilizarse; un nombre no identifica una instancia unica.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(0,2147483647)][int]$TargetPid = 0,
        [string]$ProcessName,
        [datetime]$StartTime = (Get-Date).AddHours(-24),
        [datetime]$EndTime = (Get-Date),
        [string[]]$Logs = @('Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational'),
        [System.Collections.Generic.List[object]]$QueryStatus
    )
    if ($TargetPid -eq 0 -and [string]::IsNullOrWhiteSpace($ProcessName)) { throw 'Indica un PID o nombre de ejecutable.' }
    if ($TargetPid -gt 0 -and $ProcessName) { throw 'Usa un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime) { throw 'El fin debe ser posterior al inicio.' }
    foreach ($log in $Logs) {
        $count = 0
        $state = 'Consultado'
        $detail = $null
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$StartTime; EndTime=$EndTime} -ErrorAction Stop)
            foreach ($evt in $events) {
                try {
                    [xml]$xml = $evt.ToXml()
                    $evidenceMatches = New-Object System.Collections.Generic.List[string]
                    $execution = $xml.SelectSingleNode('/Event/System/Execution')
                    if ($TargetPid -gt 0 -and $null -ne $execution -and $execution.GetAttribute('ProcessID') -eq [string]$TargetPid) {
                        [void]$evidenceMatches.Add('System.Execution.ProcessID (emisor)')
                    }
                    foreach ($node in $xml.SelectNodes('/Event/EventData/Data')) {
                        $field = $node.GetAttribute('Name')
                        $raw = $node.InnerText
                        if ($TargetPid -gt 0 -and $field -match '^(ProcessId|NewProcessId|ParentProcessId|CreatorProcessId|ClientProcessId|SourceProcessId|TargetProcessId)$') {
                            $parsed = -1L
                            if ($raw -match '^0x[0-9a-fA-F]+$') { $parsed = [Convert]::ToInt64($raw.Substring(2),16) }
                            elseif ($raw -match '^\d+$') { $parsed = [long]$raw }
                            if ($parsed -eq $TargetPid) { [void]$evidenceMatches.Add("EventData.$field") }
                        }
                        if ($ProcessName -and $field -match '^(Image|NewProcessName|ProcessName|ApplicationName|SourceImage|TargetImage|ParentImage)$') {
                            $leaf = ($raw.Trim('"') -split '[\\/]')[-1]
                            if ($leaf -ieq $ProcessName) { [void]$evidenceMatches.Add("EventData.$field (nombre)") }
                        }
                    }
                    if ($evidenceMatches.Count -gt 0) {
                        $count++
                        $message = [string]$evt.Message
                        $summary = $message -replace '\s+',' '
                        [pscustomobject]@{
                            TimeCreated=$evt.TimeCreated; LogName=$evt.LogName; Id=$evt.Id; RecordId=$evt.RecordId
                            MatchedField=($evidenceMatches -join ', ')
                            Summary=$summary.Substring(0,[Math]::Min(160,$summary.Length))
                            Message=$message; EventXml=$evt.ToXml()
                        }
                    }
                } catch {
                    $state = 'Parcial'
                    $detail = 'No se pudo interpretar uno o mas eventos: ' + $_.Exception.Message
                }
            }
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $state = 'SinEventosEnIntervalo' }
            else { $state = 'NoDisponible'; $detail = $_.Exception.Message }
        }
        if ($null -ne $QueryStatus) {
            $QueryStatus.Add([pscustomobject]@{LogName=$log; State=$state; MatchedCount=$count; Detail=$detail; CheckedAt=(Get-Date).ToString('o')})
        }
        if ($state -eq 'NoDisponible' -or $state -eq 'Parcial') { Write-Warning ("{0}: {1}. {2}" -f $log,$state,$detail) }
    }
}

function Start-WAEventCapture {
    <# Mantener esta sesion abierta. No crea tareas programadas ni cambia auditorias. #>
    [CmdletBinding()]
    param(
        [ValidateRange(0,2147483647)][int]$TargetPid = 0,
        [string]$ProcessName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime,
        [Parameter(Mandatory)][string]$Directory,
        [ValidateRange(1,300)][int]$PollSeconds = 5,
        [string[]]$Logs = @('Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational')
    )
    if (($TargetPid -eq 0 -and -not $ProcessName) -or ($TargetPid -gt 0 -and $ProcessName)) { throw 'Indica un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime -or $EndTime -le (Get-Date)) { throw 'La captura necesita un fin futuro posterior al inicio.' }
    [void](New-Item -ItemType Directory -Path $Directory -Force)
    $runId = 'capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $journal = Join-Path $Directory ($runId + '.jsonl')
    $manifest = Join-Path $Directory ($runId + '.json')
    [IO.File]::WriteAllText($journal, '', (New-Object Text.UTF8Encoding($false)))
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $statuses = New-Object 'System.Collections.Generic.List[object]'
    $metadata = [pscustomobject]@{
        Tool='WinAudit'; Mode='EventCapture'; Host=$env:COMPUTERNAME
        TimeZone=[TimeZoneInfo]::Local.Id; RequestedStart=$StartTime.ToString('o'); RequestedEnd=$EndTime.ToString('o')
        TargetPid=$TargetPid; ProcessName=$ProcessName; State='Esperando'; MatchedCount=0
        StartedAt=(Get-Date).ToString('o'); UpdatedAt=$null; LastQueryEnd=$null; FinishedAt=$null
        EventFile=$journal; Sources=@(); SourceIssues=@(); Limitations='Depende de logs habilitados y retencion. PID reutilizable; nombre no identifica instancia. Eventos tardios pueden faltar.'
    }
    $cursor = $StartTime
    try {
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
        Write-Host ("Captura local de {0} a {1}. Zona: {2}. Mantene esta terminal abierta; Ctrl+C cancela." -f $StartTime,$EndTime,$metadata.TimeZone)
        while ((Get-Date) -lt $StartTime) { Start-Sleep -Seconds 1 }
        $metadata.State = 'Capturando'
        while ($true) {
            $now = Get-Date
            $upper = if ($now -lt $EndTime) { $now } else { $EndTime }
            $lower = $cursor.AddSeconds(-2)
            if ($lower -lt $StartTime) { $lower = $StartTime }
            if ($upper -gt $lower) {
                $statuses.Clear()
                $query = @{TargetPid=$TargetPid; ProcessName=$ProcessName; StartTime=$lower; EndTime=$upper; Logs=$Logs; QueryStatus=$statuses}
                Get-WAEvents @query | ForEach-Object {
                    $key = '{0}|{1}|{2}' -f $_.LogName,$_.RecordId,$_.TimeCreated.ToString('o')
                    if ($seen.Add($key)) {
                        $_ | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8
                        $metadata.MatchedCount++
                    }
                }
                $cursor = $upper
                $metadata.LastQueryEnd = $upper.ToString('o')
                $metadata.Sources = @($statuses.ToArray())
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
                $metadata.UpdatedAt = (Get-Date).ToString('o')
                $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
            }
            if ($now -ge $EndTime) { break }
            $remaining = ($EndTime - (Get-Date)).TotalSeconds
            if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Max(1,[Math]::Min($PollSeconds * 1000,$remaining * 1000))) }
        }
        # Ultima lectura con margen para escrituras de eventos ligeramente demoradas.
        Start-Sleep -Seconds 2
        $statuses.Clear()
        Get-WAEvents -TargetPid $TargetPid -ProcessName $ProcessName -StartTime $StartTime -EndTime $EndTime -Logs $Logs -QueryStatus $statuses | ForEach-Object {
            $key = '{0}|{1}|{2}' -f $_.LogName,$_.RecordId,$_.TimeCreated.ToString('o')
            if ($seen.Add($key)) {
                $_ | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8
                $metadata.MatchedCount++
            }
        }
        $metadata.Sources = @($statuses.ToArray())
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
        $metadata.State = if ($metadata.SourceIssues.Count -gt 0) { 'FinalizadaConLimitaciones' } else { 'Finalizada' }
    } finally {
        if ($metadata.State -in @('Esperando','Capturando')) { $metadata.State = 'Interrumpida' }
        $metadata.FinishedAt = (Get-Date).ToString('o')
        $metadata.UpdatedAt = $metadata.FinishedAt
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
        Write-Host "Estado: $($metadata.State). Eventos: $journal. Resumen: $manifest"
    }
    return $metadata
}

function Get-WADirectoryComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Server,
        [Parameter(Mandatory)][pscredential]$Credential,
        [string]$SearchBase
    )
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory RSAT module not found. Install RSAT AD PowerShell tools.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $args = @{ Filter='*'; Server=$Server; Credential=$Credential; Properties=@('OperatingSystem','LastLogonDate','DNSHostName','Enabled') }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $args.SearchBase=$SearchBase }
    Get-ADComputer @args | Select-Object Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,DistinguishedName
}

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
            try { Get-WAFileEvidence -Path $_.ExecutablePath } catch { Write-Warning $_.Exception.Message }
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
$hasWindow = $PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime')
$from = if ($null -eq $StartTime) { if ($Monitor) {Get-Date} else {(Get-Date).AddHours(-24)} } else { ConvertTo-WADateTime $StartTime }
$until = if ($null -eq $EndTime) { Get-Date } else { ConvertTo-WADateTime $EndTime }
if ($until -le $from) { throw 'El fin debe ser posterior al inicio.' }
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
            '0' { return }
            default { Write-Host 'Opcion invalida.' -ForegroundColor Yellow }
        }
    } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    Pause-Menu
}
