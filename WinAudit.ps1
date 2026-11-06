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
    [switch]$VirusTotal,
    [switch]$NonInteractive,
    [switch]$Monitor,
    [switch]$FullScan,
    [string]$ComputerName,
    [string]$DirectoryServer,
    [ValidateSet('LDAPS','LDAP','RSAT')][string]$DirectoryProtocol='LDAPS',
    [string]$SearchBase,
    [ValidateNotNullOrEmpty()][string]$DirectoryNameFilter='*',
    [switch]$EnabledOnly,
    [pscredential]$DirectoryCredential,
    [ValidateRange(0,65535)][int]$DirectoryPort=0,
    [ValidateSet('Kerberos','Negotiate')][string]$DirectoryAuthentication='Kerberos',
    [ValidateRange(1,100000)][int]$MaxComputers=10000,
    [pscredential]$RemoteCredential,
    [switch]$WinRMUseSSL,
    [ValidateRange(0,65535)][int]$WinRMPort=0,
    [ValidateSet('Kerberos','Negotiate')][string]$WinRMAuthentication='Kerberos',
    [Alias('Start')][object]$StartTime,
    [Alias('End')][object]$EndTime,
    [ValidateRange(1,300)][int]$PollSeconds = 5,
    [ValidateRange(1,100000)][int]$MaxEventsPerLog=10000,
    [string]$ReportDirectory = (Join-Path $env:USERPROFILE 'WinAudit-Reports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot
Import-Module (Join-Path $script:Root 'Modules\Security.psm1') -Force
Import-Module (Join-Path $script:Root 'Modules\Runtime.psm1') -Force
Import-Module (Join-Path $script:Root 'Modules\Reputation.psm1') -Force
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
    $Data | ForEach-Object {
        $safe=[ordered]@{}
        foreach ($property in $_.PSObject.Properties) {
            $safe[$property.Name]=if ($property.Value -is [string]) {ConvertTo-WADisplayText $property.Value} else {$property.Value}
        }
        [pscustomobject]$safe
    } | Format-Table -AutoSize | Out-Host
}
function Save-Report($Data, [string]$Name) {
    if ($null -eq $Data) { return }
    $path = Export-WAReport -Data $Data -Directory $ReportDirectory -Prefix $Name
    Write-Host "Informe guardado: $path" -ForegroundColor Green
}
function Invoke-LocalProcesses([string]$Name) {
    $items = @(Get-WAProcesses -Name $Name)
    if ($script:vtAutomatic -and $script:vtContext) {
        foreach ($item in $items) {
            if ($item.ExecutablePath) {
                $fileEvidence=[pscustomobject]@{Path=$item.ExecutablePath}
                Add-OptionalReputation -Evidence $fileEvidence
                $item | Add-Member -NotePropertyName VirusTotal -NotePropertyValue $fileEvidence.VirusTotal -Force
            }
        }
    }
    Show-Result ($items | Select-Object -First 40 Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath)
    Write-Host ("Procesos: {0}. Se muestran hasta 40." -f $items.Count)
    return $items
}
function Invoke-EventInvestigation {
    param([int]$TargetPid = 0,[string]$Name,[datetime]$From,[datetime]$Until,[switch]$Capture)
    if ($Capture) {
        [void](Start-WAEventCapture -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -Directory $ReportDirectory -PollSeconds $PollSeconds -MaxEventsPerLog $MaxEventsPerLog -VirusTotalContext $(if ($script:vtAutomatic) {$script:vtContext} else {$null}))
        return
    }
    if ($Until -gt (Get-Date)) { throw 'Para un fin futuro usa -Monitor o la opcion 7 del menu.' }
    $processes = @(Get-WAProcesses -Name $Name | Where-Object { $TargetPid -eq 0 -or $_.ProcessId -eq $TargetPid })
    Show-Result $processes
    $evidence = @($processes | ForEach-Object {
        if ($_.ExecutablePath) {
            try { $fileEvidence=Get-WAFileEvidence -Path $_.ExecutablePath -HashAlgorithm $HashAlgorithm; Add-OptionalReputation -Evidence $fileEvidence; $fileEvidence } catch { Write-Warning $_.Exception.Message }
        }
    })
    $status = New-Object 'System.Collections.Generic.List[object]'
    $events = @(Get-WAEvents -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -QueryStatus $status -MaxEventsPerLog $MaxEventsPerLog)
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
    param([string]$HostName)
    if (-not $HostName) {$HostName=Read-Host 'FQDN del equipo (ej.: pc001.ad.example.com)'}
    $mode=Read-Host 'WinRM: [1] sesion actual [2] otras credenciales (lectura AD no garantiza acceso remoto)'
    $query=@{ComputerName=$HostName;UseSSL=$WinRMUseSSL;Port=$WinRMPort;Authentication=$WinRMAuthentication}
    if ($mode -eq '2') {$query.Credential=Get-Credential -Message 'Credenciales autorizadas de WinRM'}
    elseif ($mode -ne '1' -and $mode -ne '') {throw 'Opcion invalida.'}
    $result=@(Get-WARemoteProcesses @query)
    Show-Result $result
    Save-Report ([pscustomobject]@{ComputerName=$HostName;Transport='WinRM';UseSSL=[bool]$WinRMUseSSL;Processes=$result}) 'remote-processes'
}
function Invoke-DirectoryInventory {
    $server=Read-Host 'Dominio o DC DNS (ej.: dc01.ad.example.com)'
    $selection=Read-Host 'Descubrimiento: [1] LDAPS (predeterminado) [2] LDAP firmado/cifrado [3] RSAT'
    $protocol=switch ($selection) {'2' {'LDAP'} '3' {'RSAT'} '1' {'LDAPS'} '' {'LDAPS'} default {throw 'Opcion invalida.'}}
    $base=Read-Host 'DN de OU opcional (vacio = defaultNamingContext)'
    $nameFilter=Read-Host 'Nombre o patron (ej.: PC-*; vacio = todos)'
    if (-not $nameFilter) {$nameFilter='*'}
    $mode=Read-Host 'Autenticacion: [1] sesion actual [2] otras credenciales de dominio'
    $query=@{Server=$server;Protocol=$protocol;NameFilter=$nameFilter;MaxComputers=$MaxComputers;Authentication=$DirectoryAuthentication}
    if ($base) {$query.SearchBase=$base}
    if ($DirectoryPort -gt 0) {$query.Port=$DirectoryPort}
    if ($EnabledOnly) {$query.EnabledOnly=$true}
    if ($mode -eq '2') {$query.Credential=Get-Credential -Message 'Credenciales de lectura del directorio'}
    elseif ($mode -ne '1' -and $mode -ne '') {throw 'Opcion invalida.'}
    $items=@(Get-WADirectoryComputers @query)
    $rows=@(for ($index=0;$index -lt [Math]::Min(100,$items.Count);$index++) {
        [pscustomobject]@{Numero=($index+1);Name=$items[$index].Name;DNSHostName=$items[$index].DNSHostName;OperatingSystem=$items[$index].OperatingSystem;Enabled=$items[$index].Enabled}
    })
    Show-Result $rows
    Write-Host ('Equipos registrados: {0}. Se muestran hasta 100; WinRM todavia no fue comprobado.' -f $items.Count)
    Save-Report ([pscustomobject]@{Server=$server;Protocol=$protocol;SearchBase=$base;NameFilter=$nameFilter;Count=$items.Count;Computers=$items}) 'ad-inventory'
    if ($items.Count -eq 0) {return}
    $number=Read-Host 'Numero de equipo para consultar por WinRM (vacio = solo inventario)'
    if ([string]::IsNullOrWhiteSpace($number)) {return}
    $selected=0
    if (-not [int]::TryParse($number,[ref]$selected) -or $selected -lt 1 -or $selected -gt $rows.Count) {throw 'Selecciona un numero de la tabla mostrada.'}
    $target=$items[$selected-1].DNSHostName
    if ([string]::IsNullOrWhiteSpace($target)) {throw 'El objeto no tiene DNSHostName; no se adivina un destino remoto.'}
    Invoke-RemoteAudit -HostName $target
}
function Invoke-FileEvidenceMenu {
    $path = (Read-Host 'Ruta del archivo a verificar').Trim('"')
    $option = Read-Host 'Hash: [1] SHA-256 [2] MD5 [3] Ambos'
    $algorithm = switch ($option) { '1' {'SHA256'} '2' {'MD5'} '3' {'Both'} default {throw 'Opcion invalida.'} }
    $evidence = Get-WAFileEvidence -Path $path -HashAlgorithm $algorithm
    Add-OptionalReputation -Evidence $evidence
    Show-Result $evidence
    Save-Report $evidence 'file-evidence'
}
function Add-OptionalReputation {
    param([Parameter(Mandatory)]$Evidence)
    if (-not $script:vtAutomatic -or $null -eq $script:vtContext) { return }
    try {
        $localPath=Resolve-WALocalEvidencePath -Path $Evidence.Path
        $sha=(Get-FileHash -LiteralPath $localPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $report=Get-WAVirusTotalReport -SHA256 $sha -Context $script:vtContext
    } catch { $report=[pscustomobject]@{State='EvidenciaNoDisponible'; Detail='No se pudo leer el hash; no se envio la consulta.'} }
    $Evidence | Add-Member -NotePropertyName VirusTotal -NotePropertyValue $report -Force
}
function Invoke-VirusTotalMenu {
    while ($true) {
        Write-Host 'VirusTotal opcional: envia solo SHA-256 y clave al proveedor; no archivos, rutas ni logs.'
        Write-Host 'Usa una cuenta/licencia habilitada para tu uso. Restricciones: https://docs.virustotal.com/reference/public-vs-premium-api'
        Write-Host ('Configurado: {0} | Enriquecer auditorias al finalizar: {1}' -f ($null -ne $script:vtContext),$script:vtAutomatic)
        Write-Host '[1] Cargar clave para esta sesion (o VIRUSTOTAL_API_KEY)'
        Write-Host '[2] Consultar manualmente un hash SHA-256'
        Write-Host '[3] Activar/desactivar enriquecimiento de auditorias'
        Write-Host '[4] Desactivar y olvidar clave de esta sesion'
        Write-Host '[0] Volver'
        switch (Read-Host 'Opcion avanzada') {
            '1' {
                $key=if ($env:VIRUSTOTAL_API_KEY) {ConvertTo-SecureString $env:VIRUSTOTAL_API_KEY -AsPlainText -Force} else {Read-Host 'API key (oculta; solo memoria de esta sesion)' -AsSecureString}
                $script:vtContext=New-WAVirusTotalContext -ApiKey $key
                Write-Host 'Clave cargada. El enriquecimiento sigue desactivado hasta elegir opcion 3.'
                $script:vtAutomatic=$false
            }
            '2' {
                if ($null -eq $script:vtContext) {Write-Host 'Primero carga tu clave con opcion 1.'; continue}
                $hash=Read-Host 'SHA-256 a enviar a VirusTotal'
                $report=Get-WAVirusTotalReport -SHA256 $hash -Context $script:vtContext
                Show-Result $report
                Save-Report $report 'virustotal-reputation'
            }
            '3' {
                if ($null -eq $script:vtContext) {Write-Host 'Primero carga tu clave con opcion 1.'; continue}
                $script:vtAutomatic=-not $script:vtAutomatic
            }
            '4' { $script:vtAutomatic=$false; $script:vtContext=$null; Write-Host 'Integracion desactivada. La variable de entorno, si existe, no se modifica.' }
            '0' { return }
            default { Write-Host 'Opcion invalida.' }
        }
    }
}
if (-not (Initialize-WARuntimeSecurity -NonInteractive:$NonInteractive)) {return}
$script:vtContext=$null
$script:vtAutomatic=$false
if ($VirusTotal) {
    if ($env:VIRUSTOTAL_API_KEY) {
        $script:vtContext=New-WAVirusTotalContext -ApiKey (ConvertTo-SecureString $env:VIRUSTOTAL_API_KEY -AsPlainText -Force)
        $script:vtAutomatic=$true
    } else { Write-Warning 'VirusTotal desactivado: no se configuro VIRUSTOTAL_API_KEY. La auditoria local continua.' }
}
if ($VirusTotal -and ($FullScan -or $ComputerName)) { throw '-VirusTotal solo admite busqueda, investigacion, archivo o captura local en esta version.' }
$hasWindow = $PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime')
if ($DirectoryServer) {
    if ($FindProcess -or $PIDToAudit -gt 0 -or $Monitor -or $ComputerName -or $FullScan -or $FilePath -or $hasWindow -or $VirusTotal) {throw '-DirectoryServer consulta solo inventario. Selecciona despues un host con -ComputerName o el menu.'}
    $query=@{Server=$DirectoryServer;Protocol=$DirectoryProtocol;NameFilter=$DirectoryNameFilter;SearchBase=$SearchBase;EnabledOnly=$EnabledOnly;Port=$DirectoryPort;Authentication=$DirectoryAuthentication;MaxComputers=$MaxComputers}
    if ($null -ne $DirectoryCredential) {$query.Credential=$DirectoryCredential}
    $items=@(Get-WADirectoryComputers @query)
    Show-Result ($items | Select-Object -First 100 Name,DNSHostName,OperatingSystem,Enabled)
    Save-Report ([pscustomobject]@{Server=$DirectoryServer;Protocol=$DirectoryProtocol;Count=$items.Count;Computers=$items}) 'ad-inventory'
    return
}
$from = if ($null -eq $StartTime) { if ($Monitor) {Get-Date} else {(Get-Date).AddHours(-24)} } else { ConvertTo-WADateTime $StartTime }
$until = if ($null -eq $EndTime) { Get-Date } else { ConvertTo-WADateTime $EndTime }
if ($until -le $from) { throw 'El fin debe ser posterior al inicio.' }
if ($FilePath) {
    if ($FindProcess -or $PIDToAudit -gt 0 -or $Monitor -or $ComputerName -or $FullScan -or $hasWindow) { throw '-FilePath solo admite -HashAlgorithm y -ReportDirectory.' }
    $evidence = Get-WAFileEvidence -Path $FilePath -HashAlgorithm $HashAlgorithm
    Add-OptionalReputation -Evidence $evidence
    Show-Result $evidence
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
    $query=@{ComputerName=$ComputerName;UseSSL=$WinRMUseSSL;Port=$WinRMPort;Authentication=$WinRMAuthentication}
    $query.Credential=if ($null -ne $RemoteCredential) {$RemoteCredential} else {Get-Credential -Message 'Credenciales autorizadas para WinRM'}
    $data=@(Get-WARemoteProcesses @query)
    Save-Report ([pscustomobject]@{ComputerName=$ComputerName;Transport='WinRM';UseSSL=[bool]$WinRMUseSSL;Processes=$data}) 'remote-processes'
    return
}

while ($true) {
    Show-Header
    Write-Host '  [1] Mostrar procesos locales'
    Write-Host '  [2] Consultar eventos historicos por PID o nombre'
    Write-Host '  [3] Inventario remoto de procesos (WinRM)'
    Write-Host '  [4] Descubrir equipos por LDAP/LDAPS o RSAT y seleccionar WinRM'
    Write-Host '  [5] Inventario local completo + informe JSON'
    Write-Host '  [6] Buscar proceso activo por nombre (example.exe)'
    Write-Host '  [7] Capturar eventos hasta un horario futuro'
    Write-Host '  [8] Verificar archivo: firma, SHA-256, MD5 o ambos'
    Write-Host '  [9] Avanzado: VirusTotal opcional (API key propia)'
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
            '9' { Invoke-VirusTotalMenu }
            '0' { return }
            default { Write-Host 'Opcion invalida.' -ForegroundColor Yellow }
        }
    } catch { Write-Host (ConvertTo-WADisplayText ("Error: {0}" -f $_.Exception.Message)) -ForegroundColor Red }
    Pause-Menu
}
