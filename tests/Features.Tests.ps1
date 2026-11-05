#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
function Assert-True($Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $threw=$false
    try { & $Action } catch { $threw=$true }
    Assert-True $threw $Message
}
Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1') } | ForEach-Object {
    $tokens=$null; $errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) { $errors | Format-List | Out-Host; throw "Error de sintaxis: $($_.FullName)" }
}
& (Join-Path $root 'tools/Build-Standalone.ps1') -Check
Import-Module (Join-Path $root 'Modules/Events.psm1') -Force
Import-Module (Join-Path $root 'Modules/Core.psm1') -Force
$eventsModule = Get-Module Events
$coreModule = Get-Module Core
foreach ($culture in @('en-US','es-AR')) {
    $previous = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]$culture
        Assert-True ((ConvertTo-WADateTime '02-01-2026 10:00:00').Month -eq 1) 'Fecha interpretada con cultura incorrecta.'
        Assert-True ((ConvertTo-WADateTime '2026-01-02 10:00:00').Day -eq 2) 'Formato ISO incorrecto.'
        Assert-Throws { ConvertTo-WADateTime '31-02-2026 10:00:00' } 'Acepto una fecha imposible.'
        Assert-Throws { ConvertTo-WADateTime '01/02/2026' } 'Acepto un formato ambiguo.'
    } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $previous }
}
& $coreModule {
    function script:Get-CimInstance {
        param($ClassName)
        foreach ($item in @(@('example.exe',1234),@('EXAMPLE.EXE',1235),@('other.exe',1236))) {
            [pscustomobject]@{Name=$item[0]; ProcessId=$item[1]; ParentProcessId=1; CreationDate=(Get-Date); ExecutablePath='C:\Example\example.exe'; CommandLine='example.exe'}
        }
    }
}
Assert-True (@(Get-WAProcesses -Name 'example.exe').Count -eq 2) 'La busqueda debe incluir todos los PID y no distinguir mayusculas.'
Assert-True (@(Get-WAProcesses -Name 'missing.exe').Count -eq 0) 'Debe devolver cero coincidencias.'
Assert-True (@(Get-WAProcesses -Name '*.exe').Count -eq 0) 'La busqueda no debe interpretar comodines.'
& $eventsModule {
    $script:EventTime = Get-Date
    function script:Get-WinEvent {
        [CmdletBinding()]
        param($FilterHashtable)
        if ($FilterHashtable.LogName -eq 'MissingLog') { throw 'Log no disponible (prueba sintetica).' }
        $records = @(
            @('42','<Execution ProcessID="9999"/>','<Data Name="NewProcessId">0x4d2</Data><Data Name="NewProcessName">C:\Example\example.exe</Data>'),
            @('43','<Execution ProcessID="1234"/>',''),
            @('44','','<Data Name="Image">C:\Example\EXAMPLE.EXE</Data>'),
            @('45','','<Data Name="Image">C:\Example\notexample.exe</Data>')
        )
        foreach ($record in $records) {
            if ($script:EventTime -lt $FilterHashtable.StartTime -or $script:EventTime -gt $FilterHashtable.EndTime) { continue }
            $evt=[pscustomobject]@{TimeCreated=$script:EventTime; LogName=$FilterHashtable.LogName; Id=4688; RecordId=[int]$record[0]; Message='Evento sintetico'; Xml="<Event><System>$($record[1])</System><EventData>$($record[2])</EventData></Event>"}
            $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
            $evt
        }
    }
}
$now=Get-Date
$byPid=@(Get-WAEvents -TargetPid 1234 -StartTime $now.AddMinutes(-1) -EndTime $now.AddMinutes(1) -Logs @('TestLog'))
Assert-True ($byPid.Count -eq 2) 'Debe correlacionar PID hexadecimal y emisor sin corromper la lista de coincidencias.'
$byName=@(Get-WAEvents -ProcessName 'example.exe' -StartTime $now.AddMinutes(-1) -EndTime $now.AddMinutes(1) -Logs @('TestLog'))
Assert-True ($byName.Count -eq 2) 'Debe buscar campos de ejecutable aunque no exista Execution.'
Assert-True ($byName[0].EventXml -like '<Event>*') 'Debe preservar el XML del evento.'
Assert-Throws { Get-WAEvents -TargetPid 1234 -StartTime $now -EndTime $now } 'Acepto un intervalo vacio.'
Assert-Throws { Get-WAEvents -TargetPid 1234 -ProcessName 'example.exe' } 'Acepto dos selectores simultaneos.'
$state = New-Object 'System.Collections.Generic.List[object]'
[void]@(Get-WAEvents -TargetPid 1234 -StartTime $now.AddMinutes(-1) -EndTime $now.AddMinutes(1) -Logs @('MissingLog') -QueryStatus $state -WarningAction SilentlyContinue)
Assert-True ($state.Count -eq 1 -and $state[0].State -eq 'NoDisponible') 'Debe informar logs inaccesibles.'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('WA-test-' + [guid]::NewGuid().ToString('N'))
try {
    $start = (Get-Date).AddSeconds(1)
    $end = $start.AddSeconds(1)
    & $eventsModule { param($Time) $script:EventTime=$Time } $start
    $capture = Start-WAEventCapture -ProcessName 'example.exe' -StartTime $start -EndTime $end -Directory $temp -PollSeconds 1 -Logs @('TestLog','MissingLog') -WarningAction SilentlyContinue
    Assert-True ($capture.State -eq 'FinalizadaConLimitaciones') 'La captura debe informar fuentes incompletas.'
    $rows=@(Get-Content -LiteralPath $capture.EventFile | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json})
    Assert-True ($rows.Count -eq 2) 'La captura debe esperar, leer y evitar duplicados entre consultas.'
    Assert-True ($capture.MatchedCount -eq 2) 'Conteo incorrecto de captura.'
    Assert-Throws { Start-WAEventCapture -ProcessName 'example.exe' -StartTime $now.AddMinutes(-2) -EndTime $now.AddMinutes(-1) -Directory $temp } 'Acepto una captura ya vencida.'
    function global:Clear-Host { }
    function global:Read-Host { param($Prompt) '0' }
    & (Join-Path $root 'WinAudit.ps1')
    & (Join-Path $root 'dist/WinAudit-Standalone.ps1')
    Assert-Throws { & (Join-Path $root 'dist/WinAudit-Standalone.ps1') -FindProcess '../example.exe' } 'Acepto una ruta en la busqueda por nombre.'
    Assert-Throws { & (Join-Path $root 'dist/WinAudit-Standalone.ps1') -FindProcess 'example.exe' -Monitor } 'Acepto captura sin fin explicito.'
} finally {
    Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue
    Remove-Item Function:\Clear-Host -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS: sintaxis, ensamblado, fechas, busqueda, correlacion y captura sintetica.'
