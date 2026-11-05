#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules/Security.psm1') -Force
Import-Module (Join-Path $root 'Modules/Core.psm1') -Force
Import-Module (Join-Path $root 'Modules/Events.psm1') -Force
function Assert-Security($Condition,$Message) {if (-not $Condition) {throw $Message}}
function Assert-Rejected([scriptblock]$Action,$Message) {$failed=$false;try {& $Action | Out-Null} catch {$failed=$true};Assert-Security $failed $Message}
foreach ($version in @('7.4.20','7.5.11','7.6.6','7.3.12','6.2.7')) {Assert-Rejected {Assert-WASupportedRuntime -Version ([version]$version) -Platform Windows_NT} ('Debe rechazar runtime '+$version)}
foreach ($version in @('5.1.0','7.4.21','7.5.12','7.6.7')) {Assert-WASupportedRuntime -Version ([version]$version) -Platform Windows_NT}
Assert-Rejected {Assert-WASupportedRuntime -Version ([version]'7.6.7') -Platform Linux} 'Windows es requisito.'
$escape=[string][char]27
$untrusted='example.exe'+$escape+']52;c;clipboard'+[char]7+[char]0x9b+'31m'+[char]0x202e+'hidden'
$display=ConvertTo-WADisplayText $untrusted
Assert-Security ($display -notmatch '[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]') 'No debe dejar controles de terminal ni bidi.'
$xml=ConvertFrom-WAEventXml '<Event><System><Execution ProcessID="1000"/></System></Event>'
Assert-Security ($xml.DocumentElement.Name -eq 'Event') 'Debe aceptar XML normal.'
Assert-Rejected {ConvertFrom-WAEventXml '<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///C:/Example/private.txt">]><Event>&xxe;</Event>'} 'Debe rechazar DTD y entidades externas.'
Assert-Rejected {ConvertFrom-WAEventXml ('<Event>'+('x'*4194304)+'</Event>')} 'Debe limitar tamano de XML.'
foreach ($path in @('\\files.example.com\share\example.exe','//files.example.com/share/example.exe','\\?\UNC\files.example.com\share\example.exe','C:\Example\example.exe:stream',('C:\Example\x'+$escape+'.exe'))) {
    Assert-Rejected {Resolve-WALocalEvidencePath -Path $path -AllowMissing} 'Debe rechazar rutas de red, dispositivo, ADS o controles antes de leer evidencia.'
}
$securityModule=Get-Module Security
& $securityModule {function script:Get-WALocalDriveType {param($Root) [IO.DriveType]::Network}}
Assert-Rejected {Resolve-WALocalEvidencePath -Path 'C:\Example\example.exe' -AllowMissing} 'Debe rechazar unidad mapeada de red.'
Import-Module (Join-Path $root 'Modules/Security.psm1') -Force
$temp=Join-Path ([IO.Path]::GetTempPath()) ('WA-security-'+[guid]::NewGuid().ToString('N'))
$junction=$null
try {
    $directory=Initialize-WAReportDirectory $temp
    $file=Join-Path $directory 'exclusive.txt'
    [void](New-WAEvidenceFile -Path $file -Content 'original')
    Assert-Rejected {New-WAEvidenceFile -Path $file -Content 'changed'} 'No debe sobrescribir un archivo existente.'
    Assert-Security (([IO.File]::ReadAllText($file)) -eq 'original') 'Debe preservar el archivo existente.'
    $target=Join-Path $directory 'target';[void][IO.Directory]::CreateDirectory($target)
    $junction=Join-Path $directory 'redirect'
    [void](New-Item -ItemType Junction -Path $junction -Target $target)
    Assert-Rejected {Resolve-WALocalEvidencePath -Path (Join-Path $junction 'evidence.txt') -AllowMissing} 'No debe seguir junctions al leer o escribir.'
    $eventsModule=Get-Module Events
    & $eventsModule {
        function script:Get-WinEvent {
            [CmdletBinding()] param($FilterHashtable,$MaxEvents)
            for ($i=0;$i -lt $MaxEvents;$i++) {
                $evt=[pscustomobject]@{TimeCreated=(Get-Date);LogName='TestLog';Id=1;RecordId=$i;Message=('message'+[char]27+'[31m')}
                $evt | Add-Member -MemberType ScriptMethod -Name ToXml -Value {'<Event><System><Execution ProcessID="1000"/></System></Event>'}
                $evt
            }
        }
    }
    $status=New-Object 'System.Collections.Generic.List[object]'
    $rows=@(Get-WAEvents -TargetPid 1000 -StartTime (Get-Date).AddMinutes(-1) -EndTime (Get-Date).AddMinutes(1) -Logs TestLog -MaxEventsPerLog 2 -QueryStatus $status -WarningAction SilentlyContinue)
    Assert-Security ($rows.Count -eq 2 -and $status[0].State -eq 'Limitado') 'Debe limitar resultados y marcar consulta parcial.'
    Assert-Security ($rows[0].Summary -notmatch '[\x00-\x1f\x7f-\x9f]' -and $rows[0].Message.Contains([string][char]27)) 'Debe sanear resumen conservando evidencia cruda.'
} finally {
    if ($junction -and [IO.Directory]::Exists($junction)) {[IO.Directory]::Delete($junction)}
    if (Test-Path -LiteralPath $temp) {Remove-Item -LiteralPath $temp -Recurse -Force}
}
Write-Host 'PASS Security: runtime, rutas locales, reparse points, escritura exclusiva, XML, terminal y limites de eventos.'
