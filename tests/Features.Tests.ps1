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
Import-Module (Join-Path $root 'Modules/Security.psm1') -Force
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
        param($FilterHashtable,$MaxEvents)
        if ($FilterHashtable.LogName -eq 'MissingLog') { throw 'Log no disponible (prueba sintetica).' }
        $records = @(
            @('42','<Execution ProcessID="9999"/>','<Data Name="NewProcessId">0x4d2</Data><Data Name="NewProcessName">C:\Example\example.exe</Data>'),
            @('43','<Execution ProcessID="1234"/>',''),
            @('44','','<Data Name="Image">C:\Example\EXAMPLE.EXE</Data>'),
            @('45','','<Data Name="Image">C:\Example\notexample.exe</Data>')
        )
        foreach ($record in $records) {
            if ($script:EventTime -lt $FilterHashtable.StartTime -or $script:EventTime -gt $FilterHashtable.EndTime) { continue }
            $evt=[pscustomobject]@{TimeCreated=$script:EventTime; LogName=$FilterHashtable.LogName; Id=4688; RecordId=[int]$record[0]; Message='Evento sintetico'; Xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>$($record[1])</System><EventData>$($record[2])</EventData></Event>"}
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
Assert-True ($byName[0].EventXml -like '<Event*') 'Debe preservar el XML del evento.'
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
    Assert-True (Test-Path -LiteralPath $capture.TreeReportFile) 'Debe generar el informe TXT al terminar.'
    Assert-True (Test-Path -LiteralPath $capture.ProcessEvidenceFile) 'Debe preservar la evidencia de procesos.'
    $hashFile=Join-Path $temp 'hash-example.bin'
    [IO.File]::WriteAllText($hashFile,'abc',(New-Object Text.UTF8Encoding($false)))
    $hashes=Get-WAFileEvidence -Path $hashFile -HashAlgorithm Both
    Assert-True ($hashes.MD5 -eq '900150983CD24FB0D6963F7D28E17F72') 'MD5 incorrecto.'
    Assert-True ($hashes.SHA256 -eq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD') 'SHA-256 incorrecto.'
    $md5Only=Get-WAFileEvidence -Path $hashFile -HashAlgorithm MD5
    Assert-True ($md5Only.MD5 -eq $hashes.MD5 -and $null -eq $md5Only.SHA256) 'MD5 independiente incorrecto.'

    $treeFileCache=@{}
    & $coreModule {
        $script:SignatureCalls=0
        function script:Get-AuthenticodeSignature {
            [CmdletBinding()] param($LiteralPath)
            $script:SignatureCalls++
            [pscustomobject]@{Status='Valid'; SignerCertificate=[pscustomobject]@{Subject='CN=Example Publisher'}}
        }
    }
    $treeFileEvidence = & $coreModule { param($Path,$Cache) Get-WATreeFileEvidence -Path $Path -Cache $Cache } $hashFile $treeFileCache
    Assert-True ($treeFileEvidence.MD5 -eq $hashes.MD5 -and $treeFileEvidence.SignatureStatus -eq 'Valid' -and $treeFileEvidence.Signer -eq 'CN=Example Publisher') 'El arbol debe recopilar MD5 y firma por separado.'
    [void](& $coreModule { param($Path,$Cache) Get-WATreeFileEvidence -Path $Path -Cache $Cache } $hashFile $treeFileCache)
    Assert-True ((& $coreModule {$script:SignatureCalls}) -eq 1) 'No debe releer la firma del mismo archivo sin cambios.'
    [IO.File]::WriteAllText($hashFile,'abcd',(New-Object Text.UTF8Encoding($false)))
    $changedEvidence = & $coreModule { param($Path,$Cache) Get-WATreeFileEvidence -Path $Path -Cache $Cache } $hashFile $treeFileCache
    Assert-True ($changedEvidence.MD5 -eq 'E2FC714C4727EE9395F324CD2E7F331F' -and (& $coreModule {$script:SignatureCalls}) -eq 2) 'Debe invalidar cache si cambia el archivo.'
    $noPath = & $coreModule { Get-WATreeFileEvidence -Path '' }
    Assert-True ($null -eq $noPath.MD5 -and $noPath.SignatureStatus -eq 'NoDisponible' -and $noPath.MD5Error) 'Una ruta ausente no debe aparecer como archivo sin firma.'
    & $coreModule {
        function script:Get-AuthenticodeSignature { [CmdletBinding()] param($LiteralPath) throw 'Firma inaccesible (prueba)' }
    }
    $signatureFailed = & $coreModule { param($Path) Get-WATreeFileEvidence -Path $Path } $hashFile
    Assert-True ($signatureFailed.MD5 -eq $changedEvidence.MD5 -and $signatureFailed.SignatureStatus -eq 'NoDisponible' -and $signatureFailed.SignatureError) 'Un error de firma no debe ocultar un MD5 disponible.'
    & $coreModule {
        function script:Get-AuthenticodeSignature { [CmdletBinding()] param($LiteralPath) [pscustomobject]@{Status='NotSigned'; SignerCertificate=$null} }
    }
    $unsigned = & $coreModule { param($Path) Get-WATreeFileEvidence -Path $Path } $hashFile
    Assert-True ($unsigned.SignatureStatus -eq 'NotSigned' -and $null -eq $unsigned.SignatureError) 'Debe distinguir ausencia de firma de error de lectura.'
    & $coreModule {
        function script:Get-FileHash { [CmdletBinding()] param($LiteralPath,$Algorithm) throw 'Hash inaccesible (prueba)' }
    }
    $hashFailed = & $coreModule { param($Path) Get-WATreeFileEvidence -Path $Path } $hashFile
    Assert-True ($null -eq $hashFailed.MD5 -and $hashFailed.MD5Error -and $hashFailed.SignatureStatus -eq 'NotSigned') 'Un error de hash no debe ocultar el estado de firma.'
    & $coreModule {
        Remove-Item Function:\Get-FileHash
        function script:Get-AuthenticodeSignature {
            [CmdletBinding()] param($LiteralPath)
            [pscustomobject]@{Status='Valid'; SignerCertificate=[pscustomobject]@{Subject='CN=Example Publisher'}}
        }
    }
    & $coreModule {
        $script:Processes=@(
            [pscustomobject]@{Name='example.exe';ProcessId=1010;ParentProcessId=1;CreationDate=[datetime]'2026-01-01 10:20:00';ExecutablePath='C:\Example\example.exe';CommandLine=''},
            [pscustomobject]@{Name='child.exe';ProcessId=1112;ParentProcessId=1010;CreationDate=[datetime]'2026-01-01 10:21:00';ExecutablePath='C:\Example\child.exe';CommandLine=''},
            [pscustomobject]@{Name='grandchild.exe';ProcessId=1113;ParentProcessId=1112;CreationDate=[datetime]'2026-01-01 10:22:00';ExecutablePath='C:\Example\grandchild.exe';CommandLine=''},
            [pscustomobject]@{Name='older.exe';ProcessId=1114;ParentProcessId=1010;CreationDate=[datetime]'2026-01-01 10:10:00';ExecutablePath='C:\Example\older.exe';CommandLine=''},
            [pscustomobject]@{Name='unrelated.exe';ProcessId=9999;ParentProcessId=1;CreationDate=[datetime]'2026-01-01 10:25:00';ExecutablePath='C:\Example\unrelated.exe';CommandLine=''}
        )
        function script:Get-CimInstance { param($ClassName) $script:Processes }
    }
    & $coreModule { param($Path) $script:Processes[0].ExecutablePath=$Path } $hashFile
    $nodes=@{}
    Update-WAObservedProcesses -Nodes $nodes -ProcessName 'example.exe'
    Assert-True ($nodes.Count -eq 3) 'El arbol debe incluir hijos y nietos, excluir otros y rechazar padre mas joven.'
    $oldRoot=@($nodes.Values | Where-Object {$_.IsRoot})[0]
    $child=@($nodes.Values | Where-Object {$_.ProcessId -eq 1112})[0]
    Assert-True ($child.ParentKey -eq $oldRoot.Key) 'Relacion padre-hijo incorrecta.'
    & $coreModule { $script:Processes[0].CreationDate=[datetime]'2026-01-01 10:30:00' }
    Update-WAObservedProcesses -Nodes $nodes -ProcessName 'example.exe'
    Assert-True ($nodes.Count -eq 4) 'Debe conservar dos instancias distintas con un PID reutilizado.'
    Assert-True ($child.ParentKey -eq $oldRoot.Key) 'No debe reasignar hijos a un PID reutilizado.'
    $tree=Join-Path $temp 'test-tree.txt'
    [void](Export-WACaptureTree -Nodes $nodes -Metadata $capture -Path $tree)
    $treeText=Get-Content -LiteralPath $tree -Raw
    Assert-True ($treeText -match 'child.exe PID 1112' -and $treeText -notmatch 'unrelated.exe') 'Contenido incorrecto del arbol.'
    Assert-True ($treeText -match 'example.exe PID 1010 \| MD5: E2FC714C4727EE9395F324CD2E7F331F \| Signature: Valid \| Firmante: CN=Example Publisher') 'Formato del TXT incorrecto.'
    Assert-True ($treeText -match 'child.exe PID 1112 \| MD5: NoDisponible \| Signature: NoDisponible') 'Debe mostrar evidencia inaccesible sin inventar valores.'
    $screenTree=Export-WACaptureTree -Nodes $nodes -Metadata $capture -Path $tree -ShowOnScreen 6>&1 | Out-String
    Assert-True ($screenTree.Contains('example.exe PID 1010 | MD5: E2FC714C4727EE9395F324CD2E7F331F | Signature: Valid')) 'La pantalla debe mostrar el mismo formato de evidencia.'
    & $coreModule { Remove-Item Function:\Get-AuthenticodeSignature }
    $linkEvent=[pscustomobject]@{LogName='Microsoft-Windows-Sysmon/Operational';Id=10;TimeCreated=$now;RecordId=10;EventXml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="SourceProcessId">1010</Data><Data Name="TargetProcessId">2222</Data><Data Name="SourceImage">C:\Example\example.exe</Data><Data Name="TargetImage">C:\Example\other.exe</Data></EventData></Event>'}
    $link=ConvertTo-WAProcessLink -Event $linkEvent
    Assert-True ($link.ToPid -eq '2222' -and $link.Kind -like '*no implica parentesco*') 'Debe separar vinculos de parentesco.'
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
