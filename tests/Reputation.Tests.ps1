#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules/Reputation.psm1') -Force
$module=Get-Module Reputation
function Assert-VT($Condition,$Message) { if (-not $Condition) {throw $Message} }
$key=ConvertTo-SecureString 'WINAUDIT_TEST_KEY_NOT_A_CREDENTIAL' -AsPlainText -Force
$hash='a'*64
& $module {
    $script:Calls=0; $script:ResponseMode='success'; $script:Waits=0
    function script:Start-Sleep { param($Milliseconds) $script:Waits++ }
    function script:Invoke-RestMethod {
        [CmdletBinding()] param($Method,$Uri,$Headers,$MaximumRedirection,$TimeoutSec)
        $script:Calls++
        if ($Method -ne 'Get' -or $Uri -notmatch '^https://www\.virustotal\.com/api/v3/files/[a-f0-9]{64}$' -or $MaximumRedirection -ne 0 -or $TimeoutSec -ne 20) { throw 'Peticion insegura en prueba' }
        if (-not $Headers.ContainsKey('x-apikey') -or $Uri -like '*WINAUDIT_TEST*') {throw 'Autenticacion incorrecta'}
        if ($script:ResponseMode -match '^http(\d+)$') {
            $errorObject=New-Object System.Exception('Mensaje remoto no debe exportarse: WINAUDIT_TEST_KEY_NOT_A_CREDENTIAL')
            $errorObject | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=[int]$Matches[1]})
            throw $errorObject
        }
        if ($script:ResponseMode -eq 'network') {throw 'Mensaje remoto secreto: WINAUDIT_TEST_KEY_NOT_A_CREDENTIAL'}
        if ($script:ResponseMode -eq 'bad') {return [pscustomobject]@{invalid='WINAUDIT_TEST_KEY_NOT_A_CREDENTIAL'}}
        $stats=[pscustomobject]@{malicious=2; suspicious=1; harmless=1; undetected=66; timeout=3}
        if ($script:ResponseMode -eq 'zero') {$stats.malicious=0; $stats.suspicious=0}
        $id=($Uri -split '/')[-1]
        if ($script:ResponseMode -eq 'wrongHash') {$id='f'*64}
        [pscustomobject]@{data=[pscustomobject]@{id=$id;type='file';attributes=[pscustomobject]@{last_analysis_stats=$stats;last_analysis_date=1700000000}}}
    }
}
$off=Get-WAVirusTotalReport -SHA256 $hash
Assert-VT ($off.State -eq 'Desactivado' -and (& $module {$script:Calls}) -eq 0) 'Desactivado no debe consultar la red.'
$ctx=New-WAVirusTotalContext -ApiKey $key
$result=Get-WAVirusTotalReport -SHA256 $hash -Context $ctx
Assert-VT ($result.State -eq 'Encontrado' -and $result.Malicious -eq 2 -and $result.Suspicious -eq 1 -and $result.EnginesWithVerdict -eq 70) 'Estadisticas o denominador incorrectos.'
Assert-VT ($result.LastAnalysisUtc -eq '2023-11-14T22:13:20.0000000Z') 'Fecha de analisis UTC incorrecta.'
$cached=Get-WAVirusTotalReport -SHA256 $hash.ToUpperInvariant() -Context $ctx
Assert-VT ($cached.Cached -and (& $module {$script:Calls}) -eq 1) 'Debe reutilizar hash unico sin otra solicitud.'
[void](Get-WAVirusTotalReport -SHA256 ('b'*64) -Context $ctx)
Assert-VT ((& $module {$script:Waits}) -gt 0) 'Debe espaciar solicitudes.'
$ctx.MaxRequests=$ctx.Requests
Assert-VT ((Get-WAVirusTotalReport -SHA256 ('c'*64) -Context $ctx).State -eq 'LimiteAlcanzado') 'Debe respetar tope local.'
foreach ($case in @(@('http404','SinAntecedentes'),@('http401','CredencialesInvalidas'),@('http403','SinPermiso'),@('http429','LimiteAlcanzado'),@('http503','ErrorServicio'),@('network','ErrorConexion'),@('bad','RespuestaInvalida'),@('wrongHash','RespuestaInvalida'))) {
    & $module {param($Mode) $script:ResponseMode=$Mode} $case[0]
    $ctx=New-WAVirusTotalContext -ApiKey $key
    $r=Get-WAVirusTotalReport -SHA256 $hash -Context $ctx
    Assert-VT ($r.State -eq $case[1] -and $null -eq $r.Malicious) ('Manejo incorrecto: '+$case[0])
    Assert-VT (($r | ConvertTo-Json -Depth 5) -notlike '*WINAUDIT_TEST_KEY_NOT_A_CREDENTIAL*') 'No debe exportar clave ni mensaje remoto.'
    if ($case[0] -in @('http404','http401','http403','http429')) {
        $before=& $module {$script:Calls}
        [void](Get-WAVirusTotalReport -SHA256 $hash -Context $ctx)
        Assert-VT ((& $module {$script:Calls}) -eq $before) 'No debe repetir solicitud cacheada o bloqueada.'
    }
}
& $module {$script:ResponseMode='zero'}
$zero=Get-WAVirusTotalReport -SHA256 $hash -Context (New-WAVirusTotalContext -ApiKey $key)
Assert-VT ($zero.State -eq 'Encontrado' -and $zero.Detail -like '*no garantiza seguridad*') 'Cero detecciones no equivale a seguro.'
$threw=$false
try {Get-WAVirusTotalReport -SHA256 'https://example.com/'} catch {$threw=$true}
Assert-VT $threw 'Debe rechazar entradas que no sean SHA256.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('WA-vt-test-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temp)
try {
    $path=Join-Path $temp 'example.bin'
    [IO.File]::WriteAllText($path,'abc',(New-Object Text.UTF8Encoding($false)))
    & $module {$script:ResponseMode='success'}
    $ctx=New-WAVirusTotalContext -ApiKey $key
    $nodes=@{one=[pscustomobject]@{ExecutablePath=$path;MD5='900150983CD24FB0D6963F7D28E17F72'}}
    $before=& $module {$script:Calls}
    Add-WAVirusTotalToProcesses -Nodes $nodes
    Assert-VT ((& $module {$script:Calls}) -eq $before -and -not $nodes.one.PSObject.Properties['VirusTotal']) 'Sin contexto no debe calcular ni consultar reputacion.'
    Add-WAVirusTotalToProcesses -Nodes $nodes -Context $ctx
    Assert-VT ($nodes.one.VirusTotal.State -eq 'Encontrado') 'Debe enriquecer el proceso de forma opcional.'
    [IO.File]::WriteAllText($path,'changed',(New-Object Text.UTF8Encoding($false)))
    $before=& $module {$script:Calls}
    Add-WAVirusTotalToProcesses -Nodes $nodes -Context $ctx
    Assert-VT ($nodes.one.VirusTotal.State -eq 'EvidenciaNoDisponible' -and (& $module {$script:Calls}) -eq $before) 'Un archivo cambiado no debe asociarse al hash capturado.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Host 'PASS VirusTotal: red simulada, opt-in, cache, limites, errores y privacidad.'
