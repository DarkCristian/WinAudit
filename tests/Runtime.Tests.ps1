#requires -Version 5.1
$ErrorActionPreference='Stop'
$runtimeTestRoot=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $runtimeTestRoot 'Modules/Security.psm1') -Force
Import-Module (Join-Path $runtimeTestRoot 'Modules/Runtime.psm1') -Force
function Assert-Runtime($Condition,$Message) {if (-not $Condition) {throw $Message}}
foreach ($v in @('7.4.20','7.5.11','7.6.6')) {
    $s=Get-WARuntimeAssessment -Version ([version]$v) -Platform Windows_NT
    Assert-Runtime ($s.State -eq 'Affected' -and -not $s.CanContinue -and $s.CVE -eq 'CVE-2026-96303') 'Debe identificar versiones afectadas.'
}
foreach ($v in @('7.4.21','7.5.12','7.6.7')) {Assert-Runtime (Get-WARuntimeAssessment -Version ([version]$v) -Platform Windows_NT).CanContinue 'Debe admitir parches conocidos.'}
$s=Get-WARuntimeAssessment -Version ([version]'5.1.0') -Platform Windows_NT
Assert-Runtime ($s.State -eq 'WindowsUpdateRequired' -and -not $s.CVE) 'No debe afirmar estado de KB por numero 5.1.'
Assert-Runtime (-not (Get-WARuntimeAssessment -Version ([version]'7.7.0') -Prerelease -Platform Windows_NT).CanContinue) 'No admitir previews.'
$m=Get-Module Runtime
& $m {
    $script:prompts=0;$script:updates=0;$script:opened=0;$script:answer=$false;$script:fixtureState='Affected'
    function script:Get-WARuntimeAssessment {[pscustomobject]@{State=$script:fixtureState;Version='7.6.6';CVE='CVE-2026-96303'}}
    function script:Confirm-WARuntimeAction {param($Message) $script:prompts++;$script:answer}
    function script:Invoke-WARuntimeUpdate {$script:updates++}
    function script:Open-WAWindowsUpdate {$script:opened++}
}
$rejected=$false;try {[void](Initialize-WARuntimeSecurity -NonInteractive -WarningAction SilentlyContinue)} catch {$rejected=$true}
Assert-Runtime $rejected 'Sin interaccion debe detener un runtime afectado.'
Assert-Runtime (& $m {$script:prompts -eq 0 -and $script:updates -eq 0}) 'No preguntar ni instalar sin interaccion.'
$rejected=$false;try {[void](Initialize-WARuntimeSecurity -WarningAction SilentlyContinue)} catch {$rejected=$true}
Assert-Runtime $rejected 'Respuesta N debe detener auditoria afectada.'
Assert-Runtime (& $m {$script:updates -eq 0}) 'N no debe actualizar.'
& $m {$script:answer=$true}
Assert-Runtime (-not (Initialize-WARuntimeSecurity -WarningAction SilentlyContinue)) 'Despues de actualizar debe terminar la sesion de auditoria.'
Assert-Runtime (& $m {$script:updates -eq 1}) 'S debe actualizar una vez.'
& $m {$script:fixtureState='WindowsUpdateRequired';$script:answer=$false}
Assert-Runtime (Initialize-WARuntimeSecurity -NonInteractive -WarningAction SilentlyContinue) '5.1 sin interaccion puede continuar con advertencia.'
& $m {$script:answer=$true}
Assert-Runtime (-not (Initialize-WARuntimeSecurity -WarningAction SilentlyContinue)) 'Windows Update debe terminar este intento.'
Assert-Runtime (& $m {$script:opened -eq 1}) 'Debe abrir Windows Update solo tras S.'
# Restablecer implementacion antes de validar descarga, firma y MSI con fixtures.
Import-Module (Join-Path $runtimeTestRoot 'Modules/Runtime.psm1') -Force
$m=Get-Module Runtime
& $m {
    function script:Get-AuthenticodeSignature {param($LiteralPath,$ErrorAction) [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Other Publisher, O=Other Publisher'}}}
}
$tempFile=Join-Path ([IO.Path]::GetTempPath()) ('WA-runtime-test-'+[guid]::NewGuid().ToString('N')+'.txt')
[IO.File]::WriteAllText($tempFile,'fixture')
try {
    $rejected=$false;try {& $m {param($p) Assert-WAMicrosoftSignedFile $p} $tempFile | Out-Null} catch {$rejected=$true}
    Assert-Runtime $rejected 'Debe rechazar editor distinto de Microsoft aunque la firma sea valida.'
} finally {[IO.File]::Delete($tempFile)}
Import-Module (Join-Path $runtimeTestRoot 'Modules/Runtime.psm1') -Force
$m=Get-Module Runtime
& $m {
    $script:tamper=$true;$script:installed=0
    function script:Get-WARuntimeArchitecture {'x64'}
    function script:Get-WAOfficialRuntimeRelease {
        $a=[Security.Cryptography.SHA256]::Create();try {$h=([BitConverter]::ToString($a.ComputeHash([Text.Encoding]::UTF8.GetBytes('fixture')))).Replace('-','').ToLowerInvariant()} finally {$a.Dispose()}
        [pscustomobject]@{Version='7.6.7';Name='PowerShell-7.6.7-win-x64.msi';Url='https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/PowerShell-7.6.7-win-x64.msi';SHA256=$h}
    }
    function script:Save-WARuntimeInstaller {param($Url,$Path) $v=if ($script:tamper) {'tampered'} else {'fixture'};[IO.File]::WriteAllText($Path,$v,(New-Object Text.UTF8Encoding($false)))}
    function script:Assert-WAMicrosoftSignedFile {param($Path) $Path}
    function script:Invoke-WAMsiProcess {param($Path) $script:installed++;$blocked=$false;try {$f=[IO.File]::OpenWrite($Path);$f.Dispose()} catch {$blocked=$true};if (-not $blocked) {throw 'MSI sin bloqueo de escritura.'};3010}
}
$rejected=$false;try {& $m {Install-WAOfficialRuntimeMsi} | Out-Null} catch {$rejected=$_.Exception.Message -match 'SHA-256'}
Assert-Runtime $rejected 'MSI alterado debe rechazarse por hash.'
Assert-Runtime (& $m {$script:installed -eq 0}) 'Nunca ejecutar MSI alterado.'
& $m {$script:tamper=$false}
$result=& $m {Install-WAOfficialRuntimeMsi}
Assert-Runtime ($result.RebootRequired -and $result.ExitCode -eq 3010) 'Registrar reinicio requerido sin reiniciar.'
# Metadatos remotos falsos: no aceptar preview, URL de otro origen o digest ausente.
Import-Module (Join-Path $runtimeTestRoot 'Modules/Runtime.psm1') -Force
$m=Get-Module Runtime
& $m {
    function script:Invoke-RestMethod {param($Uri,$Headers,$MaximumRedirection,$TimeoutSec,$ErrorAction) [pscustomobject]@{draft=$false;prerelease=$false;tag_name='v7.6.7';assets=@([pscustomobject]@{name='PowerShell-7.6.7-win-x64.msi';browser_download_url='https://other.example.com/runtime.msi';digest=('sha256:'+('a'*64))})}}
}
$rejected=$false;try {& $m {Get-WAOfficialRuntimeRelease -Architecture x64} | Out-Null} catch {$rejected=$true}
Assert-Runtime $rejected 'URL externa no debe convertirse en instalador.'
Import-Module (Join-Path $runtimeTestRoot 'Modules/Runtime.psm1') -Force
Write-Host 'PASS Runtime: CVE/version, S/N, no interaccion, Windows Update, editor, integridad MSI, bloqueo, reinicio y origen oficial. Sin instalaciones reales.'
