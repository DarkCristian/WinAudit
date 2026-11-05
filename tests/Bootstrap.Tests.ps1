#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
# Cargar solo definiciones de funciones del launcher; nunca su invocacion de red.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'install.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'Sintaxis del launcher invalida.'}
foreach ($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$script:guardCalled=0;$script:launched=0;$script:tamper=$true
function Assert-WASupportedRuntime {$script:guardCalled++}
function Invoke-WebRequest {
    param($Uri,$OutFile,[switch]$UseBasicParsing,$MaximumRedirection,$TimeoutSec,$ErrorAction)
    if ($Uri -notmatch '^https://raw\.githubusercontent\.com/DarkCristian/WinAudit/[a-f0-9]{40}/dist/WinAudit-Standalone\.ps1$') {throw 'Fuente no inmutable.'}
    if (-not $UseBasicParsing -or $MaximumRedirection -ne 0 -or $TimeoutSec -ne 30) {throw 'Opciones HTTP inseguras.'}
    if ($script:tamper) {[IO.File]::WriteAllText($OutFile,'throw "tampered"')} else {[IO.File]::Copy((Join-Path $root 'dist/WinAudit-Standalone.ps1'),$OutFile)}
    $script:downloadPath=$OutFile
}
function Invoke-WALaunchScript {
    param($Path)
    $script:launched++
    $blocked=$false
    try {$s=[IO.File]::OpenWrite($Path);$s.Dispose()} catch {$blocked=$true}
    if (-not $blocked) {throw 'El script verificado debe quedar bloqueado contra escritura.'}
}
$rejected=$false
try {Invoke-WABootstrap} catch {if ($_.Exception.Message -notmatch 'SHA-256 incorrecto') {throw};$rejected=$true}
if (-not $rejected -or $script:launched -ne 0) {throw 'Descarga alterada ejecutada.'}
if ([IO.File]::Exists($script:downloadPath)) {throw 'Temporal alterado no eliminado.'}
$script:tamper=$false
Invoke-WABootstrap
if ($script:launched -ne 1 -or $script:guardCalled -ne 2) {throw 'No se ejecuto exactamente una descarga valida con control previo de runtime.'}
if ([IO.File]::Exists($script:downloadPath)) {throw 'Temporal valido no eliminado.'}
Write-Host 'PASS Bootstrap: commit inmutable, HTTP acotado, SHA-256, rechazo sin ejecucion y bloqueo de escritura.'
