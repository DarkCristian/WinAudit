#requires -Version 5.1
# Launcher: fuente inmutable y SHA-256 comprobado antes de ejecutar.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-WASupportedRuntime {
    [CmdletBinding()]
    param([version]$Version=([version]($PSVersionTable.PSVersion.ToString().Split('-')[0])),[string]$Platform=$env:OS)
    if ($Platform -ne 'Windows_NT') {throw 'WinAudit solo admite Windows.'}
    if (-not $PSBoundParameters.ContainsKey('Version') -and $PSVersionTable.PSVersion.ToString().Contains('-')) {throw 'Usa una version estable y actualizada de PowerShell.'}
    if ($Version.Major -eq 5 -and $Version.Minor -eq 1) {return}
    $minimum=switch ('{0}.{1}' -f $Version.Major,$Version.Minor) {
        '7.4' {[version]'7.4.21'}
        '7.5' {[version]'7.5.12'}
        '7.6' {[version]'7.6.7'}
        default {$null}
    }
    if ($null -ne $minimum -and $Version -ge $minimum) {return}
    if ($Version.Major -eq 7 -and $Version.Minor -gt 6) {Write-Warning 'Rama posterior al relevamiento de seguridad: revisa soporte y avisos de Microsoft.';return}
    throw 'PowerShell no admitido o anterior al minimo de seguridad revisado: usa 7.4.21+, 7.5.12+ o 7.6.7+ dentro de una rama con soporte, o Windows PowerShell 5.1 con Windows actualizado. WinAudit no instala parches del sistema.'
}
function Get-WALocalDriveType {
    param([string]$Root)
    return ([IO.DriveInfo]::new($Root)).DriveType
}
function Resolve-WALocalEvidencePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[switch]$AllowMissing)
    # Rechazar antes de acceder al filesystem: UNC, dispositivos, ADS y controles.
    if ($Path -match '^[\\/]{2}' -or $Path -match '[\x00-\x1f\x7f-\x9f]' -or $Path -match ':.*:') {throw 'Solo se admiten rutas locales sin UNC, dispositivos, ADS ni controles.'}
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[a-zA-Z]:\\' -or $full.Substring(2).Contains(':')) {throw 'La evidencia requiere una ruta de filesystem local.'}
    $root=[IO.Path]::GetPathRoot($full)
    $driveType=Get-WALocalDriveType $root
    if ($driveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::CDRom,[IO.DriveType]::Ram)) {throw 'No se leen evidencias ni se escriben informes en unidades de red o desconocidas.'}
    $current=$root
    $parts=@('')+@($full.Substring($root.Length).Split('\') | Where-Object {$_})
    foreach ($part in $parts) {
        if ($part) {$current=[IO.Path]::Combine($current,$part)}
        try {$attributes=[IO.File]::GetAttributes($current)}
        catch [IO.FileNotFoundException] {if ($AllowMissing) {return $full};throw}
        catch [IO.DirectoryNotFoundException] {if ($AllowMissing) {return $full};throw}
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Ruta con reparse point o junction rechazada; no se sigue para leer evidencia ni escribir informes.'}
    }
    return $full
}
function Initialize-WAReportDirectory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)
    $full=Resolve-WALocalEvidencePath -Path $Directory -AllowMissing
    [void][IO.Directory]::CreateDirectory($full)
    return (Resolve-WALocalEvidencePath -Path $full)
}

function Invoke-WALaunchScript {
    param([string]$Path)
    & $Path
}
function Invoke-WABootstrap {
    Assert-WASupportedRuntime
    $source='https://raw.githubusercontent.com/DarkCristian/WinAudit/6e883047e3b11ba19e68bc19fc2f977f745842ec/dist/WinAudit-Standalone.ps1'
    $expected='369a7d9518a240a4a81e76a2dd7acb05146be228eb4d8ad27c2c0e0100229f14'
    $root=Join-Path ([IO.Path]::GetTempPath()) ('WinAudit-'+[guid]::NewGuid().ToString('N'))
    $lock=$null
    try {
        if ([IO.Directory]::Exists($root)) {throw 'Directorio temporal inesperado.'}
        $root=Initialize-WAReportDirectory $root
        $file=Join-Path $root 'WinAudit-Standalone.ps1'
        Invoke-WebRequest -Uri $source -OutFile $file -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 30 -ErrorAction Stop
        $file=Resolve-WALocalEvidencePath $file
        # Bloquear escritura y reemplazo desde la comprobacion hasta finalizar ejecucion.
        $lock=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $algorithm=[Security.Cryptography.SHA256]::Create()
        try {$actual=([BitConverter]::ToString($algorithm.ComputeHash($lock))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
        if ($actual -cne $expected) {throw 'SHA-256 incorrecto: descarga rechazada, no se ejecuta.'}
        Invoke-WALaunchScript $file
    } finally {
        if ($null -ne $lock) {$lock.Dispose()}
        if ([IO.Directory]::Exists($root)) {
            try {
                [void](Resolve-WALocalEvidencePath $root)
                $file=Join-Path $root 'WinAudit-Standalone.ps1'
                if ([IO.File]::Exists($file)) {[void](Resolve-WALocalEvidencePath $file);[IO.File]::Delete($file)}
                [IO.Directory]::Delete($root)
            } catch {Write-Warning 'No se pudo limpiar el temporal; revisalo manualmente.'}
        }
    }
}
Invoke-WABootstrap
