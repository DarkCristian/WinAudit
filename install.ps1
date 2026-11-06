#requires -Version 5.1
# Launcher: fuente inmutable y SHA-256 comprobado antes de ejecutar.
param([switch]$NonInteractive)
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
function ConvertTo-WADisplayText {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    return ($Text -replace '[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]','?')
}
function ConvertFrom-WAEventXml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    if ($Text.Length -gt 4194304) {throw 'XML de evento supera el limite de 4 Mi caracteres.'}
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=4194304
    $inputReader=New-Object IO.StringReader($Text)
    $reader=$null
    try {
        $reader=[Xml.XmlReader]::Create($inputReader,$settings)
        $document=New-Object Xml.XmlDocument
        $document.XmlResolver=$null
        $document.Load($reader)
        return ,$document
    } finally {
        if ($null -ne $reader) {$reader.Dispose()}
        $inputReader.Dispose()
    }
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
function New-WAEvidenceFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[string]$Content='')
    $full=Resolve-WALocalEvidencePath -Path $Path -AllowMissing
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Content)
        $stream.Write($bytes,0,$bytes.Length)
    } finally {$stream.Dispose()}
    return $full
}

function Get-WARuntimeAssessment {
    [CmdletBinding()]
    param([version]$Version=([version]($PSVersionTable.PSVersion.ToString().Split('-')[0])),[string]$Platform=$env:OS,[switch]$Prerelease)
    if (-not $PSBoundParameters.ContainsKey('Version') -and $PSVersionTable.PSVersion.ToString().Contains('-')) {$Prerelease=$true}
    $state='Unsupported';$canContinue=$false;$cve=$null
    if ($Platform -ne 'Windows_NT') {$state='UnsupportedPlatform'}
    elseif ($Prerelease) {$state='UnsupportedPreview'}
    elseif ($Version.Major -eq 5 -and $Version.Minor -eq 1) {$state='WindowsUpdateRequired';$canContinue=$true}
    else {
        try {Assert-WASupportedRuntime -Version $Version -Platform $Platform -WarningAction SilentlyContinue;$canContinue=$true;$state='PatchedKnownBranch'} catch {
            if ($Version.Major -eq 7 -and $Version.Minor -in @(4,5,6)) {$state='Affected';$cve='CVE-2026-96303'}
        }
        if ($canContinue -and $Version.Minor -gt 6) {$state='UnreviewedBranch'}
    }
    [pscustomobject]@{Version=$Version.ToString();State=$state;CanContinue=$canContinue;CVE=$cve;ReviewDate='2026-11-05'}
}
function Confirm-WARuntimeAction {
    param([string]$Message)
    try {
        $answer=Read-Host ($Message+' [S/N]')
        return ($answer.Trim() -ieq 'S')
    } catch {return $false}
}
function Assert-WAMicrosoftSignedFile {
    param([Parameter(Mandatory)][string]$Path)
    $local=Resolve-WALocalEvidencePath -Path $Path
    $signature=Get-AuthenticodeSignature -LiteralPath $local -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw 'Firma Microsoft valida requerida; no se ejecuta el archivo.'
    }
    return $local
}
function Get-WAWinGetPath {
    # No ejecutar un winget.exe arbitrario encontrado en PATH o en el directorio actual.
    $packages=@(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending)
    foreach ($package in $packages) {
        try {return (Assert-WAMicrosoftSignedFile (Join-Path $package.InstallLocation 'winget.exe'))} catch {continue}
    }
    return $null
}
function Invoke-WAWinGetUpgrade {
    param([string]$Path,[switch]$NonInteractive)
    & $Path -NonInteractive:$NonInteractive upgrade --id Microsoft.PowerShell --exact --source winget --interactive | Out-Host
    return $LASTEXITCODE
}
function Get-WARuntimeArchitecture {
    $architecture=$env:PROCESSOR_ARCHITEW6432
    if (-not $architecture) {$architecture=$env:PROCESSOR_ARCHITECTURE}
    switch ($architecture) {'AMD64' {return 'x64'} 'ARM64' {return 'arm64'} 'x86' {return 'x86'} default {throw 'Arquitectura de Windows no admitida para MSI.'}}
}
function Get-WAOfficialRuntimeRelease {
    param([ValidateSet('x64','arm64','x86')][string]$Architecture)
    $release=Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -Headers @{'User-Agent'='WinAudit-runtime-update'} -MaximumRedirection 0 -TimeoutSec 30 -ErrorAction Stop
    if ($release.draft -or $release.prerelease -or $release.tag_name -notmatch '^v7\.\d+\.\d+$') {throw 'La fuente no devolvio una release estable valida.'}
    $version=[version]$release.tag_name.Substring(1)
    Assert-WASupportedRuntime -Version $version -Platform Windows_NT
    $name='PowerShell-{0}-win-{1}.msi' -f $version,$Architecture
    $assets=@($release.assets | Where-Object {$_.name -ceq $name})
    if ($assets.Count -ne 1) {throw 'No hay MSI oficial para esta version/arquitectura. Usa WinGet o la guia de Microsoft.'}
    $asset=$assets[0]
    $expectedUrl='https://github.com/PowerShell/PowerShell/releases/download/{0}/{1}' -f $release.tag_name,$name
    if ($asset.browser_download_url -cne $expectedUrl -or -not $asset.PSObject.Properties['digest'] -or $asset.digest -notmatch '^sha256:[0-9a-fA-F]{64}$') {throw 'URL o SHA-256 del MSI oficial no verificable; descarga cancelada.'}
    [pscustomobject]@{Version=$version.ToString();Name=$name;Url=$expectedUrl;SHA256=$asset.digest.Substring(7).ToLowerInvariant()}
}
function Save-WARuntimeInstaller {
    param([string]$Url,[string]$Path)
    # GitHub usa una redireccion HTTPS al CDN; hash y Authenticode se comprueban antes de instalar.
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 120 -ErrorAction Stop
}
function Invoke-WAMsiProcess {
    param([string]$Path)
    $msiexec=Assert-WAMicrosoftSignedFile (Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe')
    $process=Start-Process -FilePath $msiexec -ArgumentList @('/i',('"'+$Path+'"'),'/norestart','USE_MU=1','ENABLE_MU=1','ENABLE_PSREMOTING=0') -Wait -PassThru -ErrorAction Stop
    return $process.ExitCode
}
function Install-WAOfficialRuntimeMsi {
    $release=Get-WAOfficialRuntimeRelease -Architecture (Get-WARuntimeArchitecture)
    $folder=Join-Path ([IO.Path]::GetTempPath()) ('WinAudit-runtime-'+[guid]::NewGuid().ToString('N'))
    $created=$false;$lock=$null
    try {
        $folder=Resolve-WALocalEvidencePath $folder -AllowMissing
        if ([IO.Directory]::Exists($folder)) {throw 'Directorio temporal inesperado.'}
        $folder=Initialize-WAReportDirectory $folder;$created=$true
        $file=Join-Path $folder $release.Name
        Save-WARuntimeInstaller -Url $release.Url -Path $file
        $file=Resolve-WALocalEvidencePath $file
        $lock=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $algorithm=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($algorithm.ComputeHash($lock))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
        if ($hash -cne $release.SHA256) {throw 'SHA-256 del MSI incorrecto; no se instala.'}
        [void](Assert-WAMicrosoftSignedFile $file)
        $code=Invoke-WAMsiProcess $file
        if ($code -notin @(0,1641,3010)) {throw ('Instalacion MSI cancelada o fallida; codigo '+$code)}
        return [pscustomobject]@{Method='MicrosoftMSI';ExitCode=$code;RebootRequired=($code -in @(1641,3010))}
    } finally {
        if ($null -ne $lock) {$lock.Dispose()}
        if ($created) {
            try {
                [void](Resolve-WALocalEvidencePath $folder)
                $file=Join-Path $folder $release.Name
                if ([IO.File]::Exists($file)) {[void](Resolve-WALocalEvidencePath $file);[IO.File]::Delete($file)}
                [IO.Directory]::Delete($folder)
            } catch {Write-Warning 'No se pudo limpiar el temporal del MSI; revisalo manualmente.'}
        }
    }
}
function Get-WAInstalledRuntimeInfo {
    $paths=New-Object 'System.Collections.Generic.List[string]'
    foreach ($base in @($env:ProgramW6432,$env:ProgramFiles,${env:ProgramFiles(x86)})) {
        if ($base) {$paths.Add((Join-Path $base 'PowerShell\7\pwsh.exe'))}
    }
    try {
        foreach ($package in @(Get-AppxPackage -Name Microsoft.PowerShell -ErrorAction SilentlyContinue)) {$paths.Add((Join-Path $package.InstallLocation 'pwsh.exe'))}
    } catch {}
    foreach ($path in @($paths | Select-Object -Unique)) {
        try {
            $local=Assert-WAMicrosoftSignedFile $path
            $product=[Diagnostics.FileVersionInfo]::GetVersionInfo($local).ProductVersion
            if ($product -notmatch '^(7\.\d+\.\d+)(?:\s|\+|$)') {continue}
            $assessment=Get-WARuntimeAssessment -Version ([version]$Matches[1]) -Platform Windows_NT
            if ($assessment.CanContinue) {return [pscustomobject]@{Path=$local;Version=$assessment.Version}}
        } catch {continue}
    }
    return $null
}
function Open-WAWindowsUpdate {
    Start-Process -FilePath 'ms-settings:windowsupdate' -ErrorAction Stop | Out-Null
}
function Invoke-WARuntimeUpdate {
    $result=$null;$winget=$null
    try {$winget=Get-WAWinGetPath} catch {}
    if ($winget) {
        Write-Host 'Actualizando Microsoft.PowerShell desde WinGet. Puede solicitar UAC o acuerdos del proveedor; no se aceptan automaticamente.'
        try {
            $code=Invoke-WAWinGetUpgrade $winget
            if ($code -eq 0) {$result=[pscustomobject]@{Method='WinGet';ExitCode=0;RebootRequired=$false}}
        } catch {}
    }
    if ($null -eq $result) {
        if (-not (Confirm-WARuntimeAction 'WinGet no esta disponible o no pudo actualizar. Intentar MSI oficial de Microsoft (verifica SHA-256 y firma, permite Microsoft Update)')) {return $null}
        $result=Install-WAOfficialRuntimeMsi
    }
    $installed=Get-WAInstalledRuntimeInfo
    if ($null -eq $installed) {Write-Warning 'El instalador termino, pero no se pudo verificar una instalacion corregida. No se continua la auditoria.'}
    else {Write-Host ('Binario instalado verificado: PowerShell {0}, {1}' -f $installed.Version,$installed.Path)}
    if ($result.RebootRequired) {Write-Warning 'El instalador indica que Windows necesita reiniciarse. WinAudit no reinicia el equipo.'}
    Write-Host 'La sesion actual conserva la version anterior. Abri una nueva sesion de PowerShell actualizado y ejecuta WinAudit otra vez; se repetira el chequeo.'
    return $result
}
function Initialize-WARuntimeSecurity {
    [CmdletBinding()]
    param([switch]$NonInteractive,[switch]$DeferWindowsUpdate)
    $assessment=Get-WARuntimeAssessment
    switch ($assessment.State) {
        'PatchedKnownBranch' {return $true}
        'UnreviewedBranch' {Write-Warning 'Rama posterior al relevamiento de seguridad del 05/11/2026; revisa soporte y avisos de Microsoft.';return $true}
        'UnsupportedPlatform' {throw 'WinAudit solo admite Windows.'}
        'WindowsUpdateRequired' {
            if ($DeferWindowsUpdate) {return $true}
            Write-Warning 'Windows PowerShell 5.1: el numero de version no confirma los parches. Las correcciones llegan mediante Windows Update.'
            if (-not $NonInteractive -and (Confirm-WARuntimeAction 'Desea abrir Windows Update para buscar e instalar actualizaciones')) {
                try {Open-WAWindowsUpdate;Write-Host 'Completa Windows Update y reinicia si Windows lo solicita. WinAudit no instala todas las KB ni certifica su estado.'} catch {Write-Warning 'No se pudo abrir Windows Update. Usa la herramienta de actualizacion aprobada por tu organizacion.'}
                return $false
            }
            return $true
        }
        default {
            if ($assessment.State -eq 'Affected') {Write-Warning ('Su version de PowerShell '+$assessment.Version+' esta afectada por '+$assessment.CVE+'.')}
            else {Write-Warning ('PowerShell '+$assessment.Version+' no es una version estable admitida en esta revision.')}
            if ($NonInteractive -or -not (Confirm-WARuntimeAction 'Su version puede tener baches de seguridad. Desea actualizar PowerShell desde Microsoft')) {throw 'Auditoria detenida. Actualiza PowerShell y abre una sesion nueva.'}
            try {[void](Invoke-WARuntimeUpdate)} catch {Write-Warning ('Actualizacion no completada: '+(ConvertTo-WADisplayText $_.Exception.Message));Write-Host 'Guia oficial: https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows'}
            return $false
        }
    }
}
function Invoke-WALaunchScript {
    param([string]$Path,[switch]$NonInteractive)
    & $Path -NonInteractive:$NonInteractive
}
function Invoke-WABootstrap {
    param([switch]$NonInteractive)
    if (-not (Initialize-WARuntimeSecurity -NonInteractive:$NonInteractive -DeferWindowsUpdate)) {return}
    $source='https://raw.githubusercontent.com/DarkCristian/WinAudit/c27df4f1a99fabbf13e7c0e8a588ff0c2b930f90/dist/WinAudit-Standalone.ps1'
    $expected='00f203f1d5824b64c2ad56bb810a48126be6ee96587013ca96e8ae79ebd12368'
    $root=Join-Path ([IO.Path]::GetTempPath()) ('WinAudit-'+[guid]::NewGuid().ToString('N'))
    $lock=$null
    $created=$false
    try {
        $root=Resolve-WALocalEvidencePath -Path $root -AllowMissing
        if ([IO.Directory]::Exists($root)) {throw 'Directorio temporal inesperado.'}
        $root=Initialize-WAReportDirectory $root
        $created=$true
        $file=Join-Path $root 'WinAudit-Standalone.ps1'
        Invoke-WebRequest -Uri $source -OutFile $file -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 30 -ErrorAction Stop
        $file=Resolve-WALocalEvidencePath $file
        # Bloquear escritura y reemplazo desde la comprobacion hasta finalizar ejecucion.
        $lock=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $algorithm=[Security.Cryptography.SHA256]::Create()
        try {$actual=([BitConverter]::ToString($algorithm.ComputeHash($lock))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
        if ($actual -cne $expected) {throw 'SHA-256 incorrecto: descarga rechazada, no se ejecuta.'}
        Invoke-WALaunchScript $file -NonInteractive:$NonInteractive
    } finally {
        if ($null -ne $lock) {$lock.Dispose()}
        if ($created -and [IO.Directory]::Exists($root)) {
            try {
                [void](Resolve-WALocalEvidencePath $root)
                $file=Join-Path $root 'WinAudit-Standalone.ps1'
                if ([IO.File]::Exists($file)) {[void](Resolve-WALocalEvidencePath $file);[IO.File]::Delete($file)}
                [IO.Directory]::Delete($root)
            } catch {Write-Warning 'No se pudo limpiar el temporal; revisalo manualmente.'}
        }
    }
}
Invoke-WABootstrap -NonInteractive:$NonInteractive
