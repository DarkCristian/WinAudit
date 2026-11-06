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
    param([string]$Path)
    & $Path upgrade --id Microsoft.PowerShell --exact --source winget --interactive | Out-Host
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


function New-WAVirusTotalContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][securestring]$ApiKey)
    if ($ApiKey.Length -eq 0) { throw 'La clave esta vacia.' }
    # Solo memoria de la sesion. Este objeto nunca se exporta a informes.
    return @{ApiKey=$ApiKey; Cache=@{}; LastRequestUtc=[datetime]::MinValue; BlockedUntilUtc=[datetime]::MinValue; Halted=$null; Requests=0; MaxRequests=100; MinIntervalSeconds=16}
}
function Get-WAVirusTotalReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$SHA256,[hashtable]$Context)
    $hash=$SHA256.ToLowerInvariant()
    $result=[pscustomobject]@{
        SHA256=$hash; State='Desactivado'; Malicious=$null; Suspicious=$null; EnginesWithVerdict=$null
        LastAnalysisUtc=$null; RetrievedAtUtc=$null; ReportUrl=('https://www.virustotal.com/gui/file/'+$hash)
        Cached=$false; Detail='Integracion desactivada.'
    }
    if ($null -eq $Context) { return $result }
    if ($Context.Cache.ContainsKey($hash)) {
        $cached=$Context.Cache[$hash]
        if ((Get-Date).ToUniversalTime() -lt $cached.ExpiresUtc) {
            $copy=[ordered]@{}
            foreach ($property in $cached.Result.PSObject.Properties) { $copy[$property.Name]=$property.Value }
            $copy['Cached']=$true
            return [pscustomobject]$copy
        }
    }
    if ($Context.Halted) { $result.State=$Context.Halted; $result.Detail='Reconfigura la integracion para volver a consultar.'; return $result }
    $now=(Get-Date).ToUniversalTime()
    if ($now -lt $Context.BlockedUntilUtc -or $Context.Requests -ge $Context.MaxRequests) {
        $result.State='LimiteAlcanzado'; $result.Detail='Consulta omitida por limite o pausa de cuota. No se reintenta automaticamente.'; return $result
    }
    $remaining=$Context.MinIntervalSeconds-($now-$Context.LastRequestUtc).TotalSeconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($remaining*1000)) }
    $pointer=[IntPtr]::Zero
    $headers=@{}
    $plain=$null
    try {
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Context.ApiKey)
        $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $headers['x-apikey']=$plain
        $Context.LastRequestUtc=(Get-Date).ToUniversalTime()
        $Context.Requests++
        # URL fija, solo GET por hash, sin archivos, sin seguir redirecciones.
        $response=Invoke-RestMethod -Method Get -Uri ('https://www.virustotal.com/api/v3/files/'+$hash) -Headers $headers -MaximumRedirection 0 -TimeoutSec 20 -ErrorAction Stop -Verbose:$false -Debug:$false
        $result.RetrievedAtUtc=(Get-Date).ToUniversalTime().ToString('o')
        if (-not $response.PSObject.Properties['data']) { throw 'InvalidResponse' }
        $data=$response.data
        if (-not $data.PSObject.Properties['id'] -or [string]$data.id -ine $hash -or -not $data.PSObject.Properties['type'] -or $data.type -ne 'file' -or -not $data.PSObject.Properties['attributes']) { throw 'InvalidResponse' }
        $attributes=$data.attributes
        if (-not $attributes.PSObject.Properties['last_analysis_stats']) {
            $result.State='SinAnalisisDisponible'; $result.Detail='El proveedor conoce el hash pero no devolvio estadisticas de analisis.'
        } else {
            $stats=$attributes.last_analysis_stats
            $counts=@{}
            foreach ($category in @('malicious','suspicious','harmless','undetected')) {
                $number=0L
                if (-not $stats.PSObject.Properties[$category] -or -not [long]::TryParse([string]$stats.$category,[ref]$number) -or $number -lt 0 -or $number -gt 100000) { throw 'InvalidResponse' }
                $counts[$category]=$number
            }
            $result.Malicious=$counts.malicious; $result.Suspicious=$counts.suspicious
            $result.EnginesWithVerdict=$counts.malicious+$counts.suspicious+$counts.harmless+$counts.undetected
            if ($attributes.PSObject.Properties['last_analysis_date']) {
                $result.LastAnalysisUtc=[DateTimeOffset]::FromUnixTimeSeconds([long]$attributes.last_analysis_date).UtcDateTime.ToString('o')
            }
            $result.State='Encontrado'
            $result.Detail='Estadisticas del ultimo analisis disponible; no es un veredicto de WinAudit. Cero detecciones no garantiza seguridad.'
        }
        $Context.Cache[$hash]=@{Result=$result; ExpiresUtc=(Get-Date).ToUniversalTime().AddHours(1)}
    } catch {
        $status=0
        $exception=$_.Exception
        if ($exception.PSObject.Properties['Response'] -and $null -ne $exception.Response -and $exception.Response.PSObject.Properties['StatusCode']) {
            $status=[int]$exception.Response.StatusCode
        }
        # Nunca imprimir excepcion, cuerpo HTTP, cabeceras ni clave del proveedor.
        switch ($status) {
            404 { $result.State='SinAntecedentes'; $result.Detail='El proveedor no encontro un informe para ese hash.'; $Context.Cache[$hash]=@{Result=$result; ExpiresUtc=(Get-Date).ToUniversalTime().AddMinutes(15)} }
            401 { $result.State='CredencialesInvalidas'; $result.Detail='La API rechazo la autenticacion.'; $Context.Halted=$result.State }
            403 { $result.State='SinPermiso'; $result.Detail='La cuenta no tiene permiso para esta consulta.'; $Context.Halted=$result.State }
            429 { $result.State='LimiteAlcanzado'; $result.Detail='Cuota o limite del proveedor alcanzado; pausa local de 60 segundos.'; $Context.BlockedUntilUtc=(Get-Date).ToUniversalTime().AddSeconds(60) }
            default {
                $result.State=if ($exception.Message -eq 'InvalidResponse' -or $result.RetrievedAtUtc) {'RespuestaInvalida'} elseif ($status -ge 500) {'ErrorServicio'} else {'ErrorConexion'}
                $result.Detail='No se obtuvo un informe valido. Se conserva la auditoria local; no se reintenta automaticamente.'
            }
        }
        $result.Malicious=$null; $result.Suspicious=$null; $result.EnginesWithVerdict=$null; $result.LastAnalysisUtc=$null
    } finally {
        $headers.Clear(); $plain=$null
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
    return $result
}
function Add-WAVirusTotalToProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Nodes,[hashtable]$Context)
    if ($null -eq $Context) { return }
    foreach ($node in $Nodes.Values) {
        $reputation=$null
        try {
            if (-not $node.PSObject.Properties['SHA256'] -or $node.SHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Sin SHA256 capturado' }
            # Consulta el SHA256 preservado al observar la instancia, aunque el proceso haya terminado.
            $reputation=Get-WAVirusTotalReport -SHA256 $node.SHA256 -Context $Context
        } catch {
            $reputation=[pscustomobject]@{State='EvidenciaNoDisponible'; Detail='No hay un SHA-256 capturado para esta instancia; no se envio la consulta.'}
        }
        $node | Add-Member -NotePropertyName VirusTotal -NotePropertyValue $reputation -Force
    }
}

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
    param([Parameter(Mandatory)][string]$Path,[ValidateSet('SHA256','MD5','Both')][string]$HashAlgorithm='SHA256')
    $Path=Resolve-WALocalEvidencePath -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not accessible: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $sha256 = if ($HashAlgorithm -in @('SHA256','Both')) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } else { $null }
    $md5 = if ($HashAlgorithm -in @('MD5','Both')) { (Get-FileHash -LiteralPath $Path -Algorithm MD5).Hash } else { $null }
    [pscustomobject]@{
        Path = $Path
        SHA256 = $sha256
        MD5 = $md5
        HashAlgorithm = $HashAlgorithm
        SignatureStatus = [string]$signature.Status
        Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        SignerThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
        VerifiedAt = (Get-Date).ToString('o')
    }
}
function Export-WAReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data,[Parameter(Mandatory)][string]$Directory,[string]$Prefix='audit')
    $Directory=Initialize-WAReportDirectory -Directory $Directory
    $safe = $Prefix -replace '[^a-zA-Z0-9_-]','-'
    $file = Join-Path $Directory ('{0}-{1}-{2}.json' -f $safe,(Get-Date -Format 'yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    $payload = [pscustomobject]@{
        Tool = 'WinAudit'
        CreatedAt = (Get-Date).ToString('o')
        Host = $env:COMPUTERNAME
        Data = @($Data)
    }
    [void](New-WAEvidenceFile -Path $file -Content ($payload | ConvertTo-Json -Depth 12))
    return $file
}


function Get-WATreeFileEvidence {
    [CmdletBinding()]
    param([string]$Path,[hashtable]$Cache=@{})
    $evidence = [pscustomobject]@{
        MD5=$null; SHA256=$null; SignatureStatus='NoDisponible'; Signer=$null
        FileEvidenceAt=(Get-Date).ToString('o'); MD5Error=$null; SHA256Error=$null; SignatureError=$null
    }
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $evidence.MD5Error='Ruta de ejecutable no disponible.'
        $evidence.SignatureError=$evidence.MD5Error
        $evidence.SHA256Error=$evidence.MD5Error
        return $evidence
    }
    try {
        $Path=Resolve-WALocalEvidencePath -Path $Path
        $before = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($before.PSIsContainer) { throw 'La ruta no corresponde a un archivo.' }
        $length = $before.Length
        $writeTicks = $before.LastWriteTimeUtc.Ticks
        $cacheKey = '{0}|{1}|{2}' -f $before.FullName,$length,$writeTicks
        if ($Cache.ContainsKey($cacheKey)) { return $Cache[$cacheKey] }
    } catch {
        $evidence.MD5Error=$_.Exception.Message
        $evidence.SHA256Error=$_.Exception.Message
        $evidence.SignatureError=$_.Exception.Message
        return $evidence
    }
    try { $evidence.MD5=(Get-FileHash -LiteralPath $Path -Algorithm MD5 -ErrorAction Stop).Hash }
    catch { $evidence.MD5Error=$_.Exception.Message }
    try { $evidence.SHA256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { $evidence.SHA256Error=$_.Exception.Message }
    try {
        $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $evidence.SignatureStatus=[string]$signature.Status
        if ($signature.SignerCertificate) { $evidence.Signer=$signature.SignerCertificate.Subject }
    } catch { $evidence.SignatureError=$_.Exception.Message }
    try {
        $after=Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($after.Length -ne $length -or $after.LastWriteTimeUtc.Ticks -ne $writeTicks) { throw 'El archivo cambio durante la lectura de evidencia.' }
    } catch {
        $evidence.MD5=$null; $evidence.SHA256=$null; $evidence.SignatureStatus='NoDisponible'; $evidence.Signer=$null
        $evidence.MD5Error=$_.Exception.Message; $evidence.SHA256Error=$_.Exception.Message; $evidence.SignatureError=$_.Exception.Message
    }
    # Reutiliza solo resultados completos; los errores se pueden reintentar con otra instancia.
    if (-not $evidence.MD5Error -and -not $evidence.SHA256Error -and -not $evidence.SignatureError) { $Cache[$cacheKey]=$evidence }
    return $evidence
}

function Update-WAObservedProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Nodes,[int]$TargetPid=0,[string]$ProcessName,[hashtable]$FileEvidenceCache=@{})
    $at = Get-Date
    $current = @(Get-WAProcesses)
    $byPid = @{}
    foreach ($proc in $current) { $byPid[[string]$proc.ProcessId] = $proc }
    $selected = @{}
    foreach ($proc in $current) {
        if (-not $proc.CreationDate) { continue }
        $key = '{0}|{1}' -f $proc.ProcessId,([datetime]$proc.CreationDate).ToString('o')
        $root = ($TargetPid -gt 0 -and $proc.ProcessId -eq $TargetPid) -or ($ProcessName -and $proc.Name -ieq $ProcessName)
        if ($root -or $Nodes.ContainsKey($key)) { $selected[$key] = $proc }
    }
    do {
        $added = $false
        foreach ($proc in $current) {
            if (-not $proc.CreationDate) { continue }
            $key = '{0}|{1}' -f $proc.ProcessId,([datetime]$proc.CreationDate).ToString('o')
            if ($selected.ContainsKey($key)) { continue }
            $parent = $byPid[[string]$proc.ParentProcessId]
            if ($null -eq $parent -or -not $parent.CreationDate -or [datetime]$parent.CreationDate -gt [datetime]$proc.CreationDate) { continue }
            $parentKey = '{0}|{1}' -f $parent.ProcessId,([datetime]$parent.CreationDate).ToString('o')
            if ($selected.ContainsKey($parentKey)) { $selected[$key]=$proc; $added=$true }
        }
    } while ($added)
    foreach ($key in @($selected.Keys)) {
        $proc = $selected[$key]
        $parent = $byPid[[string]$proc.ParentProcessId]
        $parentKey = $null
        $parentName = $null
        if ($null -ne $parent -and $parent.CreationDate -and [datetime]$parent.CreationDate -le [datetime]$proc.CreationDate -and $parent.ProcessId -ne $proc.ProcessId) {
            $parentName = $parent.Name
            $candidate = '{0}|{1}' -f $parent.ProcessId,([datetime]$parent.CreationDate).ToString('o')
            if ($selected.ContainsKey($candidate) -or $Nodes.ContainsKey($candidate)) { $parentKey=$candidate }
        }
        if ($Nodes.ContainsKey($key)) { $Nodes[$key].LastSeen=$at.ToString('o'); continue }
        $root = ($TargetPid -gt 0 -and $proc.ProcessId -eq $TargetPid) -or ($ProcessName -and $proc.Name -ieq $ProcessName)
        $fileEvidence=Get-WATreeFileEvidence -Path $proc.ExecutablePath -Cache $FileEvidenceCache
        $Nodes[$key] = [pscustomobject]@{
            Key=$key; Name=$proc.Name; ProcessId=$proc.ProcessId; ParentProcessId=$proc.ParentProcessId
            CreationDate=([datetime]$proc.CreationDate).ToString('o'); ParentKey=$parentKey; ParentName=$parentName
            MD5=$fileEvidence.MD5; SHA256=$fileEvidence.SHA256; SHA256Error=$fileEvidence.SHA256Error; SignatureStatus=$fileEvidence.SignatureStatus; Signer=$fileEvidence.Signer
            FileEvidenceAt=$fileEvidence.FileEvidenceAt; MD5Error=$fileEvidence.MD5Error; SignatureError=$fileEvidence.SignatureError
            IsRoot=[bool]$root; ExecutablePath=$proc.ExecutablePath; FirstSeen=$at.ToString('o'); LastSeen=$at.ToString('o')
            Evidence='Win32_Process: PID, PPID y fecha de creacion en la misma instantanea'
        }
    }
}

function ConvertTo-WAProcessLink {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Event)
    $xml = ConvertFrom-WAEventXml -Text $Event.EventXml
    $data = @{}
    foreach ($node in $xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')) { $data[$node.GetAttribute('Name')]=$node.InnerText }
    if ($Event.LogName -eq 'Microsoft-Windows-Sysmon/Operational' -and $Event.Id -eq 1) {
        [pscustomobject]@{Kind='Creacion (Sysmon 1)'; FromPid=$data['ParentProcessId']; ToPid=$data['ProcessId']; FromName=$data['ParentImage']; ToName=$data['Image']; FromGuid=$data['ParentProcessGuid']; ToGuid=$data['ProcessGuid']; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    } elseif ($Event.LogName -eq 'Security' -and $Event.Id -eq 4688) {
        [pscustomobject]@{Kind='Creacion (Security 4688; PID puede ser hexadecimal)'; FromPid=$data['ProcessId']; ToPid=$data['NewProcessId']; FromName=$data['ParentProcessName']; ToName=$data['NewProcessName']; FromGuid=$null; ToGuid=$null; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    } elseif ($Event.LogName -eq 'Microsoft-Windows-Sysmon/Operational' -and $Event.Id -in @(8,10)) {
        [pscustomobject]@{Kind=('Vinculo (Sysmon {0}; no implica parentesco)' -f $Event.Id); FromPid=$data['SourceProcessId']; ToPid=$data['TargetProcessId']; FromName=$data['SourceImage']; ToName=$data['TargetImage']; FromGuid=$data['SourceProcessGUID']; ToGuid=$data['TargetProcessGUID']; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    }
}

function Export-WACaptureTree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Nodes,[Parameter(Mandatory)]$Metadata,[Parameter(Mandatory)][string]$Path,[object[]]$Links=@(),[switch]$ShowOnScreen)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    function Safe-Label($Value) { (ConvertTo-WADisplayText ([string]$Value)) -replace '\|','/' }
    function Add-TreeNode($Node,[string]$Indent,[int]$Depth) {
        if ($Depth -gt 64 -or -not $visited.Add($Node.Key)) { $lines.Add($Indent + '+-- [ciclo o limite de profundidad]'); return }
        $md5 = if ($Node.PSObject.Properties['MD5'] -and $Node.MD5) { $Node.MD5 } else { 'NoDisponible' }
        $signature = if ($Node.PSObject.Properties['SignatureStatus'] -and $Node.SignatureStatus) { Safe-Label $Node.SignatureStatus } else { 'NoDisponible' }
        $signer = if ($Node.PSObject.Properties['Signer'] -and $Node.Signer) { Safe-Label $Node.Signer } else { 'NoDisponible' }
        $lines.Add(('{0}+-- {1} PID {2} | MD5: {3} | Signature: {4} | Firmante: {5} | creado {6}' -f $Indent,(Safe-Label $Node.Name),$Node.ProcessId,$md5,$signature,$signer,$Node.CreationDate))
        if ($Node.PSObject.Properties['VirusTotal']) {
            $vt=$Node.VirusTotal
            $suffix=' | VT: ' + (Safe-Label $vt.State)
            if ($vt.State -eq 'Encontrado') {
                $suffix += ' | maliciosos: {0} | sospechosos: {1} | evaluados: {2} | analisis UTC: {3}' -f $vt.Malicious,$vt.Suspicious,$vt.EnginesWithVerdict,$vt.LastAnalysisUtc
            }
            $lines[$lines.Count-1] += $suffix
            if ($vt.PSObject.Properties['ReportUrl']) { $lines.Add($Indent + '    VT informe: ' + (Safe-Label $vt.ReportUrl)) }
        }
        foreach ($field in @('MD5Error','SignatureError')) {
            if ($Node.PSObject.Properties[$field] -and $Node.$field) { $lines.Add(('{0}    {1}: {2}' -f $Indent,$field,(Safe-Label $Node.$field))) }
        }
        if ($Node.PSObject.Properties['FileEvidenceAt'] -and $Node.FileEvidenceAt) { $lines.Add(('{0}    Archivo leido: {1}' -f $Indent,$Node.FileEvidenceAt)) }
        foreach ($child in @($Nodes.Values | Where-Object {$_.ParentKey -eq $Node.Key} | Sort-Object CreationDate,ProcessId)) { Add-TreeNode $child ($Indent + '    ') ($Depth+1) }
    }
    $lines.Add('WinAudit - Informe de monitoreo y relaciones de procesos')
    $lines.Add(('Estado: {0} | Eventos coincidentes: {1}' -f $Metadata.State,$Metadata.MatchedCount))
    $lines.Add(('Intervalo solicitado: {0} -> {1} | Zona: {2}' -f $Metadata.RequestedStart,$Metadata.RequestedEnd,$Metadata.TimeZone))
    $lines.Add('')
    $lines.Add('ARBOL OBSERVADO (instantaneas; identidad = PID + fecha de creacion)')
    foreach ($root in @($Nodes.Values | Where-Object {$_.IsRoot} | Sort-Object CreationDate,ProcessId)) {
        $lines.Add(('Proceso seleccionado / {0}; padre observado: {1} PID {2}' -f (Safe-Label $root.Name),$(if ($root.ParentName) {Safe-Label $root.ParentName} else {'no observado'}),$root.ParentProcessId))
        Add-TreeNode $root '' 0
    }
    if ($Nodes.Count -eq 0) { $lines.Add('No se observaron procesos con el selector durante las instantaneas.') }
    foreach ($node in @($Nodes.Values | Where-Object {-not $visited.Contains($_.Key)})) {
        $lines.Add('Relacion incompleta; no se reconstruye un padre ausente:')
        Add-TreeNode $node '' 0
    }
    $lines.Add('')
    $lines.Add('RELACIONES REGISTRADAS EN EVENTOS (evidencia separada del arbol)')
    if (@($Links).Count -eq 0) { $lines.Add('Sin relaciones de creacion o acceso compatibles en los eventos recuperados.') }
    foreach ($link in $Links) {
        $lines.Add(('{0} | {1} | {2} PID {3} -> {4} PID {5} | registro {6}' -f $link.Time,$link.Kind,(Safe-Label $link.FromName),$link.FromPid,(Safe-Label $link.ToName),$link.ToPid,$link.RecordId))
        if ($link.FromGuid -or $link.ToGuid) { $lines.Add(('    GUID: {0} -> {1}' -f $link.FromGuid,$link.ToGuid)) }
    }
    $lines.Add('')
    $lines.Add('FUENTES DE EVENTOS (ultima consulta)')
    foreach ($source in $Metadata.Sources) { $lines.Add(('{0}: {1}; coincidencias {2}; {3}' -f $source.LogName,$source.State,$source.MatchedCount,(Safe-Label $source.Detail))) }
    foreach ($issue in $Metadata.SourceIssues) { $lines.Add(('Limitacion observada: {0}; {1}; {2}' -f $issue.LogName,$issue.State,(Safe-Label $issue.Detail))) }
    foreach ($issue in $Metadata.ProcessIssues) { $lines.Add(('Instantaneas de procesos: {0}' -f (Safe-Label $issue))) }
    $lines.Add('')
    $lines.Add('LIMITES: las instantaneas pueden perder procesos breves. No demuestra ausencia de actividad.')
    $lines.Add('Los hijos se enlazan solo con un padre observado y fecha de creacion compatible. Los PID se reutilizan.')
    $lines.Add('Los vinculos de eventos no implican parentesco ni actividad maliciosa. No se inventan otros procesos vinculados.')
    $lines.Add('MD5 y Signature describen el archivo accesible al observar la instancia, no la memoria ni su contenido historico.')
    $lines.Add('Signature conserva el estado Authenticode: Valid no garantiza que un proceso sea benigno; NotSigned indica ausencia de firma.')
    $lines.Add('Los hashes identifican archivos en disco al leerlos; MD5 no sirve para demostrar integridad frente a manipulacion intencional.')
    $Path=Resolve-WALocalEvidencePath -Path $Path -AllowMissing
    [IO.File]::WriteAllLines($Path,$lines.ToArray(),(New-Object Text.UTF8Encoding($true)))
    if ($ShowOnScreen) { foreach ($line in $lines) { Write-Host $line } }
    return $Path
}

function Get-WARemoteProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ComputerName,
        [pscredential]$Credential,
        [switch]$UseSSL,
        [ValidateRange(0,65535)][int]$Port=0,
        [ValidateSet('Kerberos','Negotiate')][string]$Authentication='Kerberos'
    )
    if ([Uri]::CheckHostName($ComputerName) -ne [UriHostNameType]::Dns -or $ComputerName -match '[/\\:\s]') {throw 'WinRM requiere un nombre DNS de equipo, por ejemplo pc001.ad.example.com.'}
    $query=@{ComputerName=$ComputerName;Authentication=$Authentication;ErrorAction='Stop';ScriptBlock={
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine
    }}
    if ($null -ne $Credential) {$query.Credential=$Credential}
    if ($UseSSL) {$query.UseSSL=$true}
    if ($Port -gt 0) {$query.Port=$Port}
    Invoke-Command @query
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
        [System.Collections.Generic.List[object]]$QueryStatus,
        [ValidateRange(1,100000)][int]$MaxEventsPerLog=10000
    )
    if ($TargetPid -eq 0 -and [string]::IsNullOrWhiteSpace($ProcessName)) { throw 'Indica un PID o nombre de ejecutable.' }
    if ($TargetPid -gt 0 -and $ProcessName) { throw 'Usa un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime) { throw 'El fin debe ser posterior al inicio.' }
    foreach ($log in $Logs) {
        $count = 0
        $state = 'Consultado'
        $detail = $null
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$StartTime; EndTime=$EndTime} -MaxEvents ($MaxEventsPerLog+1) -ErrorAction Stop)
            if ($events.Count -gt $MaxEventsPerLog) {
                $state='Limitado'; $detail='Se alcanzo MaxEventsPerLog; consulta parcial (eventos mas recientes).'
                $events=@($events | Select-Object -First $MaxEventsPerLog)
            }
            foreach ($evt in $events) {
                try {
                    $xml = ConvertFrom-WAEventXml -Text $evt.ToXml()
                    $evidenceMatches = New-Object System.Collections.Generic.List[string]
                    $execution = $xml.SelectSingleNode('/*[local-name()="Event"]/*[local-name()="System"]/*[local-name()="Execution"]')
                    if ($TargetPid -gt 0 -and $null -ne $execution -and $execution.GetAttribute('ProcessID') -eq [string]$TargetPid) {
                        [void]$evidenceMatches.Add('System.Execution.ProcessID (emisor)')
                    }
                    foreach ($node in $xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')) {
                        $field = $node.GetAttribute('Name')
                        $raw = $node.InnerText
                        if ($TargetPid -gt 0 -and $field -match '^(ProcessId|NewProcessId|ParentProcessId|CreatorProcessId|ClientProcessId|SourceProcessId|TargetProcessId)$') {
                            $parsed = -1L
                            if ($raw -match '^0x[0-9a-fA-F]+$') { $parsed = [Convert]::ToInt64($raw.Substring(2),16) }
                            elseif ($raw -match '^\d+$') { $parsed = [long]$raw }
                            if ($parsed -eq $TargetPid) { [void]$evidenceMatches.Add("EventData.$field") }
                        }
                        if ($ProcessName -and $field -match '^(Image|NewProcessName|ProcessName|ApplicationName|SourceImage|TargetImage|ParentImage|ParentProcessName)$') {
                            $leaf = ($raw.Trim('"') -split '[\\/]')[-1]
                            if ($leaf -ieq $ProcessName) { [void]$evidenceMatches.Add("EventData.$field (nombre)") }
                        }
                    }
                    if ($evidenceMatches.Count -gt 0) {
                        $count++
                        $message = [string]$evt.Message
                        $summary = ConvertTo-WADisplayText ($message -replace '\s+',' ')
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
        if ($state -in @('NoDisponible','Parcial','Limitado')) { Write-Warning (ConvertTo-WADisplayText ("{0}: {1}. {2}" -f $log,$state,$detail)) }
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
        [ValidateRange(1,100000)][int]$MaxEventsPerLog=10000,
        [hashtable]$VirusTotalContext,
        [string[]]$Logs = @('Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational')
    )
    if (($TargetPid -eq 0 -and -not $ProcessName) -or ($TargetPid -gt 0 -and $ProcessName)) { throw 'Indica un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime -or $EndTime -le (Get-Date)) { throw 'La captura necesita un fin futuro posterior al inicio.' }
    $Directory=Initialize-WAReportDirectory -Directory $Directory
    $runId = 'capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $journal = Join-Path $Directory ($runId + '.jsonl')
    $manifest = Join-Path $Directory ($runId + '.json')
    $treePath = Join-Path $Directory ($runId + '-tree.txt')
    $processPath = Join-Path $Directory ($runId + '-processes.json')
    $processNodes = @{}
    $fileEvidenceCache = @{}
    $links = New-Object 'System.Collections.Generic.List[object]'
    foreach ($output in @($journal,$manifest,$treePath,$processPath)) {[void](New-WAEvidenceFile -Path $output)}
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $statuses = New-Object 'System.Collections.Generic.List[object]'
    $metadata = [pscustomobject]@{
        Tool='WinAudit'; Mode='EventCapture'; Host=$env:COMPUTERNAME; VirusTotalEnabled=($null -ne $VirusTotalContext)
        TimeZone=[TimeZoneInfo]::Local.Id; RequestedStart=$StartTime.ToString('o'); RequestedEnd=$EndTime.ToString('o')
        TargetPid=$TargetPid; ProcessName=$ProcessName; State='Esperando'; MatchedCount=0
        StartedAt=(Get-Date).ToString('o'); UpdatedAt=$null; LastQueryEnd=$null; FinishedAt=$null
        EventFile=$journal; TreeReportFile=$treePath; ProcessEvidenceFile=$processPath; ObservedProcessCount=0; ProcessIssues=@(); Sources=@(); SourceIssues=@(); Limitations='Depende de logs habilitados y retencion. PID reutilizable; nombre no identifica instancia. Eventos tardios pueden faltar.'
    }
    $cursor = $StartTime
    try {
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
        Write-Host ("Captura local de {0} a {1}. Zona: {2}. Mantene esta terminal abierta; Ctrl+C cancela." -f $StartTime,$EndTime,$metadata.TimeZone)
        while ((Get-Date) -lt $StartTime) { Start-Sleep -Seconds 1 }
        $metadata.State = 'Capturando'
        while ($true) {
            try { Update-WAObservedProcesses -Nodes $processNodes -TargetPid $TargetPid -ProcessName $ProcessName -FileEvidenceCache $fileEvidenceCache }
            catch { $metadata.ProcessIssues = @(@($metadata.ProcessIssues) + @($_.Exception.Message) | Select-Object -Unique) }
            $metadata.ObservedProcessCount = $processNodes.Count
            ConvertTo-Json -InputObject @($processNodes.Values) -Depth 8 | Set-Content -LiteralPath $processPath -Encoding UTF8
            $now = Get-Date
            $upper = if ($now -lt $EndTime) { $now } else { $EndTime }
            $lower = $cursor.AddSeconds(-2)
            if ($lower -lt $StartTime) { $lower = $StartTime }
            if ($upper -gt $lower) {
                $statuses.Clear()
                $query = @{TargetPid=$TargetPid; ProcessName=$ProcessName; StartTime=$lower; EndTime=$upper; Logs=$Logs; QueryStatus=$statuses;MaxEventsPerLog=$MaxEventsPerLog}
                Get-WAEvents @query | ForEach-Object {
                    $key = '{0}|{1}|{2}' -f $_.LogName,$_.RecordId,$_.TimeCreated.ToString('o')
                    if ($seen.Add($key)) {
                        $_ | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8
                        $metadata.MatchedCount++
                        try { ConvertTo-WAProcessLink -Event $_ | ForEach-Object {$links.Add($_)} } catch { Write-Warning 'No se pudo interpretar un vinculo del evento.' }
                    }
                }
                $cursor = $upper
                $metadata.LastQueryEnd = $upper.ToString('o')
                $metadata.Sources = @($statuses.ToArray())
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial','Limitado')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
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
        Get-WAEvents -TargetPid $TargetPid -ProcessName $ProcessName -StartTime $StartTime -EndTime $EndTime -Logs $Logs -QueryStatus $statuses -MaxEventsPerLog $MaxEventsPerLog | ForEach-Object {
            $key = '{0}|{1}|{2}' -f $_.LogName,$_.RecordId,$_.TimeCreated.ToString('o')
            if ($seen.Add($key)) {
                $_ | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8
                $metadata.MatchedCount++
                try { ConvertTo-WAProcessLink -Event $_ | ForEach-Object {$links.Add($_)} } catch { Write-Warning 'No se pudo interpretar un vinculo del evento.' }
            }
        }
        $metadata.Sources = @($statuses.ToArray())
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial','Limitado')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
        $metadata.State = if ($metadata.SourceIssues.Count -gt 0 -or $metadata.ProcessIssues.Count -gt 0) { 'FinalizadaConLimitaciones' } else { 'Finalizada' }
        if ($null -ne $VirusTotalContext) {
            Write-Host 'Captura local terminada. Consultando reputacion opcional por hashes unicos; puede demorar por limites de la API.'
            Add-WAVirusTotalToProcesses -Nodes $processNodes -Context $VirusTotalContext
        }
    } finally {
        if ($metadata.State -in @('Esperando','Capturando')) { $metadata.State = 'Interrumpida' }
        $metadata.ObservedProcessCount = $processNodes.Count
        ConvertTo-Json -InputObject @($processNodes.Values) -Depth 8 | Set-Content -LiteralPath $processPath -Encoding UTF8
        [void](Export-WACaptureTree -Nodes $processNodes -Metadata $metadata -Path $treePath -Links $links.ToArray() -ShowOnScreen)
        $metadata.FinishedAt = (Get-Date).ToString('o')
        $metadata.UpdatedAt = $metadata.FinishedAt
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
        Write-Host "Estado: $($metadata.State). Eventos: $journal. Resumen: $manifest. Arbol: $treePath"
    }
    return $metadata
}

function ConvertTo-WALdapFilterValue {
    [CmdletBinding()]
    param([string]$Value,[switch]$AllowWildcard)
    $result=New-Object Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        switch ([int]$character) {
            0 {[void]$result.Append('\00')}
            40 {[void]$result.Append('\28')}
            41 {[void]$result.Append('\29')}
            92 {[void]$result.Append('\5c')}
            42 {if ($AllowWildcard) {[void]$result.Append('*')} else {[void]$result.Append('\2a')}}
            default {[void]$result.Append($character)}
        }
    }
    return $result.ToString()
}
function New-WALdapConnection {
    [CmdletBinding()]
    param([string]$Server,[int]$Port,[string]$Authentication,[pscredential]$Credential)
    $identifier=[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server,$Port,$true,$false)
    $networkCredential=if ($null -ne $Credential) {$Credential.GetNetworkCredential()} else {[Net.CredentialCache]::DefaultNetworkCredentials}
    return [System.DirectoryServices.Protocols.LdapConnection]::new($identifier,$networkCredential,[System.DirectoryServices.Protocols.AuthType]::$Authentication)
}
function Send-WALdapRequest {
    param($Connection,$Request)
    return $Connection.SendRequest($Request)
}
function Get-WALdapAttribute {
    param($Entry,[string]$Name)
    if ($Entry.Attributes.Contains($Name) -and $Entry.Attributes[$Name].Count -gt 0) { return [string]$Entry.Attributes[$Name][0] }
    return $null
}
function Get-WADirectoryComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Server,
        [ValidateSet('LDAPS','LDAP','RSAT')][string]$Protocol='LDAPS',
        [pscredential]$Credential,
        [string]$SearchBase,
        [ValidateNotNullOrEmpty()][string]$NameFilter='*',
        [switch]$EnabledOnly,
        [ValidateRange(0,65535)][int]$Port=0,
        [ValidateSet('Kerberos','Negotiate')][string]$Authentication='Kerberos',
        [ValidateRange(1,300)][int]$TimeoutSeconds=30,
        [ValidateRange(1,1000)][int]$PageSize=500,
        [ValidateRange(1,100000)][int]$MaxComputers=10000,
        [ValidateRange(1,10000)][int]$MaxPages=1000
    )
    if ([Uri]::CheckHostName($Server) -ne [UriHostNameType]::Dns -or $Server -match '[/\\:\s]') { throw 'Usa el nombre DNS del dominio o DC, por ejemplo dc01.ad.example.com; sin URL, IP ni puerto.' }
    $escaped=ConvertTo-WALdapFilterValue -Value $NameFilter -AllowWildcard
    $filter='(&(objectCategory=computer)(|(name={0})(dNSHostName={0}))' -f $escaped
    if ($EnabledOnly) {$filter+='(!(userAccountControl:1.2.840.113556.1.4.803:=2))'}
    $filter+=')'
    if ($Protocol -eq 'RSAT') {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'RSAT ActiveDirectory no esta disponible. Usa LDAPS/LDAP o instala la dependencia opcional.' }
        Import-Module ActiveDirectory -ErrorAction Stop
        $query=@{LDAPFilter=$filter;Server=$Server;Properties=@('OperatingSystem','LastLogonDate','DNSHostName','Enabled');ResultSetSize=$MaxComputers;ErrorAction='Stop'}
        if ($null -ne $Credential) {$query.Credential=$Credential}
        if ($SearchBase) {$query.SearchBase=$SearchBase}
        $rows=@(Get-ADComputer @query)
        $mayBeTruncated=$rows.Count -ge $MaxComputers
        if ($mayBeTruncated) {Write-Warning 'Se alcanzo el limite local. El inventario RSAT puede estar incompleto.'}
        $rows | Select-Object Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,DistinguishedName,@{Name='InventorySource';Expression={'RSAT'}},@{Name='QueryTruncated';Expression={$mayBeTruncated}}
        return
    }
    try {Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop}
    catch {throw 'No esta disponible System.DirectoryServices.Protocols en este runtime de Windows. No se instala ni descarga automaticamente.'}
    $actualPort=if ($Port -gt 0) {$Port} elseif ($Protocol -eq 'LDAPS') {636} else {389}
    $connection=$null
    $items=New-Object 'System.Collections.Generic.List[object]'
    $truncated=$false
    try {
        $connection=New-WALdapConnection -Server $Server -Port $actualPort -Authentication $Authentication -Credential $Credential
        $connection.Timeout=[TimeSpan]::FromSeconds($TimeoutSeconds)
        $connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.ReferralChasing=[System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.SessionOptions.SecureSocketLayer=($Protocol -eq 'LDAPS')
        if ($Protocol -eq 'LDAP') {
            $connection.SessionOptions.Signing=$true
            $connection.SessionOptions.Sealing=$true
        }
        # No VerifyServerCertificate personalizado: se conserva la validacion de Windows.
        $connection.Bind()
        $base=$SearchBase
        if ([string]::IsNullOrWhiteSpace($base)) {
            $rootRequest=[System.DirectoryServices.Protocols.SearchRequest]::new('', '(objectClass=*)',[System.DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('defaultNamingContext'))
            $rootResponse=Send-WALdapRequest -Connection $connection -Request $rootRequest
            if ($rootResponse.Entries.Count -ne 1) {throw 'WinAudit LDAP: RootDSE no devolvio una base de busqueda unica.'}
            $base=Get-WALdapAttribute -Entry $rootResponse.Entries[0] -Name 'defaultNamingContext'
            if ([string]::IsNullOrWhiteSpace($base)) {throw 'WinAudit LDAP: no se encontro defaultNamingContext. Indica SearchBase.'}
        }
        $attributes=[string[]]@('name','dNSHostName','operatingSystem','userAccountControl','lastLogonTimestamp')
        $request=[System.DirectoryServices.Protocols.SearchRequest]::new($base,$filter,[System.DirectoryServices.Protocols.SearchScope]::Subtree,$attributes)
        $request.TimeLimit=[TimeSpan]::FromSeconds($TimeoutSeconds)
        $page=[System.DirectoryServices.Protocols.PageResultRequestControl]::new($PageSize)
        $page.IsCritical=$true
        [void]$request.Controls.Add($page)
        $cookies=New-Object 'System.Collections.Generic.HashSet[string]'
        $pageCount=0
        do {
            $pageCount++
            if ($pageCount -gt $MaxPages) {throw 'WinAudit LDAP: se alcanzo MaxPages; consulta interrumpida.'}
            $response=Send-WALdapRequest -Connection $connection -Request $request
            foreach ($entry in $response.Entries) {
                if ($items.Count -ge $MaxComputers) {$truncated=$true;break}
                $uac=0L
                $hasUac=[long]::TryParse([string](Get-WALdapAttribute $entry 'userAccountControl'),[ref]$uac)
                $lastLogon=$null; $fileTime=0L
                if ([long]::TryParse([string](Get-WALdapAttribute $entry 'lastLogonTimestamp'),[ref]$fileTime) -and $fileTime -gt 0) {
                    try {$lastLogon=[datetime]::FromFileTimeUtc($fileTime)} catch {$lastLogon=$null}
                }
                $items.Add([pscustomobject]@{
                    Name=(Get-WALdapAttribute $entry 'name');DNSHostName=(Get-WALdapAttribute $entry 'dNSHostName')
                    OperatingSystem=(Get-WALdapAttribute $entry 'operatingSystem');Enabled=$(if ($hasUac) {($uac -band 2) -eq 0} else {$null})
                    LastLogonDate=$lastLogon;DistinguishedName=$entry.DistinguishedName
                    InventorySource=$Protocol;QueryTruncated=$false
                })
            }
            $pageResponses=@($response.Controls | Where-Object {$_.Type -eq '1.2.840.113556.1.4.319' -and $_.PSObject.Properties['Cookie']})
            if ($pageResponses.Count -ne 1) {throw 'WinAudit LDAP: el servidor no confirmo paginacion; no se presenta un inventario completo.'}
            $cookie=[byte[]]$pageResponses[0].Cookie
            if ($null -eq $cookie) {$cookie=[byte[]]@()}
            if ($cookie.Length -gt 0 -and $items.Count -ge $MaxComputers) {$truncated=$true}
            if ($truncated) {break}
            if ($cookie.Length -gt 0 -and -not $cookies.Add([Convert]::ToBase64String($cookie))) {throw 'WinAudit LDAP: el servidor repitio una pagina.'}
            $page.Cookie=$cookie
        } while ($cookie.Length -gt 0)
        if ($truncated) {
            Write-Warning 'Se alcanzo MaxComputers; el inventario LDAP esta incompleto.'
            foreach ($item in $items) {$item.QueryTruncated=$true}
        }
        return $items.ToArray()
    } catch {
        $exception=$_.Exception
        if ($exception.Message -like 'WinAudit LDAP:*') {throw $exception.Message}
        while ($exception.InnerException) {$exception=$exception.InnerException}
        $code=if ($exception.PSObject.Properties['ErrorCode']) {[int]$exception.ErrorCode} else {-1}
        $detail=switch ($code) {49 {'Credenciales rechazadas.'} 8 {'El servidor exige autenticacion mas fuerte.'} 81 {'Servidor inaccesible o fallo de TLS/certificado.'} default {'Revisa DNS, permisos, autenticacion, certificado y conectividad.'}}
        throw ('No se pudo consultar {0}. {1} No se aplico fallback ni se cambiaron protecciones.' -f $Protocol,$detail)
    } finally {if ($null -ne $connection) {$connection.Dispose()}}
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
