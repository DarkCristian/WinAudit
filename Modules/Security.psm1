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
Export-ModuleMember -Function Assert-WASupportedRuntime,ConvertTo-WADisplayText,ConvertFrom-WAEventXml,Resolve-WALocalEvidencePath,Initialize-WAReportDirectory,New-WAEvidenceFile
