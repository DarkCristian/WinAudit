#requires -Version 5.1
[CmdletBinding()]
param([switch]$Check)
$root = Split-Path -Parent $PSScriptRoot
$entry = Get-Content -LiteralPath (Join-Path $root 'WinAudit.ps1') -Raw
$marker = 'function Show-Header {'
$index = $entry.IndexOf($marker, [StringComparison]::Ordinal)
if ($index -lt 0) { throw 'No se encontro el comienzo de la interfaz.' }
$prefix = $entry.Substring(0,$index) -split '\r?\n' | Where-Object { $_ -notmatch '^Import-Module ' }
$parts = New-Object 'System.Collections.Generic.List[string]'
$parts.Add(($prefix -join "`n").TrimEnd())
foreach ($name in @('Core','Events','Directory')) {
    $lines = Get-Content -LiteralPath (Join-Path $root "Modules/$name.psm1")
    $body = $lines | Where-Object { $_ -notmatch '^(Export-ModuleMember|Set-StrictMode) ' }
    $parts.Add(($body -join "`n").TrimEnd())
}
$parts.Add($entry.Substring($index).TrimEnd())
$content = ($parts -join "`n`n") + "`n"
$output = Join-Path $root 'dist/WinAudit-Standalone.ps1'
if ($Check) {
    $actual = [IO.File]::ReadAllText($output).Replace("`r`n","`n")
    if ($actual -cne $content) { throw 'El standalone no coincide con los modulos. Ejecuta tools/Build-Standalone.ps1.' }
} else {
    [void](New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force)
    [IO.File]::WriteAllText($output,$content,(New-Object Text.UTF8Encoding($true)))
}
