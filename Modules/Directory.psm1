Set-StrictMode -Version Latest
function Get-WADirectoryComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Server,
        [Parameter(Mandatory)][pscredential]$Credential,
        [string]$SearchBase
    )
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory RSAT module not found. Install RSAT AD PowerShell tools.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $args = @{ Filter='*'; Server=$Server; Credential=$Credential; Properties=@('OperatingSystem','LastLogonDate','DNSHostName','Enabled') }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $args.SearchBase=$SearchBase }
    Get-ADComputer @args | Select-Object Name,DNSHostName,OperatingSystem,Enabled,LastLogonDate,DistinguishedName
}
Export-ModuleMember -Function Get-WADirectoryComputers
