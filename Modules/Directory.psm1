Set-StrictMode -Version Latest
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
        [ValidateRange(1,100000)][int]$MaxComputers=10000
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
        do {
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
            $cookie=$pageResponses[0].Cookie
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
Export-ModuleMember -Function Get-WADirectoryComputers
