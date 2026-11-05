#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Modules/Directory.psm1') -Force
Import-Module (Join-Path $root 'Modules/Core.psm1') -Force
Add-Type -AssemblyName System.DirectoryServices.Protocols
$directory=Get-Module Directory
$core=Get-Module Core
function Assert-Directory($Condition,$Message) {if (-not $Condition) {throw $Message}}
& $directory {
    $script:Mode='normal';$script:Pages=0;$script:Roots=0;$script:FactoryCalls=0
    function script:New-WALdapConnection {
        param($Server,$Port,$Authentication,$Credential)
        $script:FactoryCalls++
        $script:Args=@{Server=$Server;Port=$Port;Authentication=$Authentication;Credential=$Credential}
        $connection=[pscustomobject]@{
            Timeout=[TimeSpan]::Zero;Bound=0;Disposed=$false;FailBind=($script:Mode -eq 'bindError')
            SessionOptions=[pscustomobject]@{ProtocolVersion=0;ReferralChasing='All';SecureSocketLayer=$false;Signing=$false;Sealing=$false;VerifyServerCertificate=$null}
        }
        $connection | Add-Member -MemberType ScriptMethod -Name Bind -Value {$this.Bound++;if ($this.FailBind) {throw 'Mock remote error containing NOT_A_REAL_PASSWORD'}}
        $connection | Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.Disposed=$true}
        $script:LastConnection=$connection
        return $connection
    }
    function script:Send-WALdapRequest {
        param($Connection,$Request)
        if ($Request.Scope -eq [System.DirectoryServices.Protocols.SearchScope]::Base) {
            $script:Roots++
            $attrs=@{}
            if ($script:Mode -ne 'noRootBase') {$attrs.defaultNamingContext=[string[]]@('DC=ad,DC=example,DC=com')}
            return [pscustomobject]@{Entries=@([pscustomobject]@{Attributes=$attrs});Controls=@()}
        }
        $script:Pages++
        $script:Filter=$Request.Filter;$script:SearchBase=$Request.DistinguishedName
        $page=@($Request.Controls | Where-Object {$_ -is [System.DirectoryServices.Protocols.PageResultRequestControl]})[0]
        if ($page.PageSize -ne 1 -or -not $page.IsCritical) {throw 'Paginacion no solicitada correctamente'}
        if ($script:Pages -eq 2 -and $page.Cookie.Length -eq 0) {throw 'No reutilizo la cookie'}
        $n=$script:Pages
        $cookie=[byte[]]@()
        if ($n -eq 1 -or $script:Mode -eq 'repeatCookie') {$cookie=[byte[]]@(1)}
        $controls=@([pscustomobject]@{Type='1.2.840.113556.1.4.319';Cookie=$cookie})
        if ($script:Mode -eq 'noPaging') {$controls=@()}
        $uac=if ($n -eq 1) {'4096'} else {'4098'}
        $attrs=@{name=[string[]]@('PC-00'+$n);dNSHostName=[string[]]@('pc00'+$n+'.ad.example.com');operatingSystem=[string[]]@('Windows Example');userAccountControl=[string[]]@($uac);lastLogonTimestamp=[string[]]@('0')}
        [pscustomobject]@{Entries=@([pscustomobject]@{Attributes=$attrs;DistinguishedName=('CN=PC-00'+$n+',DC=ad,DC=example,DC=com')});Controls=$controls}
    }
    function script:Reset-Fixture {param($Mode='normal') $script:Mode=$Mode;$script:Pages=0;$script:Roots=0}
}
$rows=@(Get-WADirectoryComputers -Server dc01.ad.example.com -PageSize 1)
Assert-Directory ($rows.Count -eq 2 -and $rows[0].Enabled -and -not $rows[1].Enabled -and $null -eq $rows[0].LastLogonDate) 'Debe paginar e interpretar UAC y fecha ausente.'
$c=& $directory {$script:LastConnection}
Assert-Directory ($c.Bound -eq 1 -and $c.Disposed -and $c.SessionOptions.SecureSocketLayer -and $c.SessionOptions.ProtocolVersion -eq 3 -and [string]$c.SessionOptions.ReferralChasing -eq 'None') 'LDAPS debe validar transporte y liberar la conexion.'
Assert-Directory ($null -eq $c.SessionOptions.VerifyServerCertificate -and (& $directory {$script:Args.Port}) -eq 636 -and (& $directory {$script:Args.Authentication}) -eq 'Kerberos') 'No debe omitir certificados ni usar autenticacion debil.'
& $directory {Reset-Fixture}
$credential=New-Object pscredential('EXAMPLE\audit.user',(ConvertTo-SecureString 'NOT_A_REAL_PASSWORD' -AsPlainText -Force))
[void]@(Get-WADirectoryComputers -Server dc01.ad.example.com -Protocol LDAP -Credential $credential -PageSize 1 -NameFilter 'PC-*)(name=*)' -SearchBase 'OU=Workstations,DC=ad,DC=example,DC=com' -EnabledOnly)
$c=& $directory {$script:LastConnection}
Assert-Directory ($c.SessionOptions.Signing -and $c.SessionOptions.Sealing -and -not $c.SessionOptions.SecureSocketLayer -and (& $directory {$script:Args.Port}) -eq 389) 'LDAP debe exigir firma y cifrado SASL.'
$filter=& $directory {$script:Filter}
Assert-Directory ($filter.Contains('PC-*\29\28name=*\29') -and $filter.Contains('userAccountControl:1.2.840.113556.1.4.803:=2') -and (& $directory {$script:Roots}) -eq 0) 'Debe escapar filtros y respetar SearchBase sin RootDSE.'
Assert-Directory ((& $directory {$script:Args.Credential.UserName}) -eq 'EXAMPLE\audit.user') 'Debe aceptar credenciales explicitas.'
& $directory {Reset-Fixture}
$limited=@(Get-WADirectoryComputers -Server dc01.ad.example.com -PageSize 1 -MaxComputers 1 -WarningAction SilentlyContinue)
Assert-Directory ($limited.Count -eq 1 -and $limited[0].QueryTruncated) 'Debe advertir y marcar resultados truncados.'
foreach ($mode in @('noRootBase','noPaging','repeatCookie','bindError')) {
    & $directory {param($Mode) Reset-Fixture $Mode} $mode
    $threw=$false
    try {[void]@(Get-WADirectoryComputers -Server dc01.ad.example.com -PageSize 1)} catch {
        $threw=$true
        Assert-Directory ($_.Exception.Message -notlike '*NOT_A_REAL_PASSWORD*') 'No debe divulgar mensajes remotos de autenticacion.'
    }
    Assert-Directory ($threw -and (& $directory {$script:LastConnection.Disposed})) ('Debe fallar y liberar conexion: '+$mode)
}
$before=& $directory {$script:FactoryCalls}
foreach ($bad in @('ldap://dc01.ad.example.com','192.0.2.10','dc01.ad.example.com:636','dc01.ad.example.com/evil')) {
    $threw=$false
    try {[void]@(Get-WADirectoryComputers -Server $bad)} catch {$threw=$true}
    Assert-Directory $threw 'Debe rechazar destinos que no sean DNS.'
}
Assert-Directory ((& $directory {$script:FactoryCalls}) -eq $before) 'No debe intentar red para destinos invalidos.'
& $directory {
    function script:Get-Module {param([switch]$ListAvailable,$Name) [pscustomobject]@{Name='ActiveDirectory'}}
    function script:Import-Module {[CmdletBinding()] param($Name)}
    function script:Get-ADComputer {
        [CmdletBinding()] param($LDAPFilter,$Server,$Properties,$ResultSetSize,$SearchBase,$Credential)
        $script:RsatFilter=$LDAPFilter
        [pscustomobject]@{Name='PC-001';DNSHostName='pc001.ad.example.com';OperatingSystem='Windows Example';Enabled=$true;LastLogonDate=$null;DistinguishedName='CN=PC-001,DC=ad,DC=example,DC=com'}
    }
}
$rsat=@(Get-WADirectoryComputers -Server dc01.ad.example.com -Protocol RSAT -NameFilter 'PC-*')
Assert-Directory ($rsat.Count -eq 1 -and $rsat[0].InventorySource -eq 'RSAT' -and (& $directory {$script:RsatFilter}).Contains('(name=PC-*)')) 'Debe conservar RSAT como alternativa.'
& $core {
    function script:Invoke-Command {
        [CmdletBinding()] param($ComputerName,$Credential,$UseSSL,$Port,$Authentication,$ScriptBlock)
        $script:RemoteArgs=$PSBoundParameters
        [pscustomobject]@{Name='example.exe';ProcessId=1234;ParentProcessId=1;ExecutablePath='C:\Example\example.exe';CommandLine='example.exe';CreationDate=(Get-Date)}
    }
}
$remote=@(Get-WARemoteProcesses -ComputerName $rows[0].DNSHostName -Credential $credential -UseSSL -Port 5986)
Assert-Directory ($remote.Count -eq 1 -and (& $core {$script:RemoteArgs.ComputerName}) -eq $rows[0].DNSHostName -and (& $core {$script:RemoteArgs.Authentication}) -eq 'Kerberos' -and (& $core {$script:RemoteArgs.UseSSL})) 'Debe consultar un equipo descubierto mediante WinRM, con permisos independientes.'
Assert-Directory (-not (& $core {$script:RemoteArgs.ContainsKey('SessionOption')})) 'No debe omitir validacion TLS ni cambiar TrustedHosts.'
Write-Host 'PASS Directory: LDAP/LDAPS simulados, paginacion, filtros, errores, RSAT y WinRM.'
