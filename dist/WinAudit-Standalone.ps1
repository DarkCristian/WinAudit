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
    [switch]$Monitor,
    [switch]$FullScan,
    [string]$ComputerName,
    [Alias('Start')][object]$StartTime,
    [Alias('End')][object]$EndTime,
    [ValidateRange(1,300)][int]$PollSeconds = 5,
    [string]$ReportDirectory = (Join-Path $env:USERPROFILE 'WinAudit-Reports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = $PSScriptRoot


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
    if (-not (Test-Path -LiteralPath $Directory)) { [void](New-Item -ItemType Directory -Path $Directory -Force) }
    $safe = $Prefix -replace '[^a-zA-Z0-9_-]','-'
    $file = Join-Path $Directory ('{0}-{1}-{2}.json' -f $safe,(Get-Date -Format 'yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    $payload = [pscustomobject]@{
        Tool = 'WinAudit'
        CreatedAt = (Get-Date).ToString('o')
        Host = $env:COMPUTERNAME
        Data = @($Data)
    }
    $payload | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $file -Encoding UTF8
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
    [xml]$xml = $Event.EventXml
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
    function Safe-Label($Value) { (([string]$Value) -replace '[\x00-\x1f\x7f]','?') -replace '\|','/' }
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
    [IO.File]::WriteAllLines($Path,$lines.ToArray(),(New-Object Text.UTF8Encoding($true)))
    if ($ShowOnScreen) { foreach ($line in $lines) { Write-Host $line } }
    return $Path
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
        [System.Collections.Generic.List[object]]$QueryStatus
    )
    if ($TargetPid -eq 0 -and [string]::IsNullOrWhiteSpace($ProcessName)) { throw 'Indica un PID o nombre de ejecutable.' }
    if ($TargetPid -gt 0 -and $ProcessName) { throw 'Usa un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime) { throw 'El fin debe ser posterior al inicio.' }
    foreach ($log in $Logs) {
        $count = 0
        $state = 'Consultado'
        $detail = $null
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$StartTime; EndTime=$EndTime} -ErrorAction Stop)
            foreach ($evt in $events) {
                try {
                    [xml]$xml = $evt.ToXml()
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
                        $summary = $message -replace '\s+',' '
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
        if ($state -eq 'NoDisponible' -or $state -eq 'Parcial') { Write-Warning ("{0}: {1}. {2}" -f $log,$state,$detail) }
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
        [hashtable]$VirusTotalContext,
        [string[]]$Logs = @('Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational')
    )
    if (($TargetPid -eq 0 -and -not $ProcessName) -or ($TargetPid -gt 0 -and $ProcessName)) { throw 'Indica un solo selector: PID o nombre.' }
    if ($EndTime -le $StartTime -or $EndTime -le (Get-Date)) { throw 'La captura necesita un fin futuro posterior al inicio.' }
    [void](New-Item -ItemType Directory -Path $Directory -Force)
    $runId = 'capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $journal = Join-Path $Directory ($runId + '.jsonl')
    $manifest = Join-Path $Directory ($runId + '.json')
    $treePath = Join-Path $Directory ($runId + '-tree.txt')
    $processPath = Join-Path $Directory ($runId + '-processes.json')
    $processNodes = @{}
    $fileEvidenceCache = @{}
    $links = New-Object 'System.Collections.Generic.List[object]'
    [IO.File]::WriteAllText($journal, '', (New-Object Text.UTF8Encoding($false)))
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
                $query = @{TargetPid=$TargetPid; ProcessName=$ProcessName; StartTime=$lower; EndTime=$upper; Logs=$Logs; QueryStatus=$statuses}
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
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
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
        Get-WAEvents -TargetPid $TargetPid -ProcessName $ProcessName -StartTime $StartTime -EndTime $EndTime -Logs $Logs -QueryStatus $statuses | ForEach-Object {
            $key = '{0}|{1}|{2}' -f $_.LogName,$_.RecordId,$_.TimeCreated.ToString('o')
            if ($seen.Add($key)) {
                $_ | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8
                $metadata.MatchedCount++
                try { ConvertTo-WAProcessLink -Event $_ | ForEach-Object {$links.Add($_)} } catch { Write-Warning 'No se pudo interpretar un vinculo del evento.' }
            }
        }
        $metadata.Sources = @($statuses.ToArray())
                $metadata.SourceIssues = @(@($metadata.SourceIssues) + @($statuses | Where-Object {$_.State -in @('NoDisponible','Parcial')} | Select-Object LogName,State,Detail) | Sort-Object LogName,State,Detail -Unique)
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
    $Data | Format-Table -AutoSize | Out-Host
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
        [void](Start-WAEventCapture -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -Directory $ReportDirectory -PollSeconds $PollSeconds -VirusTotalContext $(if ($script:vtAutomatic) {$script:vtContext} else {$null}))
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
    $events = @(Get-WAEvents -TargetPid $TargetPid -ProcessName $Name -StartTime $From -EndTime $Until -QueryStatus $status)
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
    $hostName = Read-Host 'FQDN del equipo (ej.: pc001.ad.example.com)'
    if ([string]::IsNullOrWhiteSpace($hostName)) { throw 'El nombre del equipo es obligatorio.' }
    $credential = Get-Credential -Message 'Credenciales autorizadas para el equipo remoto'
    $result = Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    } -ErrorAction Stop
    Show-Result $result
    Save-Report $result 'remote-processes'
}
function Invoke-DirectoryInventory {
    $server = Read-Host 'Dominio o DC (ej.: dc01.ad.example.com)'
    $base = Read-Host 'DN de OU opcional (vacio = contexto predeterminado)'
    $credential = Get-Credential -Message 'Credenciales autorizadas de lectura del directorio'
    $query = @{Server=$server; Credential=$credential}
    if (-not [string]::IsNullOrWhiteSpace($base)) { $query.SearchBase=$base }
    $items = @(Get-WADirectoryComputers @query)
    Show-Result ($items | Select-Object -First 100 Name,DNSHostName,OperatingSystem,Enabled)
    Save-Report $items 'ad-inventory'
}
function Invoke-FileEvidenceMenu {
    $path = (Read-Host 'Ruta del archivo a verificar').Trim('"')
    $option = Read-Host 'Hash: [1] SHA-256 [2] MD5 [3] Ambos'
    $algorithm = switch ($option) { '1' {'SHA256'} '2' {'MD5'} '3' {'Both'} default {throw 'Opcion invalida.'} }
    $evidence = Get-WAFileEvidence -Path $path -HashAlgorithm $algorithm
    Add-OptionalReputation -Evidence $evidence
    $evidence | Format-List | Out-Host
    Save-Report $evidence 'file-evidence'
}
function Add-OptionalReputation {
    param([Parameter(Mandatory)]$Evidence)
    if (-not $script:vtAutomatic -or $null -eq $script:vtContext) { return }
    try {
        $sha=(Get-FileHash -LiteralPath $Evidence.Path -Algorithm SHA256 -ErrorAction Stop).Hash
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
                $report | Format-List | Out-Host
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
$from = if ($null -eq $StartTime) { if ($Monitor) {Get-Date} else {(Get-Date).AddHours(-24)} } else { ConvertTo-WADateTime $StartTime }
$until = if ($null -eq $EndTime) { Get-Date } else { ConvertTo-WADateTime $EndTime }
if ($until -le $from) { throw 'El fin debe ser posterior al inicio.' }
if ($FilePath) {
    if ($FindProcess -or $PIDToAudit -gt 0 -or $Monitor -or $ComputerName -or $FullScan -or $hasWindow) { throw '-FilePath solo admite -HashAlgorithm y -ReportDirectory.' }
    $evidence = Get-WAFileEvidence -Path $FilePath -HashAlgorithm $HashAlgorithm
    Add-OptionalReputation -Evidence $evidence
    $evidence | Format-List | Out-Host
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
    $credential = Get-Credential -Message 'Credenciales autorizadas para el equipo remoto'
    $data = Invoke-Command -ComputerName $ComputerName -Credential $credential -ScriptBlock {
        Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
    }
    Save-Report $data 'remote-processes'
    return
}
while ($true) {
    Show-Header
    Write-Host '  [1] Mostrar procesos locales'
    Write-Host '  [2] Consultar eventos historicos por PID o nombre'
    Write-Host '  [3] Inventario remoto de procesos (WinRM)'
    Write-Host '  [4] Inventario de equipos de Active Directory'
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
    } catch { Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    Pause-Menu
}
