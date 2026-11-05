Set-StrictMode -Version Latest

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
            if (-not $node.ExecutablePath) { throw 'Sin ruta' }
            # Verifica que MD5 actual coincida con el capturado antes de asociar reputacion.
            $before=Get-FileHash -LiteralPath $node.ExecutablePath -Algorithm MD5 -ErrorAction Stop
            $sha=Get-FileHash -LiteralPath $node.ExecutablePath -Algorithm SHA256 -ErrorAction Stop
            $after=Get-FileHash -LiteralPath $node.ExecutablePath -Algorithm MD5 -ErrorAction Stop
            if (-not $node.MD5 -or $before.Hash -ine $node.MD5 -or $after.Hash -ine $node.MD5) { throw 'Archivo diferente' }
            $reputation=Get-WAVirusTotalReport -SHA256 $sha.Hash -Context $Context
        } catch {
            $reputation=[pscustomobject]@{State='EvidenciaNoDisponible'; Detail='No se pudo asociar el SHA-256 al archivo observado; no se envio la consulta.'}
        }
        $node | Add-Member -NotePropertyName VirusTotal -NotePropertyValue $reputation -Force
    }
}
Export-ModuleMember -Function New-WAVirusTotalContext,Get-WAVirusTotalReport,Add-WAVirusTotalToProcesses
