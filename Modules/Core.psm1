Set-StrictMode -Version Latest
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

function Update-WAObservedProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Nodes,[int]$TargetPid=0,[string]$ProcessName)
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
        $Nodes[$key] = [pscustomobject]@{
            Key=$key; Name=$proc.Name; ProcessId=$proc.ProcessId; ParentProcessId=$proc.ParentProcessId
            CreationDate=([datetime]$proc.CreationDate).ToString('o'); ParentKey=$parentKey; ParentName=$parentName
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
        [pscustomobject]@{Kind='Creacion (Sysmon 1)'; FromPid=$data.ParentProcessId; ToPid=$data.ProcessId; FromName=$data.ParentImage; ToName=$data.Image; FromGuid=$data.ParentProcessGuid; ToGuid=$data.ProcessGuid; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    } elseif ($Event.LogName -eq 'Security' -and $Event.Id -eq 4688) {
        [pscustomobject]@{Kind='Creacion (Security 4688; PID puede ser hexadecimal)'; FromPid=$data.ProcessId; ToPid=$data.NewProcessId; FromName=$data.ParentProcessName; ToName=$data.NewProcessName; FromGuid=$null; ToGuid=$null; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    } elseif ($Event.LogName -eq 'Microsoft-Windows-Sysmon/Operational' -and $Event.Id -in @(8,10)) {
        [pscustomobject]@{Kind=('Vinculo (Sysmon {0}; no implica parentesco)' -f $Event.Id); FromPid=$data.SourceProcessId; ToPid=$data.TargetProcessId; FromName=$data.SourceImage; ToName=$data.TargetImage; FromGuid=$data.SourceProcessGUID; ToGuid=$data.TargetProcessGUID; Time=$Event.TimeCreated; RecordId=$Event.RecordId}
    }
}

function Export-WACaptureTree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Nodes,[Parameter(Mandatory)]$Metadata,[Parameter(Mandatory)][string]$Path,[object[]]$Links=@())
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    function Safe-Label($Value) { ([string]$Value) -replace '[\x00-\x1f\x7f]','?' }
    function Add-TreeNode($Node,[string]$Indent,[int]$Depth) {
        if ($Depth -gt 64 -or -not $visited.Add($Node.Key)) { $lines.Add($Indent + '+-- [ciclo o limite de profundidad]'); return }
        $lines.Add(('{0}+-- {1} PID {2} | creado {3}' -f $Indent,(Safe-Label $Node.Name),$Node.ProcessId,$Node.CreationDate))
        foreach ($child in @($Nodes.Values | Where-Object {$_.ParentKey -eq $Node.Key} | Sort-Object CreationDate,ProcessId)) { Add-TreeNode $child ($Indent + '    ') ($Depth+1) }
    }
    $lines.Add('WinAudit - Informe de monitoreo y relaciones de procesos')
    $lines.Add(('Estado: {0} | Eventos coincidentes: {1}' -f $Metadata.State,$Metadata.MatchedCount))
    $lines.Add(('Intervalo solicitado: {0} -> {1} | Zona: {2}' -f $Metadata.RequestedStart,$Metadata.RequestedEnd,$Metadata.TimeZone))
    $lines.Add('')
    $lines.Add('ARBOL OBSERVADO (instantaneas; identidad = PID + fecha de creacion)')
    foreach ($root in @($Nodes.Values | Where-Object {$_.IsRoot} | Sort-Object CreationDate,ProcessId)) {
        $lines.Add(('Proceso seleccionado / {0}; padre observado: {1} PID {2}' -f (Safe-Label $root.Name),(Safe-Label $root.ParentName),$root.ParentProcessId))
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
    $lines.Add('Los hashes identifican archivos en disco al leerlos; MD5 no sirve para demostrar integridad frente a manipulacion intencional.')
    [IO.File]::WriteAllLines($Path,$lines.ToArray(),(New-Object Text.UTF8Encoding($true)))
    return $Path
}
Export-ModuleMember -Function Get-WAProcesses,Get-WAFileEvidence,Export-WAReport,Update-WAObservedProcesses,ConvertTo-WAProcessLink,Export-WACaptureTree
