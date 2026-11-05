Set-StrictMode -Version Latest

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
    $links = New-Object 'System.Collections.Generic.List[object]'
    [IO.File]::WriteAllText($journal, '', (New-Object Text.UTF8Encoding($false)))
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $statuses = New-Object 'System.Collections.Generic.List[object]'
    $metadata = [pscustomobject]@{
        Tool='WinAudit'; Mode='EventCapture'; Host=$env:COMPUTERNAME
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
            try { Update-WAObservedProcesses -Nodes $processNodes -TargetPid $TargetPid -ProcessName $ProcessName }
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
    } finally {
        if ($metadata.State -in @('Esperando','Capturando')) { $metadata.State = 'Interrumpida' }
        $metadata.ObservedProcessCount = $processNodes.Count
        ConvertTo-Json -InputObject @($processNodes.Values) -Depth 8 | Set-Content -LiteralPath $processPath -Encoding UTF8
        [void](Export-WACaptureTree -Nodes $processNodes -Metadata $metadata -Path $treePath -Links $links.ToArray())
        $metadata.FinishedAt = (Get-Date).ToString('o')
        $metadata.UpdatedAt = $metadata.FinishedAt
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifest -Encoding UTF8
        Write-Host "Estado: $($metadata.State). Eventos: $journal. Resumen: $manifest. Arbol: $treePath"
    }
    return $metadata
}
Export-ModuleMember -Function ConvertTo-WADateTime,Get-WAEvents,Start-WAEventCapture
