Set-StrictMode -Version Latest
function Get-WAEvents {
    <#
    .SYNOPSIS
      Correlates available event records with a PID and time window.
    .NOTES
      Event System/Execution ProcessID is the event emitter, not necessarily the subject.
      This function labels the matching field; PID reuse can cause false correlations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$TargetPid,
        [datetime]$StartTime=(Get-Date).AddHours(-24),
        [datetime]$EndTime=(Get-Date),
        [string[]]$Logs=@('Security','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational')
    )
    if ($EndTime -lt $StartTime) { throw 'Invalid time window.' }
    foreach ($log in $Logs) {
        try {
            $filter = @{LogName=$log; StartTime=$StartTime; EndTime=$EndTime}
            $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        } catch {
            Write-Verbose ("Unavailable or empty log {0}: {1}" -f $log,$_.Exception.Message)
            continue
        }
        foreach ($evt in $events) {
            $matches = New-Object System.Collections.Generic.List[string]
            try {
                [xml]$xml = $evt.ToXml()
                $emitter = $xml.Event.System.Execution.ProcessID
                if ($null -ne $emitter -and [string]$emitter -eq [string]$TargetPid) {
                    [void]$matches.Add('System.Execution.ProcessID (emitter)')
                }
                foreach ($node in @($xml.Event.EventData.Data)) {
                    if ($null -eq $node) { continue }
                    $field = [string]$node.Name
                    if ($field -notmatch '^(ProcessId|NewProcessId|ParentProcessId|CreatorProcessId|ClientProcessId|SourceProcessId|TargetProcessId)$') { continue }
                    $raw = [string]$node.'#text'
                    $parsed = 0L
                    if ($raw -match '^0x[0-9a-fA-F]+$') {
                        $parsed = [Convert]::ToInt64($raw.Substring(2),16)
                    } elseif ($raw -match '^\d+$') {
                        $parsed = [long]$raw
                    }
                    if ($parsed -eq $TargetPid) { [void]$matches.Add("EventData.$field") }
                }
            } catch { Write-Verbose ("Could not parse event {0}: {1}" -f $evt.RecordId,$_.Exception.Message) }
            if ($matches.Count -gt 0) {
                [pscustomobject]@{
                    TimeCreated=$evt.TimeCreated
                    LogName=$evt.LogName
                    Id=$evt.Id
                    RecordId=$evt.RecordId
                    MatchedField=($matches -join ', ')
                    Summary=if ($evt.Message) { ($evt.Message -replace '\s+',' ').Substring(0,[Math]::Min(160,($evt.Message -replace '\s+',' ').Length)) } else { '' }
                    Message=$evt.Message
                }
            }
        }
    }
}
Export-ModuleMember -Function Get-WAEvents
