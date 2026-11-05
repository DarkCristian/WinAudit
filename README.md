# WinAudit

```text
 __        ___         _             _ _ _
 \ \      / (_)_ __   / \  _   _  __| (_) |_
  \ \ /\ / /| | '_ \ / _ \| | | |/ _` | | __|
   \ V  V / | | | | / ___ \ |_| | (_| | | |_
    \_/\_/  |_|_| |_/_/   \_\__,_|\__,_|_|\__|

    WINDOWS SECURITY & FORENSIC AUDITOR
```

**WinAudit** is an open-source, native PowerShell utility for Windows process inventory, digital-signature verification, PID-oriented event investigation, authorized remote inventory, and Active Directory computer discovery.

> Initial development version. Not yet validated on a Windows test host. Do not rely on it as a complete forensic acquisition tool.

## Features

| Feature | Status |
| --- | --- |
| Interactive ASCII console with numbered menus | Implemented |
| Local process / PID / parent PID / command-line inventory | Implemented |
| Authenticode and SHA-256 evidence for selected running PID | Implemented |
| Event correlation by PID and time window | Initial implementation |
| Remote process inventory via WinRM | Implemented |
| AD computer discovery via RSAT | Implemented |
| Local JSON report export | Implemented |
| HTML reports, batch scanning, advanced risk scoring | Planned |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows.
- Some process metadata and event logs require elevated privileges.
- Remote mode requires configured WinRM and authorized access.
- AD mode requires the RSAT ActiveDirectory PowerShell module.
- Event coverage depends on enabled Windows logs and retention.

## Run

```powershell
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1
```

Other modes:

```powershell
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -PIDToAudit 1234 -StartTime '2026-01-01 10:00' -EndTime '2026-01-01 11:00'
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

## Menu

```text
  [1] List local processes
  [2] Investigate PID + Windows event logs
  [3] Remote process inventory (WinRM)
  [4] Active Directory computer inventory
  [5] Full local process inventory + JSON report
  [0] Exit
```

## Evidence caveats

Windows event records can identify the process **emitting** an event rather than the process being investigated. PIDs are reused and cannot uniquely identify a historical process. WinAudit labels the matching event field and does not automatically infer malicious behavior.

Reports may contain sensitive host data. They are written locally by default to `%USERPROFILE%\WinAudit-Reports`; never commit real audit reports.

## Documentation

- [Usage](docs/USAGE.md)
- [Security model](docs/SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
