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

## Install Active Directory prerequisites (optional)

**No compilation is required.** WinAudit runs as PowerShell scripts. RSAT is only required for the menu option that discovers computer objects using `Get-ADComputer`. Local audits and direct remote WinRM audits do **not** require RSAT.

First check whether the module is present:

```powershell
Get-Module -ListAvailable ActiveDirectory
.\Install-Prerequisites.ps1
```

If missing, open **Windows PowerShell as Administrator** and run:

```powershell
.\Install-Prerequisites.ps1 -Install
```

The installer uses Microsoft's built-in Windows mechanisms:

- **Windows 10/11 Pro, Enterprise or Education (supported releases):** `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
- **Windows Server:** `Install-WindowsFeature RSAT-AD-PowerShell`

On managed systems, installation may require Windows Update, an approved source, or administrator approval. RSAT may be unavailable on unsupported Windows editions. The script does not alter domain settings, enable WinRM, or install software from third-party websites.

After installation, verify:

```powershell
Import-Module ActiveDirectory
Get-Command Get-ADComputer
```

Then start WinAudit and choose **[4] Active Directory computer inventory**. Example input: `dc01.ad.example.com`; optional search base: `OU=Workstations,DC=ad,DC=example,DC=com`. Credentials must be authorized for the directory.

## Installation and execution

WinAudit supports three launch methods.

### Option 1: Clone the repository (Git)

Recommended when you want to inspect the source code, keep the modules locally, and update the project later.

```powershell
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1
```

Update the checkout with `git pull`.

### Option 2: One-command bootstrapper (IRM)

Run from Windows PowerShell without Git or a persistent installation:

```powershell
irm https://raw.githubusercontent.com/DarkCristian/WinAudit/main/install.ps1 | iex
```

The bootstrapper downloads WinAudit and its modules into a temporary directory, runs the console, then removes the downloaded program files. Reports are retained separately. It does not install RSAT or enable WinRM.

**Security:** `irm | iex` executes code retrieved from the internet. Review the source and prefer a pinned version for managed environments.

### Option 3: Standalone PowerShell script

Download [WinAudit-Standalone.ps1](dist/WinAudit-Standalone.ps1) and run it directly:

```powershell
.\WinAudit-Standalone.ps1
```

This standalone build includes the application modules in one file and does not require Git. It is an initial development build and has not yet been functionally validated on Windows.

### Non-interactive examples (Git checkout or standalone)

```powershell
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -PIDToAudit 1234 -StartTime '2026-01-01 10:00' -EndTime '2026-01-01 11:00'
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

Replace `WinAudit.ps1` with `WinAudit-Standalone.ps1` when using the standalone file.

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
