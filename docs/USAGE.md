# Usage

Run on Windows with Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\WinAudit.ps1
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -PIDToAudit 1234 -StartTime '2026-01-01 10:00' -EndTime '2026-01-01 11:00'
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

The interactive menu provides local process inventory, PID event correlation, remote inventory, and Active Directory discovery.

Remote audit uses Get-Credential and Invoke-Command over WinRM. WinAudit does not configure WinRM for you. AD inventory requires the RSAT ActiveDirectory module and an authorized directory account.

Reports are written by default to `%USERPROFILE%\WinAudit-Reports`, outside the repository. Use `-ReportDirectory` to override. Do not publish actual reports.
