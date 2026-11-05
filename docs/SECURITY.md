# Security model

WinAudit is a read-only investigation utility. It does not enable WinRM, change audit policy, terminate processes, or install agents.

## Scope and limitations
- Run only against systems you administer or are authorized to assess.
- Active Directory discovery requires RSAT ActiveDirectory and directory permissions.
- Remote inventory requires configured PowerShell Remoting and appropriate remote permissions.
- Security, PowerShell and Sysmon event availability depends on OS configuration, audit policy and retention.
- PID values can be reused. Matching a PID alone does not establish process identity.
- Event System.Execution.ProcessID describes the event emitter; EventData fields can refer to a different process.
- An unsigned binary is not automatically malicious, and a valid signature is not proof of safety.
- Reports may contain usernames, paths, command-line arguments and other sensitive information. Keep them local and access-controlled.
- No external telemetry or automatic uploads are implemented.

## Reporting vulnerabilities
Open a GitHub security advisory for security vulnerabilities. Do not include credentials, private logs or corporate identifiers in public issues.
