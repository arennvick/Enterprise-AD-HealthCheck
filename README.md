# AD Health Check Script and Dashboard

This workspace contains a complete PowerShell AD health check script:

- `Invoke-ADHealthCheck.ps1`
- `Invoke-ADHealthCheck-v2.ps1`
- `Invoke-ADHealthCheck-v2.1.ps1`
- `Invoke-ADHealthCheck-v2.3.ps1`

It discovers every domain controller in the current forest and writes a single self-contained HTML dashboard that can be opened from a network share by any browser.

Use `Invoke-ADHealthCheck-v2.3.ps1` for the newest modern dashboard, theme selector, GitHub update notification, charting, footer, and GPO backup comparison features. Current embedded script version: `2.3.5`.

## What It Checks

- Forest, domains, domain controllers, FSMO role holders, and DC inventory
- Per-DC server details: Windows Server version, OS version/build, architecture, install date, last boot, uptime, hardware model, memory, domain functional level, and forest functional level
- Per-DC patch status using latest installed hotfix date and installed hotfix count
- User and group counts per domain, including enabled users, disabled users, group category counts, and group scope counts
- Pie charts for enabled vs disabled users when user count data is available
- Recursive membership counts for Domain Admins, Enterprise Admins, and Schema Admins
- Connectivity from the server running the script to every DC
- Required and recommended TCP ports, with firewall guidance for blocked ports
- AD services: NTDS, DNS, KDC, Netlogon, W32Time, DFSR, and ADWS
- SYSVOL and NETLOGON share reachability
- Time service status from each DC
- AD replication partner metadata and replication failures
- `repadmin /replsummary` raw output when available
- `dcdiag /q` per DC when available
- DNS host records, forest DC locator SRV records, zones, forwarders, and DCDiag DNS test
- AD sites, site links, subnets, and DC counts per site
- GPO AD/SYSVOL version health and unlinked GPO visibility
- GPO backup on every run and comparison with the previous run for added, removed, or changed GPOs
- GPO inventory JSON creation for each run, with ID normalization, field-alias support, name fallback matching, and zero-overlap protection so existing GPOs are not marked as newly added when an older inventory used a different format
- Grouped summary sections and dashboard footer with script version, runtime, credits, and disclaimer
- GitHub release update check with dashboard notification and download button
- Theme selector at the top of the dashboard for Classic or Dark mode
- Optional recent event log errors from Directory Service, DNS Server, DFS Replication, and System logs

## Requirements

Run from a domain joined server or domain controller with an account that can read AD and query DCs.

Best results require these Windows tools/features:

- ActiveDirectory PowerShell module
- GroupPolicy PowerShell module
- DnsServer PowerShell module
- `dcdiag.exe`
- `repadmin.exe`

If a module or tool is missing, the dashboard will show that as a prerequisite warning and continue with the checks it can run.

## Basic Run

Open an elevated PowerShell session on an AD server or management server:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Invoke-ADHealthCheck-v2.3.ps1
```

The script saves an HTML file in the current folder using a name like:

```text
ADHealthDashboard_contoso.com_20260505_210000.html
```

## Save to a Network Share

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```

Any computer with access to that share can open the HTML file in a browser.

## Full Run With Event Logs

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -IncludeEventLogs -EventLogHours 24 -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```

Event log collection can be slower and may require firewall/RPC permissions.

## Patch Status Threshold

By default, the dashboard warns when the latest installed hotfix on a DC is older than 45 days, or when patch data cannot be queried.

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -PatchWarningDays 60 -OutputPath "\\fileserver\share\ADHealthDashboard.html"

## GitHub Update Notification

Version 2.1 and newer can check the latest GitHub release or tag when the script runs. If a newer version is found, the generated dashboard shows a notification banner with a download button.

The default repository is:

```text
https://github.com/arennvick/Enterprise-AD-HealthCheck
```

So you can run normally without passing a GitHub parameter:

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```

If the running script is `v2.1.0` and the latest GitHub release or tag is `v2.2.0`, the generated dashboard will show an update available banner.

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -GitHubRepositoryUrl "https://github.com/your-org/your-repo" -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```

Disable the check when the script server has no internet access:

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -SkipUpdateCheck -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```
```

## GPO Backups and Change Comparison

Version 2 creates a GPO backup folder on every run and writes an inventory snapshot. On the next run, it compares the current inventory with the previous run and reports added, removed, and changed GPOs in the GPO Health tab.

Default backup folder:

```text
.\ADHealth_GPOBackups
```

Custom backup folder:

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -GpoBackupRoot "\\fileserver\share\ADHealth_GPOBackups" -OutputPath "\\fileserver\share\ADHealthDashboard.html"
```

## Faster Run

```powershell
.\Invoke-ADHealthCheck-v2.3.ps1 -SkipDcDiag -SkipDnsTests -SkipGpoTests
```

## Connectivity Notes

The dashboard tests these TCP ports from the script server to every DC:

- TCP 53: DNS
- TCP 88: Kerberos
- TCP 135: RPC endpoint mapper
- TCP 389: LDAP
- TCP 445: SMB for SYSVOL and NETLOGON
- TCP 464: Kerberos password change
- TCP 636: LDAPS
- TCP 3268: Global Catalog
- TCP 3269: Global Catalog LDAPS
- TCP 5985: WinRM HTTP
- TCP 5986: WinRM HTTPS
- TCP 9389: Active Directory Web Services

Also validate UDP 53, UDP 88, UDP 123, UDP 389, UDP 464, and the Windows dynamic RPC range TCP 49152-65535 if service, event log, DCDiag, or replication checks fail even when TCP 135 is open. UDP reachability is not reliably tested by this script, so it is listed as guidance in the dashboard.
