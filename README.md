# Intune & Entra ID Admin Toolkit

Day-to-day operations, troubleshooting, and reporting for Microsoft Intune and Entra ID environments.

---

## Prerequisites

- **PowerShell 5.1+** (PowerShell 7 recommended)
- **Microsoft.Graph.Authentication** module installed:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```
- An Entra ID account with appropriate Intune admin permissions
- Active Microsoft Intune license on the tenant

---

## Folder Structure

Place all scripts in the same directory:

```
IntuneToolkit/
├── Start-IntuneToolkit.ps1              ← Menu launcher (run this)
├── Get-IntuneDevicePolicies.ps1         ← Policies assigned to a device
├── Get-IntuneGroupPolicies.ps1          ← Policies assigned to a group
├── Get-IntuneUserPolicies.ps1           ← Policies assigned to a user
├── Get-IntuneComplianceReport.ps1       ← Non-compliance details
├── Get-IntuneStaleDevices.ps1           ← Stale/orphaned devices
├── Get-IntuneAppStatusReport.ps1        ← App install failures
├── Export-IntuneDeviceInventory.ps1     ← Full device inventory
├── Get-IntuneBitLockerKeys.ps1          ← BitLocker key lookup & audit
├── Invoke-IntuneBulkActions.ps1         ← Bulk sync, restart, etc.
├── Get-EntraCAReport.ps1               ← Conditional Access report
├── Get-EntraGroupAudit.ps1             ← Group membership audit
├── Find-IntunePolicyConflict.ps1        ← Policy conflict troubleshooting
└── README.md                            ← This file
```

---

## Quick Start

### Option 1: Use the Menu Launcher

```powershell
.\Start-IntuneToolkit.ps1
```

This authenticates once with all required Graph scopes, then presents an interactive menu where you pick a script and provide parameters through guided prompts.

### Option 2: Run Scripts Directly

Each script is fully standalone. Run any script individually — it will handle Graph authentication on its own if no session exists.

---

## Script Reference & Examples

---

### 1. Get-IntuneDevicePolicies.ps1

**What it does:** Reports every Intune policy, app, and script assigned to a specific device via its group memberships, "All Devices", and "All Users" targets.

**When to use:** A device is misbehaving and you need to see everything targeting it.

```powershell
# Look up by device name
.\Get-IntuneDevicePolicies.ps1 -DeviceName "L-PF4Z0HM0"

# Look up by Intune device ID
.\Get-IntuneDevicePolicies.ps1 -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Export to a specific CSV path
.\Get-IntuneDevicePolicies.ps1 -DeviceName "L-PF4Z0HM0" -ExportPath "C:\temp\device_policies.csv"
```

**Output includes:** Policy type, policy name, platform, which group triggered the assignment, and policy ID. Auto-exports a CSV to the temp folder.

---

### 2. Get-IntuneGroupPolicies.ps1

**What it does:** Reports every Intune policy and app assigned to a specific Entra ID group — both Include and Exclude assignments.

**When to use:** You want to know what happens when a device or user is added to a group, or you need to audit a group's policy footprint.

```powershell
# Look up by group name
.\Get-IntuneGroupPolicies.ps1 -GroupName "SG-Intune-Windows-Devices"

# Look up by group ID
.\Get-IntuneGroupPolicies.ps1 -GroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Include "All Devices" and "All Users" global assignments in the report
.\Get-IntuneGroupPolicies.ps1 -GroupName "SG-Intune-Pilot" -IncludeAllDevicesAllUsers

# Export to CSV
.\Get-IntuneGroupPolicies.ps1 -GroupName "SG-Intune-Windows-Devices" -ExportPath "C:\temp\group_policies.csv"
```

**Output includes:** Policy type, policy name, platform, Include/Exclude assignment type, and policy ID. Shows group metadata (type, member count, dynamic rule, parent groups).

---

### 3. Get-IntuneUserPolicies.ps1

**What it does:** Reports every Intune policy and app assigned to a user through their transitive group memberships, "All Users", and "All Licensed Users" targets.

**When to use:** A user reports an issue and you need to see their full policy footprint, or you're onboarding someone and want to verify what they'll receive.

```powershell
# Look up by UPN
.\Get-IntuneUserPolicies.ps1 -UserPrincipalName "jsmith@contoso.com"

# Look up by user object ID
.\Get-IntuneUserPolicies.ps1 -UserId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Export to CSV
.\Get-IntuneUserPolicies.ps1 -UserPrincipalName "jsmith@contoso.com" -ExportPath "C:\temp\user_policies.csv"
```

**Output includes:** User profile details (job title, department, account status, license count), all managed devices with compliance state, group memberships, and every assigned policy with Include/Exclude status and which group triggered the match.

---

### 4. Get-IntuneComplianceReport.ps1

**What it does:** Identifies non-compliant devices and drills into the specific policies and settings that failed. Shows compliance rate, top failing policies, top failing settings, and devices with no compliance policy assigned.

**When to use:** Compliance dashboard shows failures and you need to know exactly why, or you need a compliance report for auditors.

```powershell
# All non-compliant devices across the tenant
.\Get-IntuneComplianceReport.ps1

# Deep-dive on a single device
.\Get-IntuneComplianceReport.ps1 -DeviceName "L-PF4Z0HM0"

# Devices in a specific group
.\Get-IntuneComplianceReport.ps1 -GroupName "SG-Intune-Windows-Devices"

# Full report including compliant devices
.\Get-IntuneComplianceReport.ps1 -IncludeCompliant -ExportPath "C:\temp\compliance_full.csv"

# Group-scoped export
.\Get-IntuneComplianceReport.ps1 -GroupName "SG-Corporate-Laptops" -ExportPath "C:\temp\compliance.csv"
```

**Output includes:** One CSV row per failed setting per device. Columns: device name, user, OS, model, serial, compliance state, policy name, policy state, setting name, setting state, current value. Console shows compliance rate, top failing policies ranked by violation count, and top failing settings ranked by device count.

---

### 5. Get-IntuneStaleDevices.ps1

**What it does:** Cross-references Intune and Entra ID to find stale devices, orphaned records, devices with no user, and disabled Entra accounts still owning devices. Generates actionable recommendations (RETIRE, DELETE, REVIEW, MONITOR).

**When to use:** Monthly device cleanup, preparing for license audits, or finding devices that fell off the radar.

```powershell
# Default: devices inactive for 90+ days, warning at 60 days
.\Get-IntuneStaleDevices.ps1

# Tighter thresholds
.\Get-IntuneStaleDevices.ps1 -InactivityDays 60 -WarningDays 30

# Windows devices only
.\Get-IntuneStaleDevices.ps1 -OSFilter "Windows"

# Include active devices for a full health report
.\Get-IntuneStaleDevices.ps1 -IncludeCompliant -ExportPath "C:\temp\device_health.csv"

# Combined: iOS devices inactive 30+ days
.\Get-IntuneStaleDevices.ps1 -OSFilter "iOS" -InactivityDays 30 -WarningDays 14
```

**Output includes:** Intune last sync and days since sync, Entra last sign-in and days since sign-in, cross-reference status (orphan detection both directions), issues found, and a recommended action per device. Console shows stale count, orphan count, and the most stale devices ranked by days since sync.

---

### 6. Get-IntuneAppStatusReport.ps1

**What it does:** Reports app installation status across devices — failed, pending, and successful deployments with error codes and failure reasons.

**When to use:** An app isn't installing on some devices, or you need deployment health metrics.

```powershell
# All assigned apps — show failures only
.\Get-IntuneAppStatusReport.ps1

# Specific app across all devices
.\Get-IntuneAppStatusReport.ps1 -AppName "Microsoft Teams"

# Partial name match
.\Get-IntuneAppStatusReport.ps1 -AppName "Company Portal"

# All app statuses for a single device
.\Get-IntuneAppStatusReport.ps1 -DeviceName "L-PF4Z0HM0" -IncludeAll

# Include successful installations too
.\Get-IntuneAppStatusReport.ps1 -IncludeAll -ExportPath "C:\temp\app_status.csv"
```

**Output includes:** App name, app type, device name, user, install state, error code (hex and decimal), install detail, last modified date. Console shows top failing apps, top error codes, and devices with the most failures.

---

### 7. Export-IntuneDeviceInventory.ps1

**What it does:** Exports a comprehensive 35-column device inventory covering hardware, OS, compliance, encryption, storage, enrollment, and Entra ID status.

**When to use:** Asset management, hardware lifecycle planning, executive reporting, license audits.

```powershell
# Full inventory of all managed devices
.\Export-IntuneDeviceInventory.ps1

# Windows devices only
.\Export-IntuneDeviceInventory.ps1 -OSFilter "Windows"

# Devices in a specific group
.\Export-IntuneDeviceInventory.ps1 -GroupName "SG-Corporate-Laptops"

# Include detected app counts (slower — one API call per device)
.\Export-IntuneDeviceInventory.ps1 -IncludeDetectedApps

# Combined: Windows devices in a group, exported to specific path
.\Export-IntuneDeviceInventory.ps1 -OSFilter "Windows" -GroupName "SG-Pilot" -ExportPath "C:\temp\inventory.csv"
```

**Output includes:** Device name, user, OS/version, manufacturer, model, serial, MAC addresses, IMEI, storage (total/free/% used), compliance state, encryption status, management agent, join type, ownership, enrollment date, device age, Autopilot status, Entra sign-in data, and more. Console shows fleet analytics: OS distribution, compliance breakdown, encryption status, top manufacturers/models, Windows version distribution, and low storage warnings.

---

### 8. Get-IntuneBitLockerKeys.ps1

**What it does:** Two modes — (1) Helpdesk lookup to retrieve BitLocker recovery keys for a specific device, and (2) Security audit to scan all Windows devices for missing escrowed keys.

**When to use:** User is locked out and needs a recovery key, or security audit requires proof of key escrow compliance.

```powershell
# --- Helpdesk Lookup ---

# By device name (keys masked in console by default)
.\Get-IntuneBitLockerKeys.ps1 -DeviceName "L-PF4Z0HM0"

# Show the actual recovery key values
.\Get-IntuneBitLockerKeys.ps1 -DeviceName "L-PF4Z0HM0" -ShowKeys

# By serial number
.\Get-IntuneBitLockerKeys.ps1 -SerialNumber "PF4Z0HM0" -ShowKeys

# --- Security Audit ---

# Audit all Windows devices for escrowed keys
.\Get-IntuneBitLockerKeys.ps1 -Audit

# Audit devices in a specific group
.\Get-IntuneBitLockerKeys.ps1 -Audit -GroupName "SG-Corporate-Laptops"

# Export audit results
.\Get-IntuneBitLockerKeys.ps1 -Audit -ExportPath "C:\temp\bitlocker_audit.csv"
```

**Lookup output:** Device info, encryption status, recovery key(s) with volume type, key ID, and creation date. Keys masked unless `-ShowKeys` is passed. CSV always contains full keys with a security warning.

**Audit output:** Key escrow status per device (KEY ESCROWED / KEY MISSING / NO ENTRA RECORD), key count, latest key date, volume types. Console shows escrow rate percentage and highlights encrypted devices with no escrowed key (data loss risk).

---

### 9. Invoke-IntuneBulkActions.ps1

**What it does:** Performs bulk remote actions on managed devices: Sync, Restart, BitLocker key rotation, Defender scan, Defender signature update, and diagnostic log collection.

**When to use:** Policies aren't landing and you need to force check-in, or you need to push a Defender scan across a group after a security incident.

```powershell
# Force sync all devices in a group
.\Invoke-IntuneBulkActions.ps1 -Action Sync -GroupName "SG-Windows-Devices"

# Sync only devices that haven't checked in for 3+ days
.\Invoke-IntuneBulkActions.ps1 -Action Sync -OSFilter "Windows" -StaleOnly -StaleDays 3

# Sync only non-compliant Windows devices
.\Invoke-IntuneBulkActions.ps1 -Action Sync -OSFilter "Windows" -NonCompliantOnly

# Restart specific devices (skip confirmation)
.\Invoke-IntuneBulkActions.ps1 -Action Restart -DeviceNames "PC-001","PC-002","PC-003" -Force

# Trigger Defender scan on non-compliant devices
.\Invoke-IntuneBulkActions.ps1 -Action DefenderScan -OSFilter "Windows" -NonCompliantOnly

# Update Defender signatures across a group
.\Invoke-IntuneBulkActions.ps1 -Action DefenderSignatures -GroupName "SG-All-Windows"

# Rotate BitLocker keys from a CSV list
.\Invoke-IntuneBulkActions.ps1 -Action BitLockerRotate -CsvPath "C:\temp\devices.csv"

# Collect diagnostics for troubleshooting
.\Invoke-IntuneBulkActions.ps1 -Action CollectDiagnostics -GroupName "SG-Troubleshoot"

# Export results
.\Invoke-IntuneBulkActions.ps1 -Action Sync -GroupName "SG-Pilot" -ExportPath "C:\temp\sync_results.csv"
```

**CSV input format** (for `-CsvPath`):
```csv
DeviceName
PC-001
PC-002
LAPTOP-ABC
```

**Safety features:** Confirmation prompt before execution (skip with `-Force`), extra warning for destructive actions (Restart, BitLockerRotate), configurable throttling (`-ThrottleMs`), per-device success/failure tracking.

---

### 10. Get-EntraCAReport.ps1

**What it does:** Exports all Conditional Access policies with full detail — user/group assignments (names resolved from IDs), application targets, platform/location/risk conditions, grant controls, and session controls.

**When to use:** Security audit, CA policy documentation, change review, or finding gaps in your CA coverage.

```powershell
# All enabled and report-only policies
.\Get-EntraCAReport.ps1

# Filter by policy name (partial match)
.\Get-EntraCAReport.ps1 -PolicyName "MFA"

# Only active policies
.\Get-EntraCAReport.ps1 -EnabledOnly

# Include disabled policies too
.\Get-EntraCAReport.ps1 -IncludeDisabled

# Export for documentation
.\Get-EntraCAReport.ps1 -EnabledOnly -ExportPath "C:\temp\ca_policies.csv"
```

**Output includes:** Policy name, state, created/modified dates, included/excluded users and groups (names resolved), included/excluded apps, platforms, client app types, locations (named locations resolved), risk levels, device filters, grant controls (with operator AND/OR), session controls (sign-in frequency, persistent browser, CAE, etc.). Console highlights policies targeting All Users with no exclusions (lockout risk) and report-only policies that may have been forgotten.

---

### 11. Get-EntraGroupAudit.ps1

**What it does:** Two modes — (1) Deep dive on a single group showing members, owners, nesting, licenses, and configuration, or (2) Bulk health audit across all groups flagging empty groups, ownerless groups, and large groups.

**When to use:** Auditing group hygiene, verifying membership before policy changes, or cleaning up unused groups.

```powershell
# --- Single Group Deep Dive ---

# Full audit of a specific group
.\Get-EntraGroupAudit.ps1 -GroupName "SG-Intune-Windows-Devices"

# By group ID
.\Get-EntraGroupAudit.ps1 -GroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Export full member list to CSV
.\Get-EntraGroupAudit.ps1 -GroupName "SG-Intune-Pilot" -IncludeMembers -ExportPath "C:\temp\members.csv"

# --- Bulk Health Audit ---

# Audit all groups for health issues
.\Get-EntraGroupAudit.ps1 -BulkAudit

# Export audit results
.\Get-EntraGroupAudit.ps1 -BulkAudit -ExportPath "C:\temp\group_health.csv"
```

**Single group output:** Group type, security/mail enabled, dynamic rule and processing state, owners with UPNs, member breakdown (users/devices/nested groups/service principals), disabled user accounts still in the group, device OS breakdown, parent groups (nesting hierarchy), and license assignments with SKU names.

**Bulk audit output:** Group type distribution, empty groups, ownerless groups, large groups (500+), paused dynamic rules. CSV includes member count, owner count, group age, and issues per group.

---

### 12. Find-IntunePolicyConflict.ps1

**What it does:** Three-mode policy troubleshooting tool — (1) Analyze finds reported conflicts and errors, (2) Investigate X-rays all settings for a feature area including successfully applied settings that may cause side effects, (3) Isolate does a binary search to find the culprit policy.

**When to use:** Something is broken on a device and you don't know which of the 70 policies is causing it.

```powershell
# --- Step 1: Analyze (check for reported conflicts) ---

.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0"

# --- Step 2: Investigate (X-ray a feature area) ---

# Windows Hello is broken — show every related setting and its value
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature Hello

# BitLocker won't enable
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature BitLocker

# Firewall issues
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature Firewall

# Defender not working properly
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature Defender

# WiFi profiles not connecting
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature WiFi

# VPN issues
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature VPN

# Custom keyword (not in built-in maps)
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature "Bluetooth"
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature "RemoteDesktop"
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature "Kiosk"

# Export investigation results
.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature Hello -ExportPath "C:\temp\hello_investigation.csv"

# --- Step 3: Isolate (binary search — last resort) ---

.\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Isolate
```

**Built-in feature maps** (the script knows which CSP paths and settings each feature depends on):

| Feature | What it searches for |
|---------|---------------------|
| Hello | TPM, biometrics, PIN, FIDO2, PassportForWork, credential providers, NGC, WebAuthn, smart card |
| BitLocker | Encryption methods, TPM, startup auth, recovery keys, silent encryption, volume encryption |
| Firewall | Profiles (domain/private/public), inbound/outbound rules, stealth mode, shielded mode |
| Defender | Real-time monitoring, cloud protection, ASR, EDR, tamper protection, SmartScreen, exploit guard |
| WiFi | Wireless profiles, 802.1x, EAP, SSID, WPA, proxy, DNS |
| VPN | Always-on VPN, split tunnel, traffic filters, routes, DNS suffix, trusted network detection |
| Edge | Browser policies, extensions, password manager, SmartScreen, proxy, enterprise mode |
| OneDrive | KFM, Files on Demand, tenant ID, sync client, bandwidth |
| Updates | WUfB, feature/quality/driver updates, delivery optimization, active hours, defer/pause |
| Certificates | SCEP, PKCS, root certs, client certs, certificate stores |
| Proxy | Proxy server, PAC/WPAD, auto-config URL |
| Encryption | TLS/SSL, cipher suites, SCHANNEL |
| AppLocker | Application control, WDAC, code integrity |

**Key concept:** Analyze finds conflicts (two policies fighting). Investigate finds hardening side effects (one policy successfully applied a restrictive value that breaks a feature). Isolate finds anything when the first two can't.

---

### 13. Start-IntuneToolkit.ps1 (Menu Launcher)

**What it does:** Interactive console menu that presents all toolkit scripts, handles Graph authentication once at startup, and guides you through parameter input for each script.

```powershell
# Just run it
.\Start-IntuneToolkit.ps1
```

The launcher authenticates with all required scopes upfront, then presents a numbered menu. Pick a script, answer the prompts, and it runs. Press Enter after completion to return to the menu.

---

## Graph Permissions Required

The launcher requests all scopes at once. Individual scripts only request what they need.

| Permission | Used by |
|-----------|---------|
| DeviceManagementConfiguration.Read.All | Policy scripts, conflict finder |
| DeviceManagementConfiguration.ReadWrite.All | Isolate mode (Find-IntunePolicyConflict) |
| DeviceManagementManagedDevices.Read.All | All device scripts |
| DeviceManagementManagedDevices.ReadWrite.All | Bulk actions |
| DeviceManagementManagedDevices.PrivilegedOperations.All | Bulk actions (restart, wipe) |
| DeviceManagementServiceConfig.Read.All | Policy assignment scripts |
| DeviceManagementApps.Read.All | App status, policy assignment scripts |
| Device.Read.All | All device scripts |
| Directory.Read.All | All scripts |
| Group.Read.All | Group-related scripts |
| GroupMember.Read.All | Group membership resolution |
| User.Read.All | User policy script, inventory |
| Policy.Read.All | Conditional Access report |
| Application.Read.All | Conditional Access report (app name resolution) |
| BitlockerKey.Read.All | BitLocker key script |

---

## CSV Export Behavior

Every script auto-exports results to a CSV in your temp folder (`$env:TEMP`) with a timestamped filename. Use `-ExportPath` to specify a custom path instead.

Example auto-generated paths:
```
C:\Users\admin\AppData\Local\Temp\L-PF4Z0HM0_IntunePolicies_20260411_143022.csv
C:\Users\admin\AppData\Local\Temp\SG-Windows-Devices_IntunePolicies_20260411_143055.csv
C:\Users\admin\AppData\Local\Temp\StaleDeviceReport_20260411_144512.csv
C:\Users\admin\AppData\Local\Temp\AllDevices_DeviceInventory_20260411_145033.csv
```

---

## Troubleshooting Tips

**"Insufficient privileges" errors:** Make sure your account has at least Intune Administrator or a custom role with the required Graph permissions. Some scripts (BitLocker keys, bulk actions) need elevated permissions.

**Scripts running slowly:** Large tenants with thousands of devices/policies will take longer. The scripts use progress bars for long operations. For app status and device inventory, filtering by `-OSFilter` or `-GroupName` significantly reduces API calls.

**Graph rate limiting (429 errors):** The scripts handle pagination automatically. For bulk actions, adjust `-ThrottleMs` (default 200ms between calls). If you hit persistent throttling, increase to 500-1000ms.

**"Device not found" errors:** Verify the device name matches exactly as shown in the Intune portal (case-sensitive). Use the Intune device name, not the computer hostname if they differ.

**Authentication across scripts:** If you run the launcher first, all scripts reuse the same Graph session. If running scripts individually, each one checks for an existing session before prompting.
