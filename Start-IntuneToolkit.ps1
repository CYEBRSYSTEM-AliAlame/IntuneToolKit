<#
.SYNOPSIS
    Menu-driven launcher for the Intune & Entra ID Admin Toolkit.
.DESCRIPTION
    Authenticates once to Microsoft Graph with all required scopes, then
    presents an interactive menu of all 32 toolkit scripts with guided
    parameter prompts.
.EXAMPLE
    .\Start-IntuneToolkit.ps1
#>

[CmdletBinding()]
param()

$toolkitRoot = $PSScriptRoot
if (-not $toolkitRoot) { $toolkitRoot = (Get-Location).Path }

#region --- Dependencies ---
$moduleName = "Microsoft.Graph.Authentication"
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Host ""
    Write-Host "  [!] Required module '$moduleName' is not installed." -ForegroundColor Yellow
    $install = Read-Host "  Would you like to install it now? (Y/N)"
    if ($install -match '^[Yy]') {
        Write-Host "  Installing '$moduleName' in CurrentUser scope..." -ForegroundColor Cyan
        try {
            Install-Module -Name $moduleName -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Successfully installed '$moduleName'!" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to install module: $_" -ForegroundColor Red
            Exit
        }
    } else {
        Write-Host "  Cannot continue without required module. Exiting." -ForegroundColor Red
        Exit
    }
}
Import-Module $moduleName -ErrorAction SilentlyContinue
#endregion

#region --- Helpers ---
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "    +-----------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "    |          INTUNE & ENTRA ID ADMIN TOOLKIT            | " -ForegroundColor Cyan
    Write-Host "    +-----------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "     PowerShell $($PSVersionTable.PSVersion.ToString())" -ForegroundColor DarkGray -NoNewline
    if ($context) {
        Write-Host " | Connected: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($context.Account)" -ForegroundColor Green
    } else {
        Write-Host " | Session: Not Connected" -ForegroundColor Red
    }
    Write-Host ""
}

function Write-MenuSection { param([string]$Title); Write-Host ""; Write-Host "  $Title" -ForegroundColor Yellow; Write-Host "  $('-' * $Title.Length)" -ForegroundColor DarkGray }
function Write-MenuItem { param([string]$N,[string]$Name,[string]$Desc); Write-Host "    [$N] " -ForegroundColor Green -NoNewline; Write-Host "$Name " -ForegroundColor White -NoNewline; Write-Host "- $Desc" -ForegroundColor DarkGray }
function Prompt-Input { param([string]$Msg,[string]$Default,[bool]$Required=$true); $pr="  $Msg"; if($Default){$pr+=" [$Default]"}; $pr+=": "; $v=Read-Host $pr; if(-not $v -and $Default){$v=$Default}; if(-not $v -and $Required){Write-Host "  Required." -ForegroundColor Red; return $null}; return $v }
function Prompt-YesNo { param([string]$Msg); return (Read-Host "  $Msg (Y/N)") -match '^[Yy]' }
function Confirm-Script { param([string]$S); $p=Join-Path $toolkitRoot $S; if(-not(Test-Path $p)){Write-Host "  ERROR: $S not found" -ForegroundColor Red; return $null}; return $p }
#endregion

#region --- Auth ---
$context = Get-MgContext
if ($context) {
    # Verify if session token is still active by running a quick lightweight query
    try {
        $null = Get-MgOrganization -ErrorAction Stop
    } catch {
        Write-Host "  Cached session is expired or invalid. Re-authenticating..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        $context = $null
    }
}

if (-not $context) {
    Write-Banner
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor DarkGray
    try {
        Connect-MgGraph -Scopes @(
            'DeviceManagementConfiguration.Read.All','DeviceManagementConfiguration.ReadWrite.All',
            'DeviceManagementManagedDevices.Read.All','DeviceManagementManagedDevices.ReadWrite.All',
            'DeviceManagementManagedDevices.PrivilegedOperations.All',
            'DeviceManagementServiceConfig.Read.All','DeviceManagementApps.Read.All',
            'DeviceManagementRBAC.Read.All','Device.Read.All','Directory.Read.All',
            'Group.Read.All','GroupMember.Read.All','User.Read.All',
            'Policy.Read.All','Application.Read.All','BitlockerKey.Read.All',
            'AuditLog.Read.All','IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All',
            'RoleManagement.Read.All','Organization.Read.All'
        ) -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
    } catch {
        Write-Host "  Auth failed: $_" -ForegroundColor Red
        Exit
    }
}
#endregion

#region --- Menu ---
$running = $true
while ($running) {
    Write-Banner

    Write-MenuSection "ASSIGNMENT REPORTING"
    Write-MenuItem "1"  "Get-IntuneDevicePolicies"      "All policies assigned to a device"
    Write-MenuItem "2"  "Get-IntuneGroupPolicies"        "All policies assigned to a group"
    Write-MenuItem "3"  "Get-IntuneUserPolicies"         "All policies assigned to a user"

    Write-MenuSection "COMPLIANCE & SECURITY"
    Write-MenuItem "4"  "Get-IntuneComplianceReport"     "Non-compliant devices + failure reasons"
    Write-MenuItem "5"  "Get-IntuneBitLockerKeys"        "BitLocker key lookup or escrow audit"
    Write-MenuItem "6"  "Get-IntuneDefenderStatus"       "Defender health across all devices"

    Write-MenuSection "DEVICE REPORTING"
    Write-MenuItem "7"  "Get-IntuneStaleDevices"         "Stale/orphaned devices"
    Write-MenuItem "8"  "Export-IntuneDeviceInventory"    "Full 35-column device inventory"
    Write-MenuItem "9"  "Get-IntuneAppStatusReport"      "App install status + failures"
    Write-MenuItem "10" "Get-IntuneDeviceTimeline"       "Single device deep-dive timeline"

    Write-MenuSection "WINDOWS UPDATES"
    Write-MenuItem "11" "Get-IntunePatchCompliance"      "OS build distribution + outdated"
    Write-MenuItem "12" "Get-IntuneUpdateRingStatus"     "Ring config comparison"
    Write-MenuItem "13" "Test-IntuneUpdateRingHealth"    "Ring best practices audit"
    Write-MenuItem "14" "Get-IntuneUpdateComplianceReport" "Per-ring compliance + conflicts"
    Write-MenuItem "15" "Get-IntuneFeatureUpdateStatus"  "Feature update deployment states"

    Write-MenuSection "DEPLOYMENT HEALTH"
    Write-MenuItem "16" "Get-IntunePolicyDeploymentStatus" "Per-policy success/fail rates"
    Write-MenuItem "17" "Get-IntuneRemediationStatus"    "Remediation script health"
    Write-MenuItem "18" "Get-IntuneAutopilotReport"      "Autopilot registration + profiles"
    Write-MenuItem "19" "Get-IntuneAppProtectionStatus"  "MAM policy status"
    Write-MenuItem "20" "Get-IntuneCertificateReport"    "Certificate profile health"
    Write-MenuItem "21" "Get-IntuneScopeTagReport"       "Scope tag usage + RBAC"

    Write-MenuSection "ENTRA ID - IDENTITY & ACCESS"
    Write-MenuItem "22" "Get-EntraCAReport"              "Conditional Access policies"
    Write-MenuItem "23" "Get-EntraGroupAudit"            "Group membership + health"
    Write-MenuItem "24" "Get-EntraSignInReport"          "Sign-in failures, MFA, legacy auth"
    Write-MenuItem "25" "Get-EntraRiskyUsers"            "Risky users + risk detections"
    Write-MenuItem "26" "Get-EntraAppRegistrationAudit"  "App secrets, permissions, owners"
    Write-MenuItem "27" "Get-EntraLicenseReport"         "License utilization + waste"
    Write-MenuItem "28" "Get-EntraGuestUserAudit"        "Guest user audit"
    Write-MenuItem "29" "Get-EntraAdminRoleReport"       "Admin role assignments"
    Write-MenuItem "30" "Get-EntraDirectoryAudit"        "Recent directory changes"

    Write-MenuSection "ACTIONS & TROUBLESHOOTING"
    Write-MenuItem "31" "Invoke-IntuneBulkActions"       "Bulk sync, restart, Defender scan"
    Write-MenuItem "32" "Find-IntunePolicyConflict"      "Analyze / Investigate / Isolate"

    Write-MenuSection "DASHBOARDS & EXPORTS"
    Write-MenuItem "33" "Export-IntuneDashboard"          "HTML dashboard with charts & KPIs"

    Write-Host ""
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    Write-MenuItem "Q"  "Quit" "Exit the toolkit"
    Write-Host ""

    $choice = Read-Host "  Select an option"
    Write-Host ""

    switch ($choice.Trim()) {
        '1'  { $s=Confirm-Script 'Get-IntuneDevicePolicies.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Device name';if($v){& $s -DeviceName $v} }
        '2'  { $s=Confirm-Script 'Get-IntuneGroupPolicies.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Group name';if($v){& $s -GroupName $v} }
        '3'  { $s=Confirm-Script 'Get-IntuneUserPolicies.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'User principal name (e.g., user@contoso.com)';if($v){& $s -UserPrincipalName $v} }
        '4'  { $s=Confirm-Script 'Get-IntuneComplianceReport.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Device name (blank for all)' -Required $false; $p=@{};if($v){$p.DeviceName=$v}; & $s @p }
        '5'  { $s=Confirm-Script 'Get-IntuneBitLockerKeys.ps1';if(-not $s){Read-Host "  Enter";break}; $m=Prompt-Input 'Lookup (L) or Audit (A)' -Default 'L'; if($m -match '^[Aa]'){& $s -Audit}else{$v=Prompt-Input 'Device name';if($v){& $s -DeviceName $v -ShowKeys:(Prompt-YesNo 'Show keys?')}} }
        '6'  { $s=Confirm-Script 'Get-IntuneDefenderStatus.ps1';if($s){& $s} }
        '7'  { $s=Confirm-Script 'Get-IntuneStaleDevices.ps1';if($s){& $s} }
        '8'  { $s=Confirm-Script 'Export-IntuneDeviceInventory.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'OS filter (blank for all)' -Required $false; $p=@{};if($v){$p.OSFilter=$v}; & $s @p }
        '9'  { $s=Confirm-Script 'Get-IntuneAppStatusReport.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'App name (blank for all)' -Required $false; $p=@{};if($v){$p.AppName=$v}; & $s @p }
        '10' { $s=Confirm-Script 'Get-IntuneDeviceTimeline.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Device name';if($v){& $s -DeviceName $v} }
        '11' { $s=Confirm-Script 'Get-IntunePatchCompliance.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Min build (blank to skip)' -Required $false; $p=@{};if($v){$p.MinBuild=$v}; & $s @p }
        '12' { $s=Confirm-Script 'Get-IntuneUpdateRingStatus.ps1';if($s){& $s} }
        '13' { $s=Confirm-Script 'Test-IntuneUpdateRingHealth.ps1';if($s){& $s} }
        '14' { $s=Confirm-Script 'Get-IntuneUpdateComplianceReport.ps1';if($s){& $s} }
        '15' { $s=Confirm-Script 'Get-IntuneFeatureUpdateStatus.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Profile name (blank for all)' -Required $false; $p=@{};if($v){$p.ProfileName=$v}; & $s @p }
        '16' { $s=Confirm-Script 'Get-IntunePolicyDeploymentStatus.ps1';if($s){& $s} }
        '17' { $s=Confirm-Script 'Get-IntuneRemediationStatus.ps1';if($s){& $s} }
        '18' { $s=Confirm-Script 'Get-IntuneAutopilotReport.ps1';if($s){& $s} }
        '19' { $s=Confirm-Script 'Get-IntuneAppProtectionStatus.ps1';if($s){& $s} }
        '20' { $s=Confirm-Script 'Get-IntuneCertificateReport.ps1';if($s){& $s} }
        '21' { $s=Confirm-Script 'Get-IntuneScopeTagReport.ps1';if($s){& $s} }
        '22' { $s=Confirm-Script 'Get-EntraCAReport.ps1';if($s){& $s} }
        '23' { $s=Confirm-Script 'Get-EntraGroupAudit.ps1';if(-not $s){Read-Host "  Enter";break}; $m=Prompt-Input 'Single group (S) or Bulk audit (B)' -Default 'S'; if($m -match '^[Bb]'){& $s -BulkAudit}else{$v=Prompt-Input 'Group name';if($v){& $s -GroupName $v}} }
        '24' { $s=Confirm-Script 'Get-EntraSignInReport.ps1';if(-not $s){Read-Host "  Enter";break}; $h=Prompt-Input 'Hours to look back' -Default '24'; $inc=Prompt-YesNo 'Include successes?'; $p=@{Hours=[int]$h};if($inc){$p.IncludeSuccessful=$true}; & $s @p }
        '25' { $s=Confirm-Script 'Get-EntraRiskyUsers.ps1';if(-not $s){Read-Host "  Enter";break}; $inc=Prompt-YesNo 'Include dismissed risks?'; $p=@{};if($inc){$p.IncludeDismissed=$true}; & $s @p }
        '26' { $s=Confirm-Script 'Get-EntraAppRegistrationAudit.ps1';if(-not $s){Read-Host "  Enter";break}; $d=Prompt-Input 'Expiry threshold days' -Default '30'; & $s -DaysUntilExpiry ([int]$d) }
        '27' { $s=Confirm-Script 'Get-EntraLicenseReport.ps1';if($s){& $s} }
        '28' { $s=Confirm-Script 'Get-EntraGuestUserAudit.ps1';if(-not $s){Read-Host "  Enter";break}; $d=Prompt-Input 'Inactive days threshold' -Default '90'; & $s -InactiveDays ([int]$d) }
        '29' { $s=Confirm-Script 'Get-EntraAdminRoleReport.ps1';if($s){& $s} }
        '30' { $s=Confirm-Script 'Get-EntraDirectoryAudit.ps1';if(-not $s){Read-Host "  Enter";break}; $h=Prompt-Input 'Hours to look back' -Default '24'; Write-Host "  Categories: All, User, Group, Application, Role, Policy" -ForegroundColor DarkGray; $c=Prompt-Input 'Category' -Default 'All'; & $s -Hours ([int]$h) -Category $c }
        '31' { $s=Confirm-Script 'Invoke-IntuneBulkActions.ps1';if(-not $s){Read-Host "  Enter";break}
               Write-Host "  1=Sync 2=Restart 3=BitLockerRotate 4=DefenderScan 5=DefenderSigs 6=Diagnostics" -ForegroundColor DarkGray
               $ac=Prompt-Input 'Action (1-6)'; $am=@{'1'='Sync';'2'='Restart';'3'='BitLockerRotate';'4'='DefenderScan';'5'='DefenderSignatures';'6'='CollectDiagnostics'}; $sa=$am[$ac.Trim()]
               if(-not $sa){Write-Host "  Invalid." -ForegroundColor Red;Read-Host "  Enter";break}
               Write-Host "  1=Group 2=OS 3=Names 4=CSV" -ForegroundColor DarkGray; $tc=Prompt-Input 'Target (1-4)'; $p=@{Action=$sa}
               switch($tc.Trim()){'1'{$p.GroupName=Prompt-Input 'Group name'}'2'{$p.OSFilter=Prompt-Input 'OS (Windows)'}'3'{$p.DeviceNames=(Prompt-Input 'Names (comma-sep)')-split','-replace'^\s+|\s+$',''}'4'{$p.CsvPath=Prompt-Input 'CSV path'}}
               & $s @p }
        '32' { $s=Confirm-Script 'Find-IntunePolicyConflict.ps1';if(-not $s){Read-Host "  Enter";break}
               $dn=Prompt-Input 'Device name';if(-not $dn){Read-Host "  Enter";break}
               Write-Host "  A=Analyze  I=Investigate  S=Isolate" -ForegroundColor DarkGray; $m=Prompt-Input 'Mode' -Default 'Analyze'
               $mm=@{'A'='Analyze';'I'='Investigate';'S'='Isolate';'Analyze'='Analyze';'Investigate'='Investigate';'Isolate'='Isolate'}
               $sm=if($mm.ContainsKey($m)){$mm[$m]}else{'Analyze'}; $p=@{DeviceName=$dn;Mode=$sm}
               if($sm -eq 'Investigate'){Write-Host "  Features: Hello, BitLocker, Firewall, Defender, WiFi, VPN, Edge, OneDrive, Updates, Certificates, Proxy, Encryption, AppLocker" -ForegroundColor DarkGray; $f=Prompt-Input 'Feature';if($f){$p.Feature=$f}}
               & $s @p }
        '33' { $s=Confirm-Script 'Export-IntuneDashboard.ps1';if(-not $s){Read-Host "  Enter";break}; $v=Prompt-Input 'Output path (blank for Desktop)' -Required $false; $p=@{};if($v){$p.OutputPath=$v}; & $s @p }
        {$_ -match '^[Qq]$'} { $running=$false; Write-Host "  Goodbye!" -ForegroundColor Cyan }
        default { Write-Host "  Invalid. Enter 1-33 or Q." -ForegroundColor Red }
    }

    if ($running -and $choice.Trim() -notmatch '^[Qq]$') {
        Write-Host ""; Write-Host "  $('='*60)" -ForegroundColor DarkGray; Read-Host "  Press Enter to return to menu"
    }
}
#endregion
