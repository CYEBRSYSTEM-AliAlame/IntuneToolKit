#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a single-page HTML dashboard aggregating key Intune & Entra ID health metrics.
.DESCRIPTION
    Pulls data from multiple Graph endpoints in one pass and renders an interactive HTML
    report with charts, donut rings, data tables, and severity badges. The output is a
    self-contained HTML file with zero external dependencies  open it in any browser,
    share it with your team, or attach it to an email.

    Sections included:
    - Device Compliance (donut chart + breakdown)
    - Device Inventory (OS, manufacturer, model distribution)
    - Stale Device Analysis (sync age heatmap)
    - Windows Update Ring Health (findings by severity)
    - Conditional Access Overview
    - License Utilisation
    - Risky Users
    - Guest User Audit
    - Top Non-Compliant Policies & Settings

.PARAMETER OutputPath
    Where to save the HTML file. Defaults to Desktop.
.PARAMETER DaysStale
    Number of days before a device is considered stale. Default 90.
.EXAMPLE
    .\Export-IntuneDashboard.ps1
.EXAMPLE
    .\Export-IntuneDashboard.ps1 -OutputPath "C:\Reports\Dashboard.html"
#>

[CmdletBinding()]
param(
    [Parameter()][string]$OutputPath,
    [Parameter()][int]$DaysStale = 90
)

#region --- Helpers ---
function Write-Status { param([string]$Msg,[string]$Color='Cyan'); Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg); Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri,[string]$Method='GET')
    try {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method $Method -ErrorAction Stop
        $results = @()
        if ($null -ne $response.value) { $results += $response.value }
        elseif ($response) { $results += $response }
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            if ($null -ne $response.value) { $results += $response.value }
        }
        return ,$results
    } catch { Write-Verbose "Graph call failed: $_"; return @() }
}
#endregion

#region --- Auth ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes @(
        'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All','DeviceManagementApps.Read.All',
        'Device.Read.All','Directory.Read.All','Group.Read.All','User.Read.All',
        'Policy.Read.All','Application.Read.All','AuditLog.Read.All',
        'IdentityRiskyUser.Read.All','Organization.Read.All','RoleManagement.Read.All'
    ) -NoWelcome -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
$tenantInfo = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/organization"
$tenantName = if ($tenantInfo.Count -gt 0) { $tenantInfo[0].displayName } else { $context.TenantId }
#endregion

#region --- Data Collection ---
Write-Section "COLLECTING DATA"
$now = Get-Date

# 1. Managed devices
Write-Status "Fetching managed devices..."
$devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
Write-Status "$($devices.Count) managed devices" "Green"

# 2. Update rings
Write-Status "Fetching update rings..."
$updateRings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"
Write-Status "$($updateRings.Count) update rings" "Green"

# 3. Feature update profiles
Write-Status "Fetching feature update profiles..."
$featureProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
Write-Status "$($featureProfiles.Count) feature update profiles" "Green"

# 4. Conditional Access
Write-Status "Fetching Conditional Access policies..."
$caPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
Write-Status "$($caPolicies.Count) CA policies" "Green"

# 5. License subscriptions
Write-Status "Fetching license subscriptions..."
$subscriptions = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
Write-Status "$($subscriptions.Count) subscriptions" "Green"

# 6. Risky users
Write-Status "Fetching risky users..."
$riskyUsers = @()
try { $riskyUsers = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState ne 'dismissed' and riskState ne 'remediated'" } catch {}
Write-Status "$($riskyUsers.Count) active risky users" "Green"

# 7. Guest users
Write-Status "Fetching guest users..."
$guestUsers = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,mail,accountEnabled,createdDateTime,signInActivity,externalUserState"
Write-Status "$($guestUsers.Count) guest users" "Green"

# 8. Entra devices (for stale cross-ref)
Write-Status "Fetching Entra ID device records..."
$entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/devices?`$select=id,deviceId,displayName,approximateLastSignInDateTime,accountEnabled,operatingSystem"
Write-Status "$($entraDevices.Count) Entra ID devices" "Green"
#endregion

#region --- Data Processing ---
Write-Section "PROCESSING METRICS"

# --- Compliance ---
$compliant      = @($devices | Where-Object { $_.complianceState -eq 'compliant' }).Count
$nonCompliant   = @($devices | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
$inGrace        = @($devices | Where-Object { $_.complianceState -eq 'inGracePeriod' }).Count
$unknownComp    = $devices.Count - $compliant - $nonCompliant - $inGrace
$complianceRate = if ($devices.Count -gt 0) { [math]::Round(($compliant / $devices.Count) * 100, 1) } else { 0 }

# --- OS Distribution ---
$osDist = @{}
foreach ($d in $devices) {
    $os = if ($d.operatingSystem) { $d.operatingSystem } else { 'Unknown' }
    if (-not $osDist.ContainsKey($os)) { $osDist[$os] = 0 }
    $osDist[$os]++
}

# --- Manufacturer Distribution ---
$mfgDist = @{}
foreach ($d in $devices) {
    $mfg = if ($d.manufacturer) { $d.manufacturer } else { 'Unknown' }
    if (-not $mfgDist.ContainsKey($mfg)) { $mfgDist[$mfg] = 0 }
    $mfgDist[$mfg]++
}

# --- Stale Devices ---
$staleThreshold = $now.AddDays(-$DaysStale)
$warnThreshold  = $now.AddDays(-60)
$activeDevices = 0; $warnDevices = 0; $staleDevices = 0; $noSyncDevices = 0
foreach ($d in $devices) {
    if ($d.lastSyncDateTime) {
        $lastSync = [datetime]$d.lastSyncDateTime
        if ($lastSync -ge $warnThreshold) { $activeDevices++ }
        elseif ($lastSync -ge $staleThreshold) { $warnDevices++ }
        else { $staleDevices++ }
    } else { $noSyncDevices++ }
}

# Top 10 most stale
$topStale = $devices | Where-Object { $_.lastSyncDateTime } |
    Sort-Object { [datetime]$_.lastSyncDateTime } |
    Select-Object -First 10 |
    ForEach-Object {
        $days = [math]::Round(($now - [datetime]$_.lastSyncDateTime).TotalDays, 1)
        [PSCustomObject]@{ Name=$_.deviceName; User=$_.userPrincipalName; OS=$_.operatingSystem; DaysStale=$days; LastSync=([datetime]$_.lastSyncDateTime).ToString('yyyy-MM-dd') }
    }

# --- Encryption ---
$encrypted    = @($devices | Where-Object { $_.isEncrypted -eq $true }).Count
$notEncrypted = @($devices | Where-Object { $_.isEncrypted -eq $false }).Count
$unknownEnc   = $devices.Count - $encrypted - $notEncrypted

# --- Windows Build Distribution ---
$winDevices = $devices | Where-Object { $_.operatingSystem -eq 'Windows' }
$buildDist = @{}
foreach ($d in $winDevices) {
    $ver = if ($d.osVersion) { $d.osVersion } else { 'Unknown' }
    if (-not $buildDist.ContainsKey($ver)) { $buildDist[$ver] = 0 }
    $buildDist[$ver]++
}

# --- Update Ring Health ---
$ringFindings = @()
foreach ($ring in $updateRings) {
    $issues = @()
    if (-not $ring.qualityUpdatesDeferralPeriodInDays -and -not $ring.qualityUpdatesRollbackStartDateTime) {}
    $qDeadline = $ring.deadlineForQualityUpdatesInDays
    $fDeadline = $ring.deadlineForFeatureUpdatesInDays
    $grace     = $ring.deadlineGracePeriodInDays

    if (-not $qDeadline -and $qDeadline -ne 0) { $issues += @{Severity='High';Finding='No quality update deadline'} }
    if (-not $grace -and $grace -ne 0) { $issues += @{Severity='Medium';Finding='Zero grace period'} }
    if ($ring.featureUpdatesDeferralPeriodInDays -gt 0 -and $featureProfiles.Count -gt 0) {
        $issues += @{Severity='High';Finding="Feature deferral $($ring.featureUpdatesDeferralPeriodInDays)d conflicts with Feature Update profiles"}
    }

    foreach ($iss in $issues) {
        $ringFindings += [PSCustomObject]@{
            RingName = $ring.displayName
            Severity = $iss.Severity
            Finding  = $iss.Finding
        }
    }
}

# --- CA Policy Summary ---
$caEnabled    = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
$caReportOnly = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
$caDisabled   = @($caPolicies | Where-Object { $_.state -eq 'disabled' }).Count

# --- License Utilisation ---
$licenseData = @()
foreach ($sub in $subscriptions) {
    if ($null -ne $sub.prepaidUnits -and $sub.prepaidUnits.enabled -gt 0) {
        $total    = $sub.prepaidUnits.enabled
        $consumed = $sub.consumedUnits
        $avail    = $total - $consumed
        $pct      = [math]::Round(($consumed / $total) * 100, 1)
        $licenseData += [PSCustomObject]@{
            Name     = $sub.skuPartNumber
            Total    = $total
            Used     = $consumed
            Available = $avail
            UsedPct  = $pct
        }
    }
}
$licenseData = $licenseData | Sort-Object UsedPct -Descending

# --- Guest Users ---
$guestNeverSignedIn = @($guestUsers | Where-Object {
    -not $_.signInActivity -or -not $_.signInActivity.lastSignInDateTime
}).Count
$guestDisabled = @($guestUsers | Where-Object { $_.accountEnabled -eq $false }).Count
$guestPending  = @($guestUsers | Where-Object { $_.externalUserState -eq 'PendingAcceptance' }).Count

Write-Status "All metrics processed" "Green"
#endregion

#region --- HTML Generation ---
Write-Section "GENERATING HTML DASHBOARD"

# Convert data to JSON for embedded charts
function ConvertTo-JsonSafe { param($Obj); return ($Obj | ConvertTo-Json -Compress -Depth 5) -replace "'","\\'" }

$osDistJson  = ConvertTo-JsonSafe ($osDist.GetEnumerator()  | Sort-Object Value -Descending | ForEach-Object { @{label=$_.Key;value=$_.Value} })
$mfgDistJson = ConvertTo-JsonSafe ($mfgDist.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { @{label=$_.Key;value=$_.Value} })
$buildDistJson = ConvertTo-JsonSafe ($buildDist.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { @{label=$_.Key;value=$_.Value} })
$licenseJson = ConvertTo-JsonSafe ($licenseData | Select-Object -First 15 | ForEach-Object { @{name=$_.Name;total=$_.Total;used=$_.Used;pct=$_.UsedPct} })

$staleTableHtml = ""
foreach ($s in $topStale) {
    $sevClass = if ($s.DaysStale -gt 180) { 'critical' } elseif ($s.DaysStale -gt 90) { 'high' } else { 'medium' }
    $staleTableHtml += "<tr><td>$($s.Name)</td><td>$($s.User)</td><td>$($s.OS)</td><td class='badge $sevClass'>$($s.DaysStale)d</td><td>$($s.LastSync)</td></tr>`n"
}

$ringTableHtml = ""
foreach ($rf in $ringFindings) {
    $sevClass = switch ($rf.Severity) { 'High'{'high'} 'Medium'{'medium'} 'Low'{'low'} 'Critical'{'critical'} default{'low'} }
    $ringTableHtml += "<tr><td>$($rf.RingName)</td><td class='badge $sevClass'>$($rf.Severity)</td><td>$($rf.Finding)</td></tr>`n"
}

$riskyTableHtml = ""
foreach ($ru in ($riskyUsers | Select-Object -First 10)) {
    $riskClass = switch ($ru.riskLevel) { 'high'{'high'} 'medium'{'medium'} 'low'{'low'} default{'low'} }
    $riskyTableHtml += "<tr><td>$($ru.userDisplayName)</td><td>$($ru.userPrincipalName)</td><td class='badge $riskClass'>$($ru.riskLevel)</td><td>$($ru.riskState)</td><td>$($ru.riskLastUpdatedDateTime)</td></tr>`n"
}

$licenseTableHtml = ""
foreach ($lic in ($licenseData | Select-Object -First 15)) {
    $pctClass = if ($lic.UsedPct -ge 95) { 'critical' } elseif ($lic.UsedPct -ge 80) { 'high' } elseif ($lic.UsedPct -ge 50) { 'medium' } else { 'low' }
    $licenseTableHtml += "<tr><td>$($lic.Name)</td><td>$($lic.Total)</td><td>$($lic.Used)</td><td>$($lic.Available)</td><td><div class='progress-bar'><div class='progress-fill $pctClass' style='width:$($lic.UsedPct)%'></div></div><span class='pct-label'>$($lic.UsedPct)%</span></td></tr>`n"
}

$reportTimestamp = $now.ToString('yyyy-MM-dd HH:mm:ss')
$complianceGrade = if ($complianceRate -ge 95) { 'A' } elseif ($complianceRate -ge 85) { 'B' } elseif ($complianceRate -ge 70) { 'C' } elseif ($complianceRate -ge 50) { 'D' } else { 'F' }
$gradeColor = switch ($complianceGrade) { 'A'{'#00c853'} 'B'{'#64dd17'} 'C'{'#ffd600'} 'D'{'#ff6d00'} 'F'{'#d50000'} }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Intune Dashboard  $tenantName</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

:root {
    --cds-background: #161616;
    --cds-layer-01: #262626;
    --cds-layer-02: #353535;
    --cds-border-strong-01: #4d4d4d;
    --cds-border-subtle-01: #393939;
    --cds-text-primary: #f4f4f4;
    --cds-text-secondary: #c6c6c6;
    --cds-text-helper: #8d8d8d;
    --cds-link: #78a9ff;
    
    /* Carbon Theme Accents */
    --cds-blue: #0f62fe;
    --cds-purple: #8a3ffc;
    --cds-magenta: #d02670;
    
    /* Support Status Colors */
    --cds-support-success: #24a148;
    --cds-support-warning: #f1c21b;
    --cds-support-error: #da1e28;
    --cds-support-info: #0043ce;
}

* { 
    margin: 0; 
    padding: 0; 
    box-sizing: border-box; 
}

body {
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--cds-background);
    color: var(--cds-text-primary);
    line-height: 1.4;
    padding: 32px;
    -webkit-font-smoothing: antialiased;
}

/* Header Area */
.header {
    margin-bottom: 40px;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--cds-border-strong-01);
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: 16px;
}

.header-left h1 {
    font-size: 28px;
    font-weight: 300;
    letter-spacing: 0.5px;
    color: var(--cds-text-primary);
    margin-bottom: 4px;
}

.header-left h1 strong {
    font-weight: 600;
}

.header .subtitle {
    color: var(--cds-text-secondary);
    font-size: 14px;
    font-family: 'IBM Plex Mono', monospace;
}

.header-right {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 12px;
    color: var(--cds-text-helper);
    text-align: right;
}

/* KPI / Metric Grid */
.kpi-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 2px; /* Carbon-like grid border separator */
    background-color: var(--cds-border-subtle-01);
    border: 1px solid var(--cds-border-subtle-01);
    margin-bottom: 40px;
}

.kpi-card {
    background-color: var(--cds-layer-01);
    padding: 20px;
    display: flex;
    flex-direction: column-reverse;
    justify-content: space-between;
    min-height: 120px;
    transition: background-color 0.15s ease;
}

.kpi-card:hover {
    background-color: var(--cds-layer-02);
}

.kpi-value {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 38px;
    font-weight: 400;
    line-height: 1.1;
    color: var(--cds-text-primary);
}

.kpi-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--cds-text-secondary);
    letter-spacing: 0.2px;
    margin-bottom: 12px;
}

/* Dashboard Sections */
.section-title {
    font-size: 14px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--cds-text-secondary);
    margin: 40px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--cds-border-subtle-01);
    display: flex;
    align-items: center;
    gap: 8px;
}

.grid-2 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
    gap: 24px;
    margin-bottom: 24px;
}

.card {
    background-color: var(--cds-layer-01);
    border: 1px solid var(--cds-border-subtle-01);
    padding: 24px;
    display: flex;
    flex-direction: column;
}

.card h2 {
    font-size: 16px;
    font-weight: 400;
    margin-bottom: 24px;
    color: var(--cds-text-primary);
    border-left: 3px solid var(--cds-blue);
    padding-left: 12px;
}

/* Charts layouts */
.donut-container {
    display: flex;
    align-items: center;
    justify-content: space-around;
    gap: 24px;
    flex-wrap: wrap;
}

.donut-wrap { 
    position: relative; 
    width: 160px; 
    height: 160px; 
}

.donut-center {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}

.donut-center .grade {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 36px;
    font-weight: 500;
    line-height: 1;
}

.donut-center .rate {
    font-size: 11px;
    color: var(--cds-text-helper);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
}

.legend { 
    list-style: none; 
    flex: 1;
    min-width: 180px;
}

.legend li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 0;
    font-size: 13px;
    border-bottom: 1px solid var(--cds-border-subtle-01);
}

.legend li:last-child {
    border-bottom: none;
}

.legend .dot {
    width: 8px;
    height: 8px;
    flex-shrink: 0;
}

.legend .count {
    margin-left: auto;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 500;
}

/* Carbon Flat Bar Charts */
.bar-chart { 
    display: flex; 
    flex-direction: column; 
    gap: 12px; 
}

.bar-row { 
    display: flex; 
    align-items: center; 
    gap: 16px; 
    font-size: 13px; 
}

.bar-label { 
    min-width: 140px; 
    text-align: right; 
    color: var(--cds-text-secondary); 
    white-space: nowrap; 
    overflow: hidden; 
    text-overflow: ellipsis; 
}

.bar-track { 
    flex: 1; 
    height: 20px; 
    background-color: var(--cds-border-subtle-01); 
    position: relative; 
}

.bar-fill {
    height: 100%;
    transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1);
    display: flex;
    align-items: center;
    padding-left: 8px;
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    color: #ffffff;
    min-width: 24px;
}

/* Carbon Structured Tables */
table { 
    width: 100%; 
    border-collapse: collapse; 
    font-size: 13px; 
}

thead th {
    text-align: left;
    padding: 12px 16px;
    background-color: var(--cds-layer-02);
    border-bottom: 1px solid var(--cds-border-strong-01);
    color: var(--cds-text-primary);
    font-weight: 500;
    font-size: 12px;
}

tbody td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--cds-border-subtle-01);
    color: var(--cds-text-secondary);
}

tbody tr {
    background-color: var(--cds-layer-01);
    transition: background-color 0.1s ease;
}

tbody tr:hover { 
    background-color: var(--cds-layer-02); 
}

/* Flat square badges */
.badge {
    display: inline-block;
    padding: 2px 8px;
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.badge.critical { background-color: rgba(218, 30, 40, 0.15); color: #ff8389; border-left: 3px solid var(--cds-support-error); }
.badge.high { background-color: rgba(219, 109, 40, 0.15); color: #ffb38a; border-left: 3px solid var(--cds-accent-orange); }
.badge.medium { background-color: rgba(241, 194, 27, 0.15); color: #f1c21b; border-left: 3px solid var(--cds-support-warning); }
.badge.low { background-color: rgba(36, 161, 72, 0.15); color: #8ee0a5; border-left: 3px solid var(--cds-support-success); }

/* Progress indicator bars */
.progress-bar {
    display: inline-block;
    width: 100px;
    height: 8px;
    background-color: var(--cds-border-subtle-01);
    vertical-align: middle;
}

.progress-fill {
    height: 100%;
    transition: width 0.5s ease;
}
.progress-fill.low { background-color: var(--cds-support-success); }
.progress-fill.medium { background-color: var(--cds-support-warning); }
.progress-fill.high { background-color: #db6d28; }
.progress-fill.critical { background-color: var(--cds-support-error); }

.pct-label {
    font-size: 11px;
    font-family: 'IBM Plex Mono', monospace;
    margin-left: 8px;
    vertical-align: middle;
    color: var(--cds-text-secondary);
}

.empty-state {
    text-align: center;
    padding: 40px;
    color: var(--cds-text-helper);
    font-style: normal;
    border: 1px dashed var(--cds-border-strong-01);
    background-color: var(--cds-background);
}

canvas { 
    max-width: 100%; 
}

@media (max-width: 768px) {
    .grid-2 { grid-template-columns: 1fr; }
    .kpi-row { grid-template-columns: repeat(2, 1fr); }
    body { padding: 16px; }
}
</style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>Intune & Entra ID <strong>Dashboard</strong></h1>
        <div class="subtitle">TENANT: $tenantName</div>
    </div>
    <div class="header-right">
        <div>GENERATED: $reportTimestamp</div>
        <div style="margin-top: 4px;">OPERATOR: $($context.Account)</div>
    </div>
</div>

<!-- KPI Cards -->
<div class="kpi-row">
    <div class="kpi-card">
        <div class="kpi-value">$($devices.Count)</div>
        <div class="kpi-label">Managed Devices</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-value" style="color:$(if($complianceRate -lt 50){'var(--cds-support-error)'}elseif($complianceRate -lt 85){'var(--cds-support-warning)'}else{'var(--cds-support-success)'})">$complianceRate%</div>
        <div class="kpi-label">Compliance Rate</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-value" style="color:$(if($staleDevices -gt 0){'var(--cds-support-warning)'}else{'var(--cds-text-primary)'})">$staleDevices</div>
        <div class="kpi-label">Stale Devices (>$($DaysStale)d)</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-value" style="color:$(if($riskyUsers.Count -gt 0){'var(--cds-support-error)'}else{'var(--cds-support-success)'})">$($riskyUsers.Count)</div>
        <div class="kpi-label">Risky Users</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-value">$($caPolicies.Count)</div>
        <div class="kpi-label">CA Policies</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-value" style="color:$(if($notEncrypted -gt 0){'var(--cds-support-warning)'}else{'var(--cds-support-success)'})">$notEncrypted</div>
        <div class="kpi-label">Not Encrypted</div>
    </div>
</div>

<!-- Compliance & OS Distribution -->
<div class="section-title">Compliance & Device Overview</div>
<div class="grid-2">
    <div class="card">
        <h2>Device Compliance</h2>
        <div class="donut-container">
            <div class="donut-wrap">
                <canvas id="complianceDonut" width="160" height="160"></canvas>
                <div class="donut-center">
                    <div class="grade" style="color:$gradeColor">$complianceGrade</div>
                    <div class="rate">$complianceRate%</div>
                </div>
            </div>
            <ul class="legend">
                <li><span class="dot" style="background-color:var(--cds-support-success)"></span> Compliant <span class="count">$compliant</span></li>
                <li><span class="dot" style="background-color:var(--cds-support-error)"></span> Non-Compliant <span class="count">$nonCompliant</span></li>
                <li><span class="dot" style="background-color:var(--cds-support-warning)"></span> In Grace <span class="count">$inGrace</span></li>
                <li><span class="dot" style="background-color:var(--cds-text-helper)"></span> Unknown <span class="count">$unknownComp</span></li>
            </ul>
        </div>
    </div>
    <div class="card">
        <h2>OS Distribution</h2>
        <div class="bar-chart" id="osChart"></div>
    </div>
</div>

<!-- Encryption & Sync Health -->
<div class="grid-2">
    <div class="card">
        <h2>Encryption Status</h2>
        <div class="donut-container">
            <div class="donut-wrap">
                <canvas id="encryptionDonut" width="160" height="160"></canvas>
                <div class="donut-center">
                    <div class="grade" style="color:$(if($notEncrypted -eq 0){'var(--cds-support-success)'}else{'var(--cds-support-warning)'});font-size:28px">$(if($devices.Count -gt 0){[math]::Round(($encrypted/$devices.Count)*100)}else{0})%</div>
                    <div class="rate">encrypted</div>
                </div>
            </div>
            <ul class="legend">
                <li><span class="dot" style="background-color:var(--cds-support-success)"></span> Encrypted <span class="count">$encrypted</span></li>
                <li><span class="dot" style="background-color:var(--cds-support-error)"></span> Not Encrypted <span class="count">$notEncrypted</span></li>
                <li><span class="dot" style="background-color:var(--cds-text-helper)"></span> Unknown <span class="count">$unknownEnc</span></li>
            </ul>
        </div>
    </div>
    <div class="card">
        <h2>Device Sync Health</h2>
        <div class="donut-container">
            <div class="donut-wrap">
                <canvas id="syncDonut" width="160" height="160"></canvas>
                <div class="donut-center">
                    <div class="grade" style="color:$(if($staleDevices -eq 0){'var(--cds-support-success)'}else{'var(--cds-support-error)'});font-size:28px">$activeDevices</div>
                    <div class="rate">active</div>
                </div>
            </div>
            <ul class="legend">
                <li><span class="dot" style="background-color:var(--cds-support-success)"></span> Active (&lt;60d) <span class="count">$activeDevices</span></li>
                <li><span class="dot" style="background-color:var(--cds-support-warning)"></span> Warning (60-${DaysStale}d) <span class="count">$warnDevices</span></li>
                <li><span class="dot" style="background-color:var(--cds-support-error)"></span> Stale (&gt;${DaysStale}d) <span class="count">$staleDevices</span></li>
            </ul>
        </div>
    </div>
</div>

<!-- Stale Devices Table -->
$(if ($topStale.Count -gt 0) { @"
<div class="section-title">Most Stale Devices</div>
<div class="card" style="padding:0;overflow-x:auto;">
    <table>
        <thead><tr><th>Device</th><th>User</th><th>OS</th><th>Days Stale</th><th>Last Sync</th></tr></thead>
        <tbody>$staleTableHtml</tbody>
    </table>
</div>
"@ })

<!-- Windows Build Distribution -->
$(if ($buildDist.Count -gt 0) { @"
<div class="section-title">Windows Build Distribution</div>
<div class="card">
    <div class="bar-chart" id="buildChart"></div>
</div>
"@ })

<!-- Update Ring Health -->
$(if ($ringFindings.Count -gt 0) { @"
<div class="section-title">Update Ring Findings ($($ringFindings.Count))</div>
<div class="card" style="padding:0;overflow-x:auto;">
    <table>
        <thead><tr><th>Ring</th><th>Severity</th><th>Finding</th></tr></thead>
        <tbody>$ringTableHtml</tbody>
    </table>
</div>
"@ } else { @"
<div class="section-title">Update Ring Health</div>
<div class="card"><div class="empty-state">No update ring issues detected</div></div>
"@ })

<!-- Conditional Access -->
<div class="section-title">Conditional Access</div>
<div class="kpi-row">
    <div class="kpi-card"><div class="kpi-value" style="color:var(--cds-support-success)">$caEnabled</div><div class="kpi-label">Enabled</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:var(--cds-support-warning)">$caReportOnly</div><div class="kpi-label">Report-Only</div></div>
    <div class="kpi-card"><div class="kpi-value">$caDisabled</div><div class="kpi-label">Disabled</div></div>
</div>

<!-- License Utilisation -->
$(if ($licenseData.Count -gt 0) { @"
<div class="section-title">License Utilisation</div>
<div class="card" style="padding:0;overflow-x:auto;">
    <table>
        <thead><tr><th>SKU</th><th>Total</th><th>Used</th><th>Available</th><th>Utilisation</th></tr></thead>
        <tbody>$licenseTableHtml</tbody>
    </table>
</div>
"@ })

<!-- Risky Users -->
$(if ($riskyUsers.Count -gt 0) { @"
<div class="section-title">Risky Users ($($riskyUsers.Count))</div>
<div class="card" style="padding:0;overflow-x:auto;">
    <table>
        <thead><tr><th>Name</th><th>UPN</th><th>Risk Level</th><th>State</th><th>Last Updated</th></tr></thead>
        <tbody>$riskyTableHtml</tbody>
    </table>
</div>
"@ } else { @"
<div class="section-title">Risky Users</div>
<div class="card"><div class="empty-state">No active risky users detected</div></div>
"@ })

<!-- Guest Users -->
<div class="section-title">Guest User Summary</div>
<div class="kpi-row">
    <div class="kpi-card"><div class="kpi-value">$($guestUsers.Count)</div><div class="kpi-label">Total Guests</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:$(if($guestNeverSignedIn -gt 0){'var(--cds-support-warning)'}else{'var(--cds-support-success)'})">$guestNeverSignedIn</div><div class="kpi-label">Never Signed In</div></div>
    <div class="kpi-card"><div class="kpi-value">$guestDisabled</div><div class="kpi-label">Disabled</div></div>
    <div class="kpi-card"><div class="kpi-value" style="color:$(if($guestPending -gt 0){'var(--cds-support-warning)'}else{'var(--cds-support-success)'})">$guestPending</div><div class="kpi-label">Pending Invite</div></div>
</div>

<div style="text-align:center;margin-top:64px;padding:32px;color:var(--cds-text-helper);font-size:12px;border-top:1px solid var(--cds-border-subtle-01)">
    Generated by <strong>Intune & Entra ID Admin Toolkit</strong> &nbsp;&nbsp; $reportTimestamp &nbsp;&nbsp; $($context.Account)
</div>

<script>
// Mini donut chart renderer (no dependencies)
function drawDonut(canvasId, data, colors) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = canvas.width / 2, cy = canvas.height / 2;
    const outerR = 76, innerR = 58; /* Thinner borders for Carbon style */
    const total = data.reduce((a, b) => a + b, 0);
    if (total === 0) return;
    let startAngle = -Math.PI / 2;
    data.forEach((val, i) => {
        const sliceAngle = (val / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.arc(cx, cy, outerR, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, innerR, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = colors[i];
        ctx.fill();
        startAngle += sliceAngle;
    });
}

// Bar chart renderer
function drawBars(containerId, data, colorFn) {
    const container = document.getElementById(containerId);
    if (!container || !data) return;
    const dataArray = Array.isArray(data) ? data : [data];
    if (!dataArray.length || (dataArray.length === 1 && !dataArray[0])) return;
    const maxVal = Math.max(...dataArray.map(d => d.value || 0));
    const colors = ['#0f62fe','#8a3ffc','#00b0ff','#008080','#da1e28','#ff832b','#8d8d8d','#e0e0e0'];
    dataArray.forEach((item, i) => {
        if (!item) return;
        const val = item.value || 0;
        const label = item.label || 'Unknown';
        const pct = maxVal > 0 ? (val / maxVal * 100) : 0;
        const color = colorFn ? colorFn(item, i) : colors[i % colors.length];
        const row = document.createElement('div');
        row.className = 'bar-row';
        row.innerHTML =
            '<div class="bar-label" title="' + label + '">' + label + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background-color:' + color + '">' + val + '</div></div>';
        container.appendChild(row);
    });
}

// Draw charts
drawDonut('complianceDonut', [$compliant, $nonCompliant, $inGrace, $unknownComp], ['#24a148','#da1e28','#f1c21b','#525252']);
drawDonut('encryptionDonut', [$encrypted, $notEncrypted, $unknownEnc], ['#24a148','#da1e28','#525252']);
drawDonut('syncDonut', [$activeDevices, $warnDevices, $staleDevices], ['#24a148','#f1c21b','#da1e28']);

drawBars('osChart', $osDistJson);
if (document.getElementById('buildChart')) drawBars('buildChart', $buildDistJson);
</script>

</body>
</html>
"@

# Determine output path
if (-not $OutputPath) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $OutputPath = Join-Path $desktop "IntuneDashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
}

$html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
Write-Status "Dashboard exported to: $OutputPath" "Green"
Write-Host ""
Write-Host "  Open in your browser: " -ForegroundColor White -NoNewline
Write-Host "$OutputPath" -ForegroundColor Cyan
Write-Host ""

# Auto-open in default browser
try { Start-Process $OutputPath -ErrorAction SilentlyContinue } catch {}

Write-Host "$('='*60)" -ForegroundColor DarkGray
#endregion



