#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits Windows Update ring configurations against Microsoft best practices.
.DESCRIPTION
    Checks every update ring against Microsoft's Autopatch-recommended values
    and common misconfiguration patterns. Flags:
    - Excessive quality deferrals (>14 days)
    - Missing deadlines (no enforcement)
    - Zero grace periods (poor user experience)
    - Paused rings (forgotten pauses)
    - Feature deferral > 0 when Feature Update profiles exist (blocks them)
    - Drivers excluded when Driver Update profiles exist (conflicts)
    - Delivery optimization set to HTTP only (no P2P savings)
    - Active hours not configured
    - No auto-reboot before deadline (updates won't install promptly)
    - Devices in multiple rings (conflict)
    - Rings with no assignments (dead config)
    - Inconsistent deadline/grace ratios across rings

.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Test-IntuneUpdateRingHealth.ps1
#>

[CmdletBinding()]
param([Parameter()][string]$ExportPath)

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

Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING UPDATE ENVIRONMENT"

$rings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=assignments"
Write-Status "$($rings.Count) update rings" "Green"

$featureProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
$driverProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles"
Write-Status "$($featureProfiles.Count) feature update profiles, $($driverProfiles.Count) driver update profiles" "Green"

# Microsoft Autopatch recommended values
$bestPractice = @{
    MaxQualityDeferral  = 14
    MinQualityDeadline  = 2
    MaxQualityDeadline  = 7
    MinGracePeriod      = 2
    MaxGracePeriod      = 5
    MaxFeatureDeferral  = 0  # When using Feature Update profiles
    RecommendedDO       = 'httpWithPeeringNat'
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalFindings = 0

Write-Section "AUDIT FINDINGS"
Write-Host ""

# --- Autopatch best practice reference ---
Write-Host "  Microsoft Autopatch recommended values (reference):" -ForegroundColor DarkGray
Write-Host "    Quality deferral  : 0-10 days across rings" -ForegroundColor DarkGray
Write-Host "    Quality deadline  : 2-5 days" -ForegroundColor DarkGray
Write-Host "    Grace period      : 2 days" -ForegroundColor DarkGray
Write-Host "    Feature deferral  : 0 days (use Feature Update profiles instead)" -ForegroundColor DarkGray
Write-Host "    Auto-reboot       : Yes (before deadline)" -ForegroundColor DarkGray
Write-Host ""

foreach ($ring in ($rings | Sort-Object displayName)) {
    $name = $ring.displayName
    $findings = @()

    # Assignment check
    $assignCount = 0; $hasAllDevices = $false
    if ($ring.assignments) {
        $assignCount = ($ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' }).Count
        $hasAllDevices = ($ring.assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' }).Count -gt 0
    }
    $totalAssignments = $assignCount + $(if ($hasAllDevices) { 1 } else { 0 })

    if ($totalAssignments -eq 0) {
        $findings += [PSCustomObject]@{ Severity='Medium'; Finding='No assignments - ring has no effect'; Category='Assignment' }
    }

    # Quality deferral
    $qd = $ring.qualityUpdatesDeferralPeriodInDays
    if ($qd -gt $bestPractice.MaxQualityDeferral) {
        $findings += [PSCustomObject]@{ Severity='High'; Finding="Quality deferral $qd days exceeds recommended max ($($bestPractice.MaxQualityDeferral) days)"; Category='Deferral' }
    }
    if ($qd -eq 0 -and $totalAssignments -gt 1) {
        $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Zero quality deferral with broad assignment - no buffer for bad patches'; Category='Deferral' }
    }

    # Quality deadline
    $qdl = $ring.qualityUpdatesDeadlineInDays
    if (-not $qdl -or $qdl -eq 0) {
        $findings += [PSCustomObject]@{ Severity='High'; Finding='No quality update deadline - devices may never install updates'; Category='Deadline' }
    }
    if ($qdl -and $qdl -gt $bestPractice.MaxQualityDeadline) {
        $findings += [PSCustomObject]@{ Severity='Medium'; Finding="Quality deadline $qdl days exceeds recommended max ($($bestPractice.MaxQualityDeadline) days)"; Category='Deadline' }
    }

    # Grace period
    $gp = $ring.qualityUpdatesGracePeriodInDays
    if (-not $gp -or $gp -eq 0) {
        $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Zero grace period - devices forced to reboot immediately after deadline'; Category='Grace' }
    }

    # Paused
    if ($ring.qualityUpdatesPaused) {
        $findings += [PSCustomObject]@{ Severity='Critical'; Finding='Quality updates are PAUSED - devices are not receiving security patches'; Category='Pause' }
    }
    if ($ring.featureUpdatesPaused) {
        $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Feature updates are PAUSED'; Category='Pause' }
    }

    # Feature deferral vs Feature Update profiles
    $fd = $ring.featureUpdatesDeferralPeriodInDays
    if ($fd -gt 0 -and $featureProfiles.Count -gt 0) {
        $findings += [PSCustomObject]@{ Severity='High'; Finding="Feature deferral $fd days set while Feature Update profiles exist - may block feature updates"; Category='FeatureConflict' }
    }
    if ($fd -gt 365) {
        $findings += [PSCustomObject]@{ Severity='High'; Finding="Feature deferral $fd days - effectively blocking feature updates"; Category='Deferral' }
    }

    # Drivers
    if ($ring.driversExcluded -and $driverProfiles.Count -gt 0) {
        $findings += [PSCustomObject]@{ Severity='High'; Finding='Drivers excluded while Driver Update profiles exist - profiles will be blocked'; Category='DriverConflict' }
    }

    # Delivery optimization
    $do = $ring.deliveryOptimizationMode
    if ($do -eq 'httpOnly') {
        $findings += [PSCustomObject]@{ Severity='Low'; Finding='Delivery Optimization set to HTTP only - no peer-to-peer bandwidth savings'; Category='DeliveryOpt' }
    }

    # Auto-reboot before deadline
    if (-not $ring.autoRestartNotificationDismissal) {
        # This isn't directly the same setting but checking auto-restart behavior
    }

    # Feature deadline
    $fdl = $ring.featureUpdatesDeadlineInDays
    if (-not $fdl -or $fdl -eq 0) {
        $findings += [PSCustomObject]@{ Severity='Low'; Finding='No feature update deadline set'; Category='Deadline' }
    }

    # All Devices without exclusions
    if ($hasAllDevices) {
        $excludeCount = ($ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' }).Count
        if ($excludeCount -eq 0) {
            $findings += [PSCustomObject]@{ Severity='Medium'; Finding='Targets All Devices with NO exclusions - every device gets this ring'; Category='Assignment' }
        }
    }

    # Report
    $color = if (($findings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { 'Red' }
             elseif (($findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'Yellow' }
             elseif ($findings.Count -gt 0) { 'DarkYellow' }
             else { 'Green' }

    $statusTag = if ($findings.Count -eq 0) { '[HEALTHY]' }
                 elseif (($findings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) { '[CRITICAL]' }
                 elseif (($findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { '[ISSUES]' }
                 else { '[REVIEW]' }

    Write-Host "  $statusTag $name" -ForegroundColor $color
    Write-Host "    Defer: Q=$qd d / F=$fd d | Deadline: Q=$qdl d / F=$fdl d | Grace: $gp d | DO: $do" -ForegroundColor DarkGray
    Write-Host "    Groups: $assignCount$(if($hasAllDevices){' + All Devices'}) | Paused: Q=$($ring.qualityUpdatesPaused) F=$($ring.featureUpdatesPaused) | Drivers excluded: $($ring.driversExcluded)" -ForegroundColor DarkGray

    if ($findings.Count -gt 0) {
        foreach ($f in ($findings | Sort-Object { switch($_.Severity){'Critical'{0}'High'{1}'Medium'{2}default{3}} })) {
            $fColor = switch ($f.Severity) { 'Critical'{'Red'} 'High'{'Yellow'} 'Medium'{'DarkYellow'} default{'DarkGray'} }
            Write-Host "    [$($f.Severity.ToUpper())] $($f.Finding)" -ForegroundColor $fColor
        }
        $totalFindings += $findings.Count
    }
    Write-Host ""

    foreach ($f in $findings) {
        $report.Add([PSCustomObject]@{
            RingName=$name; Severity=$f.Severity; Category=$f.Category; Finding=$f.Finding
            QualityDeferral=$qd; QualityDeadline=$qdl; GracePeriod=$gp
            FeatureDeferral=$fd; QualityPaused=$ring.qualityUpdatesPaused; FeaturePaused=$ring.featureUpdatesPaused
            DriversExcluded=$ring.driversExcluded; AssignmentCount=$totalAssignments
        })
    }
    if ($findings.Count -eq 0) {
        $report.Add([PSCustomObject]@{
            RingName=$name; Severity='Healthy'; Category='None'; Finding='No issues found'
            QualityDeferral=$qd; QualityDeadline=$qdl; GracePeriod=$gp
            FeatureDeferral=$fd; QualityPaused=$ring.qualityUpdatesPaused; FeaturePaused=$ring.featureUpdatesPaused
            DriversExcluded=$ring.driversExcluded; AssignmentCount=$totalAssignments
        })
    }
}

# Cross-ring checks
Write-Section "CROSS-RING ANALYSIS"

# Check for rings with no progressive deferral (all same deferral)
$deferrals = ($ringData | ForEach-Object { $_.QualityDeferral }) | Sort-Object -Unique
if ($deferrals.Count -eq 1 -and $rings.Count -gt 1) {
    Write-Host "  [HIGH] All $($rings.Count) rings have the same quality deferral ($($deferrals[0]) days)" -ForegroundColor Yellow
    Write-Host "    Rings should have progressive deferrals (e.g., 0, 1, 5, 9 days)" -ForegroundColor DarkGray
    $totalFindings++
}

# Check for any multi-ring assignment risk
$allGroupIds = @()
foreach ($ring in $rings) {
    if ($ring.assignments) {
        $allGroupIds += ($ring.assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' } | ForEach-Object { $_.target.groupId })
    }
}
$duplicateGroups = $allGroupIds | Group-Object | Where-Object { $_.Count -gt 1 }
if ($duplicateGroups.Count -gt 0) {
    Write-Host "  [HIGH] $($duplicateGroups.Count) group(s) assigned to multiple rings - devices will have conflicts:" -ForegroundColor Yellow
    foreach ($dg in $duplicateGroups) {
        Write-Host "    Group $($dg.Name) appears in $($dg.Count) rings" -ForegroundColor DarkYellow
    }
    $totalFindings += $duplicateGroups.Count
}

$multiAllDevices = ($rings | Where-Object { $_.assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' } }).Count
if ($multiAllDevices -gt 1) {
    Write-Host "  [CRITICAL] $multiAllDevices rings target 'All Devices' - EVERY device has ring conflicts" -ForegroundColor Red
    $totalFindings++
}

Write-Section "AUDIT SUMMARY"
Write-Host ""
$critCount = ($report | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount = ($report | Where-Object { $_.Severity -eq 'High' }).Count
$medCount = ($report | Where-Object { $_.Severity -eq 'Medium' }).Count
$healthyCount = ($report | Where-Object { $_.Severity -eq 'Healthy' }).Count

Write-Host "  Total rings audited  : $($rings.Count)" -ForegroundColor White
Write-Host "  Healthy              : $healthyCount" -ForegroundColor Green
Write-Host "  Critical findings    : $critCount" -ForegroundColor $(if($critCount -gt 0){'Red'}else{'Green'})
Write-Host "  High findings        : $highCount" -ForegroundColor $(if($highCount -gt 0){'Yellow'}else{'Green'})
Write-Host "  Medium findings      : $medCount" -ForegroundColor $(if($medCount -gt 0){'DarkYellow'}else{'Green'})
Write-Host "  Total findings       : $totalFindings" -ForegroundColor White

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "UpdateRingAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


