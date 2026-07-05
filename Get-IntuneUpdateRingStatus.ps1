#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Compares all Windows Update ring configurations and their deployment status.
.DESCRIPTION
    Lists every Windows Update for Business ring with its deferral periods,
    deadlines, active hours, delivery optimization, and restart settings.
    Shows assignment counts and compares rings side by side so you can spot
    misconfigured or inconsistent rings.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneUpdateRingStatus.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','Group.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "WINDOWS UPDATE RINGS"
$rings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"
Write-Status "Found $($rings.Count) update rings" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($ring in ($rings | Sort-Object displayName)) {
    Write-Host ""
    Write-Host "  $($ring.displayName)" -ForegroundColor White
    Write-Host "  $('-' * $ring.displayName.Length)" -ForegroundColor DarkGray

    # Get assignment count
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($ring.id)/assignments"
    $groupCount = ($assignments | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' }).Count
    $hasAllDevices = ($assignments | Where-Object { $_.target.'@odata.type' -like '*allDevices*' }).Count -gt 0

    $qualityDefer = if ($null -ne $ring.qualityUpdatesDeferralPeriodInDays) { $ring.qualityUpdatesDeferralPeriodInDays } else { 'Not set' }
    $featureDefer = if ($null -ne $ring.featureUpdatesDeferralPeriodInDays) { $ring.featureUpdatesDeferralPeriodInDays } else { 'Not set' }
    $qualityPaused = $ring.qualityUpdatesPaused
    $featurePaused = $ring.featureUpdatesPaused
    $autoRestart = $ring.autoRestartNotificationDismissal
    $deadlineQuality = $ring.qualityUpdatesDeadlineInDays
    $deadlineFeature = $ring.featureUpdatesDeadlineInDays
    $graceQuality = $ring.qualityUpdatesGracePeriodInDays
    $graceFeature = $ring.featureUpdatesGracePeriodInDays
    $activeHoursStart = $ring.activeHoursStart
    $activeHoursEnd = $ring.activeHoursEnd
    $deliveryOpt = $ring.deliveryOptimizationMode
    $driversExcluded = $ring.driversExcluded
    $autoInstallBehavior = $ring.automaticUpdateMode

    Write-Host "    Quality deferral    : ${qualityDefer} days$(if($qualityPaused){' [PAUSED]'})" -ForegroundColor $(if($qualityPaused){'Red'}else{'White'})
    Write-Host "    Feature deferral    : ${featureDefer} days$(if($featurePaused){' [PAUSED]'})" -ForegroundColor $(if($featurePaused){'Red'}else{'White'})
    Write-Host "    Quality deadline    : $deadlineQuality days (grace: $graceQuality)" -ForegroundColor Gray
    Write-Host "    Feature deadline    : $deadlineFeature days (grace: $graceFeature)" -ForegroundColor Gray
    Write-Host "    Active hours        : $activeHoursStart - $activeHoursEnd" -ForegroundColor Gray
    Write-Host "    Drivers excluded    : $driversExcluded" -ForegroundColor Gray
    Write-Host "    Delivery opt mode   : $deliveryOpt" -ForegroundColor Gray
    Write-Host "    Auto-install mode   : $autoInstallBehavior" -ForegroundColor Gray
    Write-Host "    Assigned groups     : $groupCount$(if($hasAllDevices){' + All Devices'})" -ForegroundColor $(if($hasAllDevices){'DarkYellow'}else{'White'})

    $report.Add([PSCustomObject]@{
        RingName              = $ring.displayName
        QualityDeferralDays   = $qualityDefer
        FeatureDeferralDays   = $featureDefer
        QualityPaused         = $qualityPaused
        FeaturePaused         = $featurePaused
        QualityDeadlineDays   = $deadlineQuality
        FeatureDeadlineDays   = $deadlineFeature
        QualityGraceDays      = $graceQuality
        FeatureGraceDays      = $graceFeature
        ActiveHoursStart      = $activeHoursStart
        ActiveHoursEnd        = $activeHoursEnd
        DeliveryOptMode       = $deliveryOpt
        DriversExcluded       = $driversExcluded
        AutoInstallMode       = $autoInstallBehavior
        AssignedGroups        = $groupCount
        HasAllDevices         = $hasAllDevices
    })
}

# Alerts
Write-Section "UPDATE RING ALERTS"
$paused = $report | Where-Object { $_.QualityPaused -or $_.FeaturePaused }
if ($paused.Count -gt 0) {
    Write-Host ""
    Write-Host "  PAUSED RINGS ($($paused.Count)):" -ForegroundColor Red
    foreach ($p in $paused) {
        $which = @()
        if ($p.QualityPaused) { $which += 'Quality' }
        if ($p.FeaturePaused) { $which += 'Feature' }
        Write-Host "    $($p.RingName) - $($which -join ' + ') updates paused" -ForegroundColor DarkYellow
    }
}

$zeroDeferral = $report | Where-Object { $_.QualityDeferralDays -eq 0 -or $_.FeatureDeferralDays -eq 0 }
if ($zeroDeferral.Count -gt 0) {
    Write-Host ""
    Write-Host "  ZERO DEFERRAL RINGS ($($zeroDeferral.Count)):" -ForegroundColor Yellow
    foreach ($z in $zeroDeferral) {
        Write-Host "    $($z.RingName) - Quality: $($z.QualityDeferralDays)d, Feature: $($z.FeatureDeferralDays)d" -ForegroundColor DarkYellow
    }
}

$noDeadline = $report | Where-Object { -not $_.QualityDeadlineDays -and $_.AssignedGroups -gt 0 }
if ($noDeadline.Count -gt 0) {
    Write-Host ""
    Write-Host "  NO DEADLINE SET ($($noDeadline.Count)):" -ForegroundColor Yellow
    foreach ($nd in $noDeadline) {
        Write-Host "    $($nd.RingName) - no quality deadline enforced" -ForegroundColor DarkGray
    }
}

if ($paused.Count -eq 0 -and $zeroDeferral.Count -eq 0) {
    Write-Host "  No alerts. All rings look healthy." -ForegroundColor Green
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "UpdateRings_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


