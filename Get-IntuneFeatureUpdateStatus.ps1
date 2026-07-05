#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports feature update profile deployment status per device.
.DESCRIPTION
    For each feature update profile, shows deployment state per device:
    offered, pending download, downloading, installing, pending reboot,
    installed, cancelled, safeguard held, or error. Identifies devices
    blocked by safeguard holds and those stuck in pending states.

.PARAMETER ProfileName
    Optional. Filter to a specific feature update profile name.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneFeatureUpdateStatus.ps1
.EXAMPLE
    .\Get-IntuneFeatureUpdateStatus.ps1 -ProfileName "Windows 11 24H2"
#>

[CmdletBinding()]
param(
    [Parameter()][string]$ProfileName,
    [Parameter()][string]$ExportPath
)

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

Write-Section "FEATURE UPDATE PROFILES"
$profiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"

if ($ProfileName) {
    $profiles = $profiles | Where-Object { $_.displayName -like "*$ProfileName*" }
}

Write-Status "$($profiles.Count) feature update profile(s)" "Green"

if ($profiles.Count -eq 0) {
    Write-Host "  No feature update profiles found." -ForegroundColor Yellow
    return
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($profile in ($profiles | Sort-Object displayName)) {
    $pName = $profile.displayName
    $targetVer = $profile.featureUpdateVersion
    $rolloutStart = $profile.rolloutStartDateTime
    $rolloutEnd = $profile.endOfSupportDate
    $createdDate = $profile.createdDateTime

    Write-Section "PROFILE: $pName"
    Write-Host ""
    Write-Host "  Target version   : $targetVer" -ForegroundColor White
    Write-Host "  Rollout start    : $rolloutStart" -ForegroundColor Gray
    Write-Host "  End of support   : $rolloutEnd" -ForegroundColor Gray
    Write-Host "  Created          : $createdDate" -ForegroundColor Gray

    # Get assignments
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$($profile.id)/assignments"
    $assignCount = $assignments.Count
    Write-Host "  Assignments      : $assignCount" -ForegroundColor $(if($assignCount -gt 0){'Green'}else{'Yellow'})

    # Get device states for this profile
    Write-Status "Fetching per-device deployment states..."
    $deviceStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$($profile.id)/deviceUpdateStates"

    if ($deviceStates.Count -eq 0) {
        Write-Host "  No device state data available for this profile." -ForegroundColor DarkGray
        Write-Host "  This may indicate the profile is new or the deployment service hasn't reported yet." -ForegroundColor DarkGray
        continue
    }

    Write-Status "$($deviceStates.Count) device states returned" "Green"

    # Categorize states
    $stateCounts = @{}
    $safeguardHeld = @()
    $errors = @()
    $pending = @()

    foreach ($ds in $deviceStates) {
        $state = if ($ds.status) { $ds.status } elseif ($ds.state) { $ds.state } else { 'unknown' }
        if (-not $stateCounts.ContainsKey($state)) { $stateCounts[$state] = 0 }
        $stateCounts[$state]++

        if ($state -like '*safeguard*' -or $state -like '*hold*') { $safeguardHeld += $ds }
        if ($state -like '*error*' -or $state -like '*fail*') { $errors += $ds }
        if ($state -like '*pending*' -or $state -like '*download*' -or $state -like '*install*') { $pending += $ds }

        $report.Add([PSCustomObject]@{
            ProfileName    = $pName
            TargetVersion  = $targetVer
            DeviceName     = $ds.deviceDisplayName
            DeviceId       = $ds.deviceId
            UserName       = $ds.userId
            State          = $state
            Substate       = $ds.substate
            LastUpdated    = $ds.lastUpdatedDateTime
            FeatureUpdateVersion = $ds.featureUpdateVersion
        })
    }

    # State distribution
    Write-Host ""
    Write-Host "  --- Deployment State Distribution ---" -ForegroundColor Yellow
    foreach ($sc in ($stateCounts.GetEnumerator() | Sort-Object Value -Descending)) {
        $stateColor = switch -Wildcard ($sc.Key) {
            '*installed*'  { 'Green' }
            '*success*'    { 'Green' }
            '*upToDate*'   { 'Green' }
            '*safeguard*'  { 'Red' }
            '*hold*'       { 'Red' }
            '*error*'      { 'Red' }
            '*fail*'       { 'Red' }
            '*pending*'    { 'Yellow' }
            '*download*'   { 'Yellow' }
            '*install*'    { 'Yellow' }
            '*reboot*'     { 'Yellow' }
            '*cancel*'     { 'DarkGray' }
            default        { 'White' }
        }
        Write-Host "    $($sc.Key) : $($sc.Value)" -ForegroundColor $stateColor
    }

    # Safeguard holds
    if ($safeguardHeld.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- Devices on Safeguard Hold ($($safeguardHeld.Count)) ---" -ForegroundColor Red
        Write-Host "  These devices have a Microsoft-applied compatibility block." -ForegroundColor DarkGray
        foreach ($sh in ($safeguardHeld | Select-Object -First 10)) {
            Write-Host "    $($sh.deviceDisplayName)" -ForegroundColor DarkYellow
        }
        if ($safeguardHeld.Count -gt 10) { Write-Host "    ... and $($safeguardHeld.Count - 10) more" -ForegroundColor DarkGray }
    }

    # Errors
    if ($errors.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- Devices with Errors ($($errors.Count)) ---" -ForegroundColor Red
        foreach ($e in ($errors | Select-Object -First 10)) {
            Write-Host "    $($e.deviceDisplayName) : $($e.substate)" -ForegroundColor DarkYellow
        }
        if ($errors.Count -gt 10) { Write-Host "    ... and $($errors.Count - 10) more" -ForegroundColor DarkGray }
    }
}

# Summary
Write-Section "FEATURE UPDATE SUMMARY"
Write-Host ""
Write-Host "  Total profiles   : $($profiles.Count)" -ForegroundColor White
Write-Host "  Total devices    : $($report.Count)" -ForegroundColor White

$stateOverall = $report | Group-Object State | Sort-Object Count -Descending
foreach ($so in $stateOverall) {
    Write-Host "    $($so.Name) : $($so.Count)" -ForegroundColor White
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "FeatureUpdateStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


