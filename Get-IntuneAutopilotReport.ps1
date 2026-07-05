#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Autopilot device registration and deployment profile status.
.DESCRIPTION
    Lists all Autopilot registered devices with their profile assignment state,
    group tag, deployment profile, purchase order, serial number, and enrollment
    status. Identifies devices registered but not enrolled, devices with no
    profile assigned, and deployment errors.
.PARAMETER ExportPath
    Optional. Export results to CSV.
.EXAMPLE
    .\Get-IntuneAutopilotReport.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementServiceConfig.Read.All','DeviceManagementManagedDevices.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "AUTOPILOT DEVICE INVENTORY"
Write-Status "Fetching Autopilot device identities..."
$apDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
Write-Status "Found $($apDevices.Count) Autopilot registered devices" "Green"

Write-Status "Fetching Autopilot deployment profiles..."
$apProfiles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles"
Write-Status "Found $($apProfiles.Count) deployment profiles" "Green"

# Build profile lookup
$profileMap = @{}
foreach ($p in $apProfiles) { $profileMap[$p.id] = $p.displayName }

# Fetch managed devices for cross-reference
Write-Status "Fetching managed devices for enrollment cross-reference..."
$managedDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,serialNumber,azureADDeviceId,enrolledDateTime"
$managedSerials = @{}
foreach ($md in $managedDevices) {
    if ($md.serialNumber) { $managedSerials[$md.serialNumber] = $md }
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$profileAssigned = 0; $profileNotAssigned = 0; $enrolled = 0; $notEnrolled = 0

foreach ($ap in $apDevices) {
    $serial = $ap.serialNumber
    $profileStatus = $ap.deploymentProfileAssignmentStatus
    $profileName = '-'
    if ($ap.deploymentProfileAssignedDateTime -and $ap.deploymentProfile) {
        $profileName = $ap.deploymentProfile
    }
    $intendedProfile = $ap.intendedDeploymentProfileAssignedDateTime

    $hasProfile = $profileStatus -and $profileStatus -ne 'notAssigned' -and $profileStatus -ne 'failed'
    if ($hasProfile) { $profileAssigned++ } else { $profileNotAssigned++ }

    # Check if enrolled
    $isEnrolled = $false
    $enrolledDevice = $null
    if ($serial -and $managedSerials.ContainsKey($serial)) {
        $isEnrolled = $true
        $enrolledDevice = $managedSerials[$serial]
    }
    if ($isEnrolled) { $enrolled++ } else { $notEnrolled++ }

    $groupTag = $ap.groupTag
    $purchaseOrder = $ap.purchaseOrderIdentifier
    $model = $ap.model
    $manufacturer = $ap.manufacturer

    $report.Add([PSCustomObject]@{
        SerialNumber       = $serial
        Model              = $model
        Manufacturer       = $manufacturer
        GroupTag           = $groupTag
        PurchaseOrder      = $purchaseOrder
        ProfileStatus      = $profileStatus
        ProfileAssignDate  = $ap.deploymentProfileAssignedDateTime
        EnrollmentState    = $ap.enrollmentState
        IsEnrolled         = $isEnrolled
        EnrolledDeviceName = if ($enrolledDevice) { $enrolledDevice.deviceName } else { '-' }
        EnrolledDate       = if ($enrolledDevice) { $enrolledDevice.enrolledDateTime } else { '-' }
        LastContacted      = $ap.lastContactedDateTime
        AddressableUserName = $ap.addressableUserName
        UserPrincipalName  = $ap.userPrincipalName
    })
}

Write-Section "AUTOPILOT STATUS SUMMARY"
Write-Host ""
Write-Host "  Total registered devices   : $($apDevices.Count)" -ForegroundColor White
Write-Host "  Profile assigned           : $profileAssigned" -ForegroundColor Green
Write-Host "  Profile NOT assigned       : $profileNotAssigned" -ForegroundColor $(if($profileNotAssigned -gt 0){'Red'}else{'Green'})
Write-Host "  Enrolled in Intune         : $enrolled" -ForegroundColor Green
Write-Host "  Registered but not enrolled: $notEnrolled" -ForegroundColor $(if($notEnrolled -gt 0){'Yellow'}else{'Green'})

# Profile status breakdown
$statusGroups = $report | Group-Object ProfileStatus | Sort-Object Count -Descending
Write-Host ""
Write-Host "  --- Profile Assignment Status ---" -ForegroundColor Yellow
foreach ($sg in $statusGroups) {
    $statusColor = switch ($sg.Name) { 'assigned'{'Green'} 'notAssigned'{'Red'} 'failed'{'Red'} 'pending'{'Yellow'} default{'White'} }
    Write-Host "    $($sg.Name) : $($sg.Count)" -ForegroundColor $statusColor
}

# Group tag distribution
$tagGroups = $report | Where-Object { $_.GroupTag } | Group-Object GroupTag | Sort-Object Count -Descending
if ($tagGroups.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Group Tag Distribution ---" -ForegroundColor Yellow
    foreach ($tg in ($tagGroups | Select-Object -First 15)) {
        Write-Host "    $($tg.Name) : $($tg.Count) device(s)" -ForegroundColor White
    }
}

# Model distribution
$modelGroups = $report | Where-Object { $_.Model } | Group-Object Model | Sort-Object Count -Descending | Select-Object -First 10
if ($modelGroups.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Models ---" -ForegroundColor Yellow
    foreach ($mg in $modelGroups) {
        Write-Host "    $($mg.Name) : $($mg.Count)" -ForegroundColor White
    }
}

# Deployment profiles
if ($apProfiles.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Deployment Profiles ---" -ForegroundColor Yellow
    foreach ($p in $apProfiles) {
        $mode = if ($p.extractHardwareHash) { 'Hardware hash' } else { 'Standard' }
        Write-Host "    $($p.displayName) | $mode | OOBE: $(if($p.outOfBoxExperienceSettings.hidePrivacySettings){'Privacy hidden'}else{'Standard'})" -ForegroundColor White
    }
}

# Devices without profiles
$noProfile = $report | Where-Object { $_.ProfileStatus -eq 'notAssigned' -or -not $_.ProfileStatus }
if ($noProfile.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Devices Without Profile ($($noProfile.Count)) ---" -ForegroundColor Red
    foreach ($np in ($noProfile | Select-Object -First 15)) {
        Write-Host "    $($np.SerialNumber) | $($np.Model) | Tag: $($np.GroupTag)" -ForegroundColor DarkYellow
    }
    if ($noProfile.Count -gt 15) { Write-Host "    ... and $($noProfile.Count - 15) more" -ForegroundColor DarkGray }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "AutopilotReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


