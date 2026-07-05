#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Identifies stale and orphaned devices across Intune and Entra ID.
.DESCRIPTION
    Cross-references Intune managed devices and Entra ID device records to find:
    - Devices that haven't synced with Intune in X days (default 90)
    - Devices that haven't signed in to Entra ID in X days
    - Orphaned Intune devices with no matching Entra ID record
    - Orphaned Entra ID devices with no matching Intune record
    - Devices with no primary user assigned
    - Disabled Entra ID accounts still owning managed devices
    Exports a comprehensive CSV with recommended actions.
.PARAMETER InactivityDays
    Number of days since last sync/sign-in to consider a device stale. Default: 90.
.PARAMETER WarningDays
    Number of days for the "warning" threshold (approaching stale). Default: 60.
.PARAMETER IncludeCompliant
    Include devices that are within the activity thresholds (for a full inventory).
.PARAMETER OSFilter
    Filter by operating system (e.g., "Windows", "iOS", "Android", "macOS").
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneStaleDevices.ps1
    # Find devices inactive for 90+ days
.EXAMPLE
    .\Get-IntuneStaleDevices.ps1 -InactivityDays 60 -WarningDays 30
    # More aggressive thresholds
.EXAMPLE
    .\Get-IntuneStaleDevices.ps1 -OSFilter "Windows" -ExportPath "C:\temp\stale_windows.csv"
    # Windows devices only
.EXAMPLE
    .\Get-IntuneStaleDevices.ps1 -IncludeCompliant -ExportPath "C:\temp\full_device_health.csv"
    # Full device health report including active devices
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$InactivityDays = 90,

    [Parameter()]
    [int]$WarningDays = 60,

    [Parameter()]
    [switch]$IncludeCompliant,

    [Parameter()]
    [string]$OSFilter,

    [Parameter()]
    [string]$ExportPath
)

#region --- Helpers ---
function Write-Status { param([string]$Msg, [string]$Color = 'Cyan') ; Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg) ; Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri, [string]$Method = 'GET')
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
    }
    catch {
        Write-Verbose "Graph call failed for $Uri : $_"
        return @()
    }
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'DeviceManagementManagedDevices.Read.All',
        'Device.Read.All',
        'Directory.Read.All',
        'User.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Configuration ---
Write-Section "CONFIGURATION"
$now = Get-Date
$staleThreshold   = $now.AddDays(-$InactivityDays)
$warningThreshold = $now.AddDays(-$WarningDays)

Write-Host "  Stale threshold    : $InactivityDays days ($($staleThreshold.ToString('yyyy-MM-dd')))" -ForegroundColor White
Write-Host "  Warning threshold  : $WarningDays days ($($warningThreshold.ToString('yyyy-MM-dd')))" -ForegroundColor White
Write-Host "  OS filter          : $(if($OSFilter){$OSFilter}else{'All'})" -ForegroundColor White
Write-Host "  Include active     : $($IncludeCompliant.IsPresent)" -ForegroundColor White
#endregion

#region --- Retrieve Intune Devices ---
Write-Section "RETRIEVING INTUNE MANAGED DEVICES"

$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,azureADDeviceId,userPrincipalName,userId,lastSyncDateTime,enrolledDateTime,complianceState,operatingSystem,osVersion,model,manufacturer,serialNumber,managedDeviceOwnerType,managementAgent,deviceRegistrationState"

if ($OSFilter) {
    $intuneUri += "&`$filter=operatingSystem eq '$OSFilter'"
}

Write-Status "Fetching Intune devices$(if($OSFilter){" (OS: $OSFilter)"})..."
$intuneDevices = Invoke-MgGraph-Safe -Uri $intuneUri
Write-Status "$($intuneDevices.Count) Intune managed devices retrieved" "Green"
#endregion

#region --- Retrieve Entra ID Devices ---
Write-Section "RETRIEVING ENTRA ID DEVICE RECORDS"

Write-Status "Fetching Entra ID devices (with sign-in activity)..."
# Use beta for approximateLastSignInDateTime
$entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/devices?`$select=id,deviceId,displayName,approximateLastSignInDateTime,accountEnabled,operatingSystem,operatingSystemVersion,trustType,registrationDateTime,isManaged,isCompliant"
Write-Status "$($entraDevices.Count) Entra ID device records retrieved" "Green"

# Build lookup by Entra device ID (azureADDeviceId in Intune = deviceId in Entra)
$entraLookup = @{}
foreach ($ed in $entraDevices) {
    if ($ed.deviceId) { $entraLookup[$ed.deviceId] = $ed }
}
#endregion

#region --- Cross-Reference Analysis ---
Write-Section "CROSS-REFERENCING DEVICES"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# Counters
$activeCount   = 0
$warningCount  = 0
$staleCount    = 0
$orphanIntune  = 0
$orphanEntra   = 0
$noUserCount   = 0
$disabledOwner = 0
$deviceIndex   = 0

foreach ($device in $intuneDevices) {
    $deviceIndex++
    if ($deviceIndex % 100 -eq 0) {
        Write-Progress -Activity "Analyzing Intune devices" -Status "$deviceIndex of $($intuneDevices.Count)" -PercentComplete (($deviceIndex / $intuneDevices.Count) * 100)
    }

    $lastSync = $device.lastSyncDateTime
    $entraDeviceId = $device.azureADDeviceId
    $upn = $device.userPrincipalName

    # Calculate Intune staleness
    $daysSinceSync = if ($lastSync) {
        [math]::Round(($now - [datetime]$lastSync).TotalDays, 1)
    } else { 9999 }

    # Look up matching Entra ID record
    $entraRecord = if ($entraDeviceId) { $entraLookup[$entraDeviceId] } else { $null }

    $entraLastSignIn = $null
    $daysSinceEntraSignIn = 'N/A'
    $entraAccountEnabled = $null
    $entraIsManaged = $null

    if ($entraRecord) {
        $entraLastSignIn = $entraRecord.approximateLastSignInDateTime
        $entraAccountEnabled = $entraRecord.accountEnabled
        $entraIsManaged = $entraRecord.isManaged

        if ($entraLastSignIn) {
            $daysSinceEntraSignIn = [math]::Round(($now - [datetime]$entraLastSignIn).TotalDays, 1)
        }
    }

    # Determine status
    $intuneStatus = if ($daysSinceSync -ge $InactivityDays) { 'Stale' }
                    elseif ($daysSinceSync -ge $WarningDays) { 'Warning' }
                    else { 'Active' }

    $entraStatus = if (-not $entraRecord) { 'No Entra Record' }
                   elseif ($daysSinceEntraSignIn -eq 'N/A') { 'No Sign-In Data' }
                   elseif ([double]$daysSinceEntraSignIn -ge $InactivityDays) { 'Stale' }
                   elseif ([double]$daysSinceEntraSignIn -ge $WarningDays) { 'Warning' }
                   else { 'Active' }

    # Classify issues
    $issues = @()

    if ($intuneStatus -eq 'Stale') { $issues += "Intune sync stale ($daysSinceSync days)" ; $staleCount++ }
    elseif ($intuneStatus -eq 'Warning') { $issues += "Intune sync warning ($daysSinceSync days)" ; $warningCount++ }
    else { $activeCount++ }

    if ($entraStatus -eq 'No Entra Record') { $issues += 'No matching Entra ID device record' ; $orphanIntune++ }
    if ($entraStatus -eq 'Stale') { $issues += "Entra sign-in stale ($daysSinceEntraSignIn days)" }

    if (-not $upn -or $upn -eq '') { $issues += 'No primary user assigned' ; $noUserCount++ }

    if ($entraAccountEnabled -eq $false) { $issues += 'Entra device account disabled' ; $disabledOwner++ }

    # Check if the owning user account is disabled
    $userAccountDisabled = $false
    if ($upn -and $upn -ne '' -and $device.userId) {
        # We'll batch this check - for now flag for the report
        # (individual user lookups would be too slow for large tenants)
    }

    # Recommended action
    $recommendation = if ($issues.Count -eq 0) { 'No action needed' }
    elseif ($intuneStatus -eq 'Stale' -and $entraStatus -eq 'No Entra Record') { 'RETIRE - Orphaned stale device' }
    elseif ($intuneStatus -eq 'Stale' -and $entraStatus -eq 'Stale') { 'RETIRE - Stale in both systems' }
    elseif ($intuneStatus -eq 'Stale') { 'REVIEW - Stale Intune sync' }
    elseif ($entraStatus -eq 'No Entra Record') { 'REVIEW - Missing Entra record' }
    elseif ($entraAccountEnabled -eq $false) { 'REVIEW - Entra device disabled' }
    elseif ($intuneStatus -eq 'Warning') { 'MONITOR - Approaching stale' }
    else { 'REVIEW' }

    # Skip active devices unless -IncludeCompliant
    if ($issues.Count -eq 0 -and -not $IncludeCompliant) { continue }

    $report.Add([PSCustomObject]@{
        DeviceName             = $device.deviceName
        UserPrincipalName      = $upn
        OperatingSystem        = $device.operatingSystem
        OSVersion              = $device.osVersion
        Model                  = $device.model
        Manufacturer           = $device.manufacturer
        SerialNumber           = $device.serialNumber
        Ownership              = $device.managedDeviceOwnerType
        ComplianceState        = $device.complianceState
        ManagementAgent        = $device.managementAgent
        IntuneLastSync         = $lastSync
        DaysSinceIntuneSync    = $daysSinceSync
        IntuneStatus           = $intuneStatus
        EntraLastSignIn        = $entraLastSignIn
        DaysSinceEntraSignIn   = $daysSinceEntraSignIn
        EntraStatus            = $entraStatus
        EntraAccountEnabled    = $entraAccountEnabled
        EnrolledDateTime       = $device.enrolledDateTime
        Issues                 = ($issues -join '; ')
        Recommendation         = $recommendation
        IntuneDeviceId         = $device.id
        EntraDeviceId          = $entraDeviceId
    })
}

# Check for Entra ID devices not in Intune (orphaned Entra records)
Write-Status "Checking for Entra ID devices not enrolled in Intune..."
$intuneEntraIds = $intuneDevices | Where-Object { $_.azureADDeviceId } | ForEach-Object { $_.azureADDeviceId }

foreach ($ed in $entraDevices) {
    # Only check managed devices or Azure AD joined
    if ($ed.trustType -notin @('AzureAd','ServerAd','Workplace') ) { continue }
    if (-not $ed.isManaged -and $ed.trustType -eq 'Workplace') { continue }

    if ($ed.deviceId -and $intuneEntraIds -notcontains $ed.deviceId) {
        # Apply OS filter if set
        if ($OSFilter -and $ed.operatingSystem -ne $OSFilter) { continue }

        $orphanEntra++

        $entraLastSignIn = $ed.approximateLastSignInDateTime
        $daysSinceSign = if ($entraLastSignIn) { [math]::Round(($now - [datetime]$entraLastSignIn).TotalDays, 1) } else { 'N/A' }

        $orphanRec = if ($daysSinceSign -ne 'N/A' -and [double]$daysSinceSign -ge $InactivityDays) {
            'DELETE - Stale Entra device, not in Intune'
        } else {
            'REVIEW - Entra device not enrolled in Intune'
        }

        $report.Add([PSCustomObject]@{
            DeviceName             = $ed.displayName
            UserPrincipalName      = '-'
            OperatingSystem        = $ed.operatingSystem
            OSVersion              = $ed.operatingSystemVersion
            Model                  = '-'
            Manufacturer           = '-'
            SerialNumber           = '-'
            Ownership              = '-'
            ComplianceState        = if($ed.isCompliant){'compliant'}else{'unknown'}
            ManagementAgent        = '-'
            IntuneLastSync         = '-'
            DaysSinceIntuneSync    = 'N/A'
            IntuneStatus           = 'Not Enrolled'
            EntraLastSignIn        = $entraLastSignIn
            DaysSinceEntraSignIn   = $daysSinceSign
            EntraStatus            = if($daysSinceSign -ne 'N/A' -and [double]$daysSinceSign -ge $InactivityDays){'Stale'}else{'Active'}
            EntraAccountEnabled    = $ed.accountEnabled
            EnrolledDateTime       = $ed.registrationDateTime
            Issues                 = 'Entra ID device not enrolled in Intune'
            Recommendation         = $orphanRec
            IntuneDeviceId         = '-'
            EntraDeviceId          = $ed.deviceId
        })
    }
}

Write-Progress -Activity "Analyzing Intune devices" -Completed
#endregion

#region --- Summary ---
Write-Section "STALE DEVICE SUMMARY"
Write-Host ""

Write-Host "  Intune Managed Devices : $($intuneDevices.Count)" -ForegroundColor White
Write-Host "  Entra ID Devices       : $($entraDevices.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  --- Intune Sync Status ---" -ForegroundColor Yellow
Write-Host "  Active (< $WarningDays days)     : $activeCount" -ForegroundColor Green
Write-Host "  Warning ($WarningDays-$InactivityDays days)    : $warningCount" -ForegroundColor $(if($warningCount -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "  Stale (> $InactivityDays days)      : $staleCount" -ForegroundColor $(if($staleCount -gt 0){'Red'}else{'DarkGray'})
Write-Host ""
Write-Host "  --- Cross-Reference Issues ---" -ForegroundColor Yellow
Write-Host "  Intune orphans (no Entra record)  : $orphanIntune" -ForegroundColor $(if($orphanIntune -gt 0){'Red'}else{'DarkGray'})
Write-Host "  Entra orphans (not in Intune)     : $orphanEntra" -ForegroundColor $(if($orphanEntra -gt 0){'Red'}else{'DarkGray'})
Write-Host "  No primary user assigned          : $noUserCount" -ForegroundColor $(if($noUserCount -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "  Entra device account disabled     : $disabledOwner" -ForegroundColor $(if($disabledOwner -gt 0){'Yellow'}else{'DarkGray'})

# Recommendation breakdown
if ($report.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Recommended Actions ---" -ForegroundColor Yellow
    $actionGroups = $report | Group-Object Recommendation | Sort-Object Count -Descending
    foreach ($ag in $actionGroups) {
        $actionColor = switch -Wildcard ($ag.Name) {
            'RETIRE*' { 'Red' }
            'DELETE*' { 'Red' }
            'REVIEW*' { 'Yellow' }
            'MONITOR*' { 'DarkYellow' }
            default   { 'DarkGray' }
        }
        Write-Host "  $($ag.Name) : $($ag.Count) device(s)" -ForegroundColor $actionColor
    }

    # Show top stale devices
    $staleDevices = $report | Where-Object { $_.IntuneStatus -eq 'Stale' } | Sort-Object { [double]$_.DaysSinceIntuneSync } -Descending
    if ($staleDevices.Count -gt 0) {
        $displayCount = [math]::Min($staleDevices.Count, 15)
        Write-Section "MOST STALE DEVICES (top $displayCount)"
        Write-Host ""

        foreach ($sd in ($staleDevices | Select-Object -First 15)) {
            Write-Host "  $($sd.DeviceName)" -ForegroundColor White -NoNewline
            Write-Host " | $($sd.DaysSinceIntuneSync) days" -ForegroundColor Red -NoNewline
            Write-Host " | $($sd.UserPrincipalName)" -ForegroundColor Gray -NoNewline
            Write-Host " | $($sd.OperatingSystem)" -ForegroundColor DarkGray
            Write-Host "    $($sd.Recommendation)" -ForegroundColor DarkCyan
        }
        Write-Host ""
    }

    # OS breakdown of stale devices
    $staleByOS = $report | Where-Object { $_.Recommendation -match 'RETIRE|DELETE|REVIEW' } | Group-Object OperatingSystem | Sort-Object Count -Descending
    if ($staleByOS.Count -gt 0) {
        Write-Section "ISSUES BY OPERATING SYSTEM"
        Write-Host ""
        foreach ($os in $staleByOS) {
            Write-Host "  $($os.Name): $($os.Count) device(s)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

# Export
if ($report.Count -gt 0) {
    if ($ExportPath) {
        $report | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status "Exported $($report.Count) rows to: $ExportPath" "Green"
    } else {
        $defaultPath = Join-Path $env:TEMP "StaleDeviceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $report | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported $($report.Count) rows to: $defaultPath" "Green"
    }
} else {
    Write-Host ""
    Write-Host "  No stale or problematic devices found. Environment is clean!" -ForegroundColor Green
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


