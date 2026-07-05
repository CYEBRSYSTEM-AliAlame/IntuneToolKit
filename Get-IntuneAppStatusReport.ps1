#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a detailed Intune app installation status report showing
    deployment results per app per device with failure reasons.
.DESCRIPTION
    Queries Microsoft Graph to retrieve app installation status across managed
    devices. Shows which apps succeeded, failed, or are pending installation,
    including error codes, failure reasons, and install state details.
    Supports filtering by a single app, a single device, or all assigned apps.
.PARAMETER AppName
    Filter by app display name (supports partial match / contains).
.PARAMETER DeviceName
    Report app status for a single device.
.PARAMETER FailedOnly
    Only show apps with failed or error installation states (default).
    Use -IncludeAll to override.
.PARAMETER IncludeAll
    Include all installation states (installed, not installed, pending, failed).
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneAppStatusReport.ps1
    # All assigned apps - failed installations only
.EXAMPLE
    .\Get-IntuneAppStatusReport.ps1 -AppName "Microsoft Teams"
    # Status for a specific app across all devices
.EXAMPLE
    .\Get-IntuneAppStatusReport.ps1 -DeviceName "L-PF4Z0HM0" -IncludeAll
    # All app statuses for a single device
.EXAMPLE
    .\Get-IntuneAppStatusReport.ps1 -IncludeAll -ExportPath "C:\temp\app_status.csv"
    # Full report exported to CSV
#>

[CmdletBinding(DefaultParameterSetName = 'AllApps')]
param(
    [Parameter(ParameterSetName = 'ByApp')]
    [string]$AppName,

    [Parameter(ParameterSetName = 'ByDevice')]
    [string]$DeviceName,

    [Parameter()]
    [switch]$IncludeAll,

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

function Get-FriendlyInstallState {
    param([string]$State)
    switch ($State) {
        'installed'              { 'Installed' }
        'failed'                 { 'Failed' }
        'notInstalled'           { 'Not Installed' }
        'uninstallFailed'        { 'Uninstall Failed' }
        'pendingInstall'         { 'Pending Install' }
        'unknown'                { 'Unknown' }
        'notApplicable'          { 'Not Applicable' }
        'installError'           { 'Install Error' }
        default                  { $State }
    }
}

function Get-InstallStateColor {
    param([string]$State)
    switch ($State) {
        'installed'         { 'Green' }
        'failed'            { 'Red' }
        'installError'      { 'Red' }
        'uninstallFailed'   { 'Red' }
        'notInstalled'      { 'Yellow' }
        'pendingInstall'    { 'DarkYellow' }
        'notApplicable'     { 'DarkGray' }
        default             { 'Gray' }
    }
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'DeviceManagementApps.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'Device.Read.All',
        'Directory.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve Scope ---
Write-Section "RESOLVING SCOPE"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($DeviceName) {
    # --- Single Device Mode ---
    Write-Status "Looking up device: $DeviceName"
    $devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'&`$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState"
    if ($devices.Count -eq 0) {
        Write-Host "  ERROR: Device '$DeviceName' not found in Intune." -ForegroundColor Red
        return
    }
    $device = $devices[0]
    Write-Status "Device found: $($device.deviceName) ($($device.operatingSystem))" "Green"

    Write-Section "APP INSTALLATION STATUS FOR: $($device.deviceName)"

    # Get all app statuses for this device
    $appStatuses = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/detectedApps"
    
    # Use device install status from managed apps
    Write-Status "Retrieving app installation states for device..."
    
    # Get assigned apps and their device statuses
    $assignedApps = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$select=id,displayName,@odata.type"
    Write-Status "Checking $($assignedApps.Count) assigned apps..."

    $appIndex = 0
    foreach ($app in $assignedApps) {
        $appIndex++
        if ($appIndex % 25 -eq 0) {
            Write-Progress -Activity "Checking app statuses" -Status "$appIndex of $($assignedApps.Count) - $($app.displayName)" -PercentComplete (($appIndex / $assignedApps.Count) * 100)
        }

        # Get device status for this specific app
        $deviceStatuses = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/deviceStatuses?`$filter=deviceId eq '$($device.id)'"

        foreach ($ds in $deviceStatuses) {
            $installState = $ds.installState
            if (-not $installState) { $installState = $ds.installStateDetail }

            # Filter to failures unless IncludeAll
            if (-not $IncludeAll -and $installState -in @('installed','notApplicable','unknown')) { continue }

            $errorCode = $ds.errorCode
            $errorDesc = if ($ds.installStateDetail) { $ds.installStateDetail } else { '-' }

            $report.Add([PSCustomObject]@{
                AppName           = $app.displayName
                AppType           = ($app.'@odata.type' -replace '#microsoft.graph.','')
                DeviceName        = $device.deviceName
                UserPrincipalName = $ds.userPrincipalName
                InstallState      = Get-FriendlyInstallState $installState
                InstallStateRaw   = $installState
                ErrorCode         = if ($errorCode -and $errorCode -ne 0) { "0x{0:X8}" -f $errorCode } else { '-' }
                ErrorCodeDec      = if ($errorCode -and $errorCode -ne 0) { $errorCode } else { '-' }
                InstallDetail     = $errorDesc
                LastModified      = $ds.lastSyncDateTime
                DeviceId          = $device.id
                AppId             = $app.id
            })
        }
    }
    Write-Progress -Activity "Checking app statuses" -Completed

} else {
    # --- All Apps or Filtered by App Name ---
    Write-Status "Retrieving assigned apps..."
    $apps = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$select=id,displayName,@odata.type,isAssigned"

    if ($AppName) {
        $apps = $apps | Where-Object { $_.displayName -like "*$AppName*" }
        if ($apps.Count -eq 0) {
            Write-Host "  ERROR: No assigned apps found matching '$AppName'." -ForegroundColor Red
            return
        }
        Write-Status "Found $($apps.Count) app(s) matching '$AppName'" "Green"
    } else {
        Write-Status "Found $($apps.Count) assigned apps" "Green"
    }

    Write-Section "SCANNING APP INSTALLATION STATUSES"

    $appIndex = 0
    foreach ($app in $apps) {
        $appIndex++
        $pctComplete = [math]::Round(($appIndex / $apps.Count) * 100)
        Write-Progress -Activity "Scanning app deployment status" -Status "$appIndex of $($apps.Count) - $($app.displayName)" -PercentComplete $pctComplete

        # Get device statuses for this app
        $deviceStatuses = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/deviceStatuses"

        if ($deviceStatuses.Count -eq 0) { continue }

        foreach ($ds in $deviceStatuses) {
            $installState = $ds.installState
            if (-not $installState) { $installState = $ds.installStateDetail }

            # Filter to failures unless IncludeAll
            if (-not $IncludeAll -and $installState -in @('installed','notApplicable','unknown')) { continue }

            $errorCode = $ds.errorCode
            $errorDesc = if ($ds.installStateDetail) { $ds.installStateDetail } else { '-' }

            $report.Add([PSCustomObject]@{
                AppName           = $app.displayName
                AppType           = ($app.'@odata.type' -replace '#microsoft.graph.','')
                DeviceName        = $ds.deviceName
                UserPrincipalName = $ds.userPrincipalName
                InstallState      = Get-FriendlyInstallState $installState
                InstallStateRaw   = $installState
                ErrorCode         = if ($errorCode -and $errorCode -ne 0) { "0x{0:X8}" -f $errorCode } else { '-' }
                ErrorCodeDec      = if ($errorCode -and $errorCode -ne 0) { $errorCode } else { '-' }
                InstallDetail     = $errorDesc
                LastModified      = $ds.lastSyncDateTime
                DeviceId          = $ds.deviceId
                AppId             = $app.id
            })
        }

        # Show progress for current app
        $failedForApp = ($deviceStatuses | Where-Object { $_.installState -in @('failed','installError','uninstallFailed') }).Count
        if ($failedForApp -gt 0) {
            Write-Host "    $($app.displayName)" -ForegroundColor White -NoNewline
            Write-Host " - $failedForApp failure(s)" -ForegroundColor Red
        }
    }
    Write-Progress -Activity "Scanning app deployment status" -Completed
}
#endregion

#region --- Summary ---
Write-Section "APP DEPLOYMENT SUMMARY"
Write-Host ""

if ($report.Count -eq 0) {
    if ($IncludeAll) {
        Write-Host "  No app installation records found for the specified scope." -ForegroundColor DarkGray
    } else {
        Write-Host "  No app installation failures found. All deployments are healthy!" -ForegroundColor Green
        Write-Host "  Use -IncludeAll to see all installation states." -ForegroundColor DarkGray
    }
} else {
    # State breakdown
    $stateGroups = $report | Group-Object InstallState | Sort-Object Count -Descending
    Write-Host "  Installation State Breakdown:" -ForegroundColor White
    foreach ($sg in $stateGroups) {
        $stateColor = switch ($sg.Name) {
            'Installed'       { 'Green' }
            'Failed'          { 'Red' }
            'Install Error'   { 'Red' }
            'Uninstall Failed'{ 'Red' }
            'Not Installed'   { 'Yellow' }
            'Pending Install' { 'DarkYellow' }
            default           { 'Gray' }
        }
        Write-Host "    $($sg.Name) : $($sg.Count)" -ForegroundColor $stateColor
    }
    Write-Host ""

    # Top failing apps
    $failedEntries = $report | Where-Object { $_.InstallState -in @('Failed','Install Error','Uninstall Failed') }
    if ($failedEntries.Count -gt 0) {
        Write-Section "TOP FAILING APPS"
        Write-Host ""
        $appFailRanking = $failedEntries | Group-Object AppName | Sort-Object Count -Descending | Select-Object -First 15

        foreach ($af in $appFailRanking) {
            $uniqueDevices = ($af.Group | Select-Object -Property DeviceName -Unique).Count
            Write-Host "  $($af.Name)" -ForegroundColor Yellow
            Write-Host "    $($af.Count) failure(s) across $uniqueDevices device(s)" -ForegroundColor DarkCyan

            # Show top error codes for this app
            $errorCodes = $af.Group | Where-Object { $_.ErrorCode -ne '-' } | Group-Object ErrorCode | Sort-Object Count -Descending | Select-Object -First 3
            foreach ($ec in $errorCodes) {
                Write-Host "      Error $($ec.Name) : $($ec.Count) occurrence(s)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        # Top error codes overall
        $allErrors = $failedEntries | Where-Object { $_.ErrorCode -ne '-' } | Group-Object ErrorCode | Sort-Object Count -Descending | Select-Object -First 10
        if ($allErrors.Count -gt 0) {
            Write-Section "TOP ERROR CODES"
            Write-Host ""
            foreach ($err in $allErrors) {
                $affectedApps = ($err.Group | Select-Object -Property AppName -Unique | ForEach-Object { $_.AppName }) -join ', '
                $truncApps = if ($affectedApps.Length -gt 80) { $affectedApps.Substring(0,77) + '...' } else { $affectedApps }
                Write-Host "  $($err.Name) : $($err.Count) occurrence(s)" -ForegroundColor Yellow
                Write-Host "    Apps: $truncApps" -ForegroundColor DarkGray
            }
            Write-Host ""
        }

        # Devices with most failures
        $deviceFailRanking = $failedEntries | Group-Object DeviceName | Sort-Object Count -Descending | Select-Object -First 10
        if ($deviceFailRanking.Count -gt 0) {
            Write-Section "DEVICES WITH MOST APP FAILURES"
            Write-Host ""
            foreach ($df in $deviceFailRanking) {
                $upn = ($df.Group | Select-Object -First 1).UserPrincipalName
                Write-Host "  $($df.Name)" -ForegroundColor White -NoNewline
                Write-Host " ($upn)" -ForegroundColor Gray -NoNewline
                Write-Host " - $($df.Count) failed app(s)" -ForegroundColor Red
            }
            Write-Host ""
        }
    }

    # Pending installs
    $pendingEntries = $report | Where-Object { $_.InstallState -eq 'Pending Install' }
    if ($pendingEntries.Count -gt 0) {
        Write-Section "PENDING INSTALLATIONS ($($pendingEntries.Count))"
        Write-Host ""
        $pendingByApp = $pendingEntries | Group-Object AppName | Sort-Object Count -Descending | Select-Object -First 10
        foreach ($pa in $pendingByApp) {
            Write-Host "  $($pa.Name) : $($pa.Count) device(s) pending" -ForegroundColor DarkYellow
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
        $scopeSafe = switch ($PSCmdlet.ParameterSetName) {
            'ByApp'    { ($AppName -replace '[^\w\-]','_') }
            'ByDevice' { ($DeviceName -replace '[^\w\-]','_') }
            default    { 'AllApps' }
        }
        $defaultPath = Join-Path $env:TEMP "$scopeSafe`_AppStatusReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $report | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported $($report.Count) rows to: $defaultPath" "Green"
    }
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


