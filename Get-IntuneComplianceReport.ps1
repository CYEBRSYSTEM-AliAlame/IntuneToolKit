#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a detailed Intune device compliance report showing non-compliant
    devices, the policies they failed, and the specific settings in violation.
.DESCRIPTION
    Queries Microsoft Graph to retrieve all managed devices (or a filtered subset)
    and their compliance policy states. For each non-compliant or in-grace-period
    device, drills into the specific settings that triggered the failure.
    Exports a flat CSV with one row per non-compliant setting per device.
.PARAMETER All
    Report on all managed devices (default if no other filter is specified).
.PARAMETER DeviceName
    Report on a single device by name.
.PARAMETER GroupName
    Report on devices belonging to a specific Entra ID group.
.PARAMETER NonCompliantOnly
    Only include devices that are non-compliant or in grace period (skip compliant devices).
    This is the default. Use -IncludeCompliant to override.
.PARAMETER IncludeCompliant
    Include compliant devices in the report (shows them with a clean status).
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneComplianceReport.ps1
    # Reports all non-compliant devices across the tenant
.EXAMPLE
    .\Get-IntuneComplianceReport.ps1 -DeviceName "L-PF4Z0HM0"
    # Deep-dive compliance for a single device
.EXAMPLE
    .\Get-IntuneComplianceReport.ps1 -GroupName "SG-Intune-Windows-Devices" -ExportPath "C:\temp\compliance.csv"
    # Compliance report for devices in a specific group
.EXAMPLE
    .\Get-IntuneComplianceReport.ps1 -IncludeCompliant -ExportPath "C:\temp\full_compliance.csv"
    # Full compliance report including compliant devices
#>

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'All')]
    [switch]$All,

    [Parameter(Mandatory, ParameterSetName = 'ByDevice')]
    [string]$DeviceName,

    [Parameter(Mandatory, ParameterSetName = 'ByGroup')]
    [string]$GroupName,

    [Parameter()]
    [switch]$IncludeCompliant,

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
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'Device.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'GroupMember.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve Device Scope ---
Write-Section "RESOLVING DEVICE SCOPE"

$targetDevices = @()

switch ($PSCmdlet.ParameterSetName) {
    'ByDevice' {
        Write-Status "Searching for device: $DeviceName"
        $targetDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'"
        if ($targetDevices.Count -eq 0) {
            Write-Host "  ERROR: Device '$DeviceName' not found in Intune." -ForegroundColor Red
            return
        }
        Write-Status "Found device: $($targetDevices[0].deviceName)" "Green"
    }
    'ByGroup' {
        Write-Status "Resolving group: $GroupName"
        $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($GroupName -replace "'","''")'"
        if ($groups.Count -eq 0) {
            Write-Host "  ERROR: Group '$GroupName' not found in Entra ID." -ForegroundColor Red
            return
        }
        $groupId = $groups[0].id
        Write-Status "Group found: $($groups[0].displayName) ($groupId)"

        # Get device members of the group
        Write-Status "Getting device members from group..."
        $groupMembers = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,deviceId,displayName"
        $deviceMembers = $groupMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }

        if ($deviceMembers.Count -eq 0) {
            # Group might contain users - get their devices instead
            Write-Status "No device members found, checking user members' devices..."
            $userMembers = $groupMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
            if ($userMembers.Count -gt 0) {
                Write-Status "Found $($userMembers.Count) user members, retrieving their managed devices..."
                foreach ($um in $userMembers) {
                    $userDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userId eq '$($um.id)'"
                    $targetDevices += $userDevices
                }
            }
        } else {
            # Map Entra device IDs to Intune managed devices
            Write-Status "Found $($deviceMembers.Count) device members, mapping to Intune..."
            foreach ($dm in $deviceMembers) {
                $entraDeviceId = $dm.deviceId
                if ($entraDeviceId) {
                    $intuneDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$entraDeviceId'"
                    $targetDevices += $intuneDevices
                }
            }
        }

        if ($targetDevices.Count -eq 0) {
            Write-Host "  ERROR: No Intune managed devices found for group '$GroupName'." -ForegroundColor Red
            return
        }
        Write-Status "$($targetDevices.Count) managed devices resolved from group" "Green"
    }
    default {
        # All devices
        Write-Status "Retrieving all managed devices..."
        $targetDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,complianceState,complianceGracePeriodExpirationDateTime,lastSyncDateTime,operatingSystem,osVersion,model,manufacturer,serialNumber,managedDeviceOwnerType,enrolledDateTime"
        Write-Status "$($targetDevices.Count) managed devices retrieved" "Green"
    }
}
#endregion

#region --- Compliance Analysis ---
Write-Section "ANALYZING COMPLIANCE STATUS"

# Summary counters
$totalDevices      = $targetDevices.Count
$compliantCount    = 0
$nonCompliantCount = 0
$inGraceCount      = 0
$unknownCount      = 0
$notEvalCount      = 0

$complianceReport = [System.Collections.Generic.List[PSCustomObject]]::new()
$deviceIndex = 0

foreach ($device in $targetDevices) {
    $deviceIndex++
    $pctComplete = [math]::Round(($deviceIndex / $totalDevices) * 100)
    Write-Progress -Activity "Analyzing device compliance" -Status "$deviceIndex of $totalDevices - $($device.deviceName)" -PercentComplete $pctComplete

    $compState = $device.complianceState
    $graceExpiry = $device.complianceGracePeriodExpirationDateTime
    $lastSync = $device.lastSyncDateTime

    # Classify device
    switch ($compState) {
        'compliant'    { $compliantCount++ }
        'noncompliant' { $nonCompliantCount++ }
        'inGracePeriod' { $inGraceCount++ }
        'configManager' { $unknownCount++ }
        'unknown'      { $unknownCount++ }
        default        { $notEvalCount++ }
    }

    # Skip compliant devices unless -IncludeCompliant is set
    if ($compState -eq 'compliant' -and -not $IncludeCompliant) { continue }

    # Calculate days since last sync
    $daysSinceSync = if ($lastSync) {
        [math]::Round(((Get-Date) - [datetime]$lastSync).TotalDays, 1)
    } else { 'N/A' }

    # Get detailed compliance policy states for this device
    $policyStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates"

    if ($policyStates.Count -eq 0) {
        # No compliance policies evaluated - report as a single row
        $complianceReport.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OverallCompliance = $compState
            OperatingSystem   = $device.operatingSystem
            OSVersion         = $device.osVersion
            Model             = $device.model
            Manufacturer      = $device.manufacturer
            SerialNumber      = $device.serialNumber
            Ownership         = $device.managedDeviceOwnerType
            LastSyncDateTime  = $lastSync
            DaysSinceSync     = $daysSinceSync
            EnrolledDateTime  = $device.enrolledDateTime
            GraceExpiry       = $graceExpiry
            PolicyName        = '(No compliance policy assigned)'
            PolicyState       = $compState
            SettingName       = '-'
            SettingState      = '-'
            SettingDetail     = '-'
            DeviceId          = $device.id
        })
        continue
    }

    foreach ($ps in $policyStates) {
        $policyState = $ps.state
        $policyName  = $ps.displayName
        if (-not $policyName) { $policyName = "(Policy ID: $($ps.id))" }

        # For non-compliant policies, get the specific setting states
        if ($policyState -eq 'nonCompliant' -or $policyState -eq 'error' -or $policyState -eq 'conflict') {
            $settingStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates/$($ps.id)/settingStates"

            $nonCompliantSettings = $settingStates | Where-Object {
                $_.state -ne 'compliant' -and $_.state -ne 'notApplicable'
            }

            if ($nonCompliantSettings.Count -gt 0) {
                foreach ($ss in $nonCompliantSettings) {
                    $settingDetail = if ($ss.currentValue) { $ss.currentValue } else { '-' }

                    $complianceReport.Add([PSCustomObject]@{
                        DeviceName        = $device.deviceName
                        UserPrincipalName = $device.userPrincipalName
                        OverallCompliance = $compState
                        OperatingSystem   = $device.operatingSystem
                        OSVersion         = $device.osVersion
                        Model             = $device.model
                        Manufacturer      = $device.manufacturer
                        SerialNumber      = $device.serialNumber
                        Ownership         = $device.managedDeviceOwnerType
                        LastSyncDateTime  = $lastSync
                        DaysSinceSync     = $daysSinceSync
                        EnrolledDateTime  = $device.enrolledDateTime
                        GraceExpiry       = $graceExpiry
                        PolicyName        = $policyName
                        PolicyState       = $policyState
                        SettingName       = $ss.setting
                        SettingState      = $ss.state
                        SettingDetail     = $settingDetail
                        DeviceId          = $device.id
                    })
                }
            } else {
                # Policy is non-compliant but no specific settings flagged
                $complianceReport.Add([PSCustomObject]@{
                    DeviceName        = $device.deviceName
                    UserPrincipalName = $device.userPrincipalName
                    OverallCompliance = $compState
                    OperatingSystem   = $device.operatingSystem
                    OSVersion         = $device.osVersion
                    Model             = $device.model
                    Manufacturer      = $device.manufacturer
                    SerialNumber      = $device.serialNumber
                    Ownership         = $device.managedDeviceOwnerType
                    LastSyncDateTime  = $lastSync
                    DaysSinceSync     = $daysSinceSync
                    EnrolledDateTime  = $device.enrolledDateTime
                    GraceExpiry       = $graceExpiry
                    PolicyName        = $policyName
                    PolicyState       = $policyState
                    SettingName       = '(No specific setting reported)'
                    SettingState      = $policyState
                    SettingDetail     = '-'
                    DeviceId          = $device.id
                })
            }
        } elseif ($IncludeCompliant -or $policyState -ne 'compliant') {
            # Include compliant policy rows if requested, or non-standard states
            $complianceReport.Add([PSCustomObject]@{
                DeviceName        = $device.deviceName
                UserPrincipalName = $device.userPrincipalName
                OverallCompliance = $compState
                OperatingSystem   = $device.operatingSystem
                OSVersion         = $device.osVersion
                Model             = $device.model
                Manufacturer      = $device.manufacturer
                SerialNumber      = $device.serialNumber
                Ownership         = $device.managedDeviceOwnerType
                LastSyncDateTime  = $lastSync
                DaysSinceSync     = $daysSinceSync
                EnrolledDateTime  = $device.enrolledDateTime
                GraceExpiry       = $graceExpiry
                PolicyName        = $policyName
                PolicyState       = $policyState
                SettingName       = '-'
                SettingState      = $policyState
                SettingDetail     = '-'
                DeviceId          = $device.id
            })
        }
    }
}

Write-Progress -Activity "Analyzing device compliance" -Completed
#endregion

#region --- Summary ---
Write-Section "COMPLIANCE SUMMARY"
Write-Host ""

# Overall status
$scopeText = switch ($PSCmdlet.ParameterSetName) {
    'ByDevice' { "Device: $DeviceName" }
    'ByGroup'  { "Group: $GroupName" }
    default    { "All managed devices" }
}

Write-Host "  Scope              : $scopeText" -ForegroundColor White
Write-Host "  Total devices      : $totalDevices" -ForegroundColor White
Write-Host ""
Write-Host "  Compliant          : $compliantCount" -ForegroundColor Green
Write-Host "  Non-Compliant      : $nonCompliantCount" -ForegroundColor $(if($nonCompliantCount -gt 0){'Red'}else{'Green'})
Write-Host "  In Grace Period    : $inGraceCount" -ForegroundColor $(if($inGraceCount -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "  Unknown/ConfigMgr  : $unknownCount" -ForegroundColor $(if($unknownCount -gt 0){'Yellow'}else{'DarkGray'})
Write-Host "  Not Evaluated      : $notEvalCount" -ForegroundColor $(if($notEvalCount -gt 0){'Yellow'}else{'DarkGray'})

if ($totalDevices -gt 0) {
    $complianceRate = [math]::Round(($compliantCount / $totalDevices) * 100, 1)
    $rateColor = if ($complianceRate -ge 95) { 'Green' } elseif ($complianceRate -ge 80) { 'Yellow' } else { 'Red' }
    Write-Host ""
    Write-Host "  Compliance Rate    : $complianceRate%" -ForegroundColor $rateColor
}

# Non-compliant device details
if ($complianceReport.Count -gt 0) {
    Write-Host ""

    # Group by device for console display
    $deviceGroups = $complianceReport | Group-Object DeviceName | Sort-Object Name
    $displayCount = [math]::Min($deviceGroups.Count, 25)

    Write-Section "NON-COMPLIANT DEVICE DETAILS$(if($deviceGroups.Count -gt 25){" (showing first 25 of $($deviceGroups.Count))"})"
    Write-Host ""

    foreach ($dg in ($deviceGroups | Select-Object -First 25)) {
        $firstRow = $dg.Group[0]
        $compColor = switch ($firstRow.OverallCompliance) {
            'noncompliant'  { 'Red' }
            'inGracePeriod' { 'Yellow' }
            'unknown'       { 'DarkYellow' }
            'compliant'     { 'Green' }
            default         { 'Gray' }
        }

        Write-Host "  $($dg.Name)" -ForegroundColor White -NoNewline
        Write-Host " | $($firstRow.UserPrincipalName)" -ForegroundColor Gray -NoNewline
        Write-Host " | $($firstRow.OverallCompliance)" -ForegroundColor $compColor
        Write-Host "    $($firstRow.OperatingSystem) $($firstRow.OSVersion) | $($firstRow.Model) | Serial: $($firstRow.SerialNumber)" -ForegroundColor DarkGray
        Write-Host "    Last sync: $($firstRow.LastSyncDateTime) ($($firstRow.DaysSinceSync) days ago)" -ForegroundColor DarkGray

        # Show failed policies and settings
        $failedPolicies = $dg.Group | Where-Object { $_.PolicyState -ne 'compliant' } | Group-Object PolicyName
        foreach ($fp in $failedPolicies) {
            $policyColor = switch ($fp.Group[0].PolicyState) {
                'nonCompliant' { 'Red' }
                'error'        { 'Magenta' }
                'conflict'     { 'DarkYellow' }
                default        { 'Yellow' }
            }
            Write-Host "    POLICY: $($fp.Name) [$($fp.Group[0].PolicyState)]" -ForegroundColor $policyColor

            foreach ($setting in $fp.Group) {
                if ($setting.SettingName -ne '-' -and $setting.SettingName -ne '(No specific setting reported)') {
                    Write-Host "      Setting: $($setting.SettingName)" -ForegroundColor White -NoNewline
                    Write-Host " [$($setting.SettingState)]" -ForegroundColor Red
                    if ($setting.SettingDetail -ne '-') {
                        Write-Host "        Current value: $($setting.SettingDetail)" -ForegroundColor DarkGray
                    }
                }
            }
        }
        Write-Host ""
    }

    # Top failing policies summary
    $failingPolicies = $complianceReport | Where-Object { $_.PolicyState -ne 'compliant' -and $_.PolicyName -ne '(No compliance policy assigned)' }
    if ($failingPolicies.Count -gt 0) {
        Write-Section "TOP FAILING POLICIES"
        Write-Host ""
        $policyRanking = $failingPolicies | Group-Object PolicyName | Sort-Object Count -Descending | Select-Object -First 10
        foreach ($pr in $policyRanking) {
            $uniqueDevices = ($pr.Group | Select-Object -Property DeviceName -Unique).Count
            Write-Host "  $($pr.Name)" -ForegroundColor Yellow
            Write-Host "    Failures: $($pr.Count) setting violations across $uniqueDevices device(s)" -ForegroundColor DarkCyan
        }
        Write-Host ""
    }

    # Top failing settings summary
    $failingSettings = $complianceReport | Where-Object { $_.SettingState -ne 'compliant' -and $_.SettingState -ne '-' -and $_.SettingName -ne '-' -and $_.SettingName -ne '(No specific setting reported)' }
    if ($failingSettings.Count -gt 0) {
        Write-Section "TOP FAILING SETTINGS"
        Write-Host ""
        $settingRanking = $failingSettings | Group-Object SettingName | Sort-Object Count -Descending | Select-Object -First 10
        foreach ($sr in $settingRanking) {
            $uniqueDevices = ($sr.Group | Select-Object -Property DeviceName -Unique).Count
            Write-Host "  $($sr.Name)" -ForegroundColor Yellow
            Write-Host "    Failed on $uniqueDevices device(s)" -ForegroundColor DarkCyan
        }
        Write-Host ""
    }

    # Devices with no compliance policy
    $noPolicyDevices = $complianceReport | Where-Object { $_.PolicyName -eq '(No compliance policy assigned)' }
    if ($noPolicyDevices.Count -gt 0) {
        Write-Section "DEVICES WITH NO COMPLIANCE POLICY"
        Write-Host ""
        Write-Host "  $($noPolicyDevices.Count) device(s) have no compliance policy assigned:" -ForegroundColor Yellow
        foreach ($npd in ($noPolicyDevices | Select-Object -First 15)) {
            Write-Host "    - $($npd.DeviceName) ($($npd.UserPrincipalName))" -ForegroundColor White
        }
        if ($noPolicyDevices.Count -gt 15) {
            Write-Host "    ... and $($noPolicyDevices.Count - 15) more (see CSV export)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

# Export
if ($complianceReport.Count -gt 0) {
    if ($ExportPath) {
        $complianceReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status "Exported $($complianceReport.Count) rows to: $ExportPath" "Green"
    } else {
        $scopeSafe = switch ($PSCmdlet.ParameterSetName) {
            'ByDevice' { $DeviceName -replace '[^\w\-]','_' }
            'ByGroup'  { $GroupName -replace '[^\w\-]','_' }
            default    { 'AllDevices' }
        }
        $defaultPath = Join-Path $env:TEMP "$scopeSafe`_ComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $complianceReport | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported $($complianceReport.Count) rows to: $defaultPath" "Green"
    }
} elseif ($complianceReport.Count -eq 0 -and -not $IncludeCompliant) {
    Write-Host ""
    Write-Host "  All devices are compliant. Use -IncludeCompliant to generate a full report." -ForegroundColor Green
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


