#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Shows a comprehensive timeline of everything that happened to a single device.
.DESCRIPTION
    Pulls all available data for one device: enrollment info, compliance evaluations,
    configuration profile states, app installation status, script execution results,
    detected apps, and hardware details. Presents as a chronological timeline for
    troubleshooting "what changed on this device?"
.PARAMETER DeviceName
    The Intune device name.
.PARAMETER ExportPath
    Optional. Export timeline to CSV.
.EXAMPLE
    .\Get-IntuneDeviceTimeline.ps1 -DeviceName "CYBR-PW00K4WR"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DeviceName,
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
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All','Device.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "RESOLVING DEVICE: $DeviceName"
$devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'"
if ($devices.Count -eq 0) { Write-Host "  ERROR: Device not found." -ForegroundColor Red; return }
$device = $devices[0]
$deviceId = $device.id

# Device info
Write-Host ""
Write-Host "  Device Name      : $($device.deviceName)" -ForegroundColor White
Write-Host "  Serial Number    : $($device.serialNumber)" -ForegroundColor Gray
Write-Host "  Model            : $($device.manufacturer) $($device.model)" -ForegroundColor Gray
Write-Host "  OS               : $($device.operatingSystem) $($device.osVersion)" -ForegroundColor Gray
Write-Host "  Primary User     : $($device.userPrincipalName)" -ForegroundColor White
Write-Host "  Entra Device ID  : $($device.azureADDeviceId)" -ForegroundColor Gray
Write-Host "  Compliance       : $($device.complianceState)" -ForegroundColor $(if($device.complianceState -eq 'compliant'){'Green'}else{'Red'})
Write-Host "  Management Agent : $($device.managementAgent)" -ForegroundColor Gray
Write-Host "  Ownership        : $($device.managedDeviceOwnerType)" -ForegroundColor Gray
Write-Host "  Encrypted        : $($device.isEncrypted)" -ForegroundColor Gray
Write-Host "  Enrolled         : $($device.enrolledDateTime)" -ForegroundColor Gray
Write-Host "  Last Sync        : $($device.lastSyncDateTime)" -ForegroundColor Gray

$timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

# Enrollment event
if ($device.enrolledDateTime) {
    $timeline.Add([PSCustomObject]@{ Timestamp=$device.enrolledDateTime; Category='Enrollment'; Event='Device enrolled'; Detail="User: $($device.userPrincipalName)"; State='Success' })
}
if ($device.lastSyncDateTime) {
    $timeline.Add([PSCustomObject]@{ Timestamp=$device.lastSyncDateTime; Category='Sync'; Event='Last sync check-in'; Detail='Device checked in with Intune'; State='Info' })
}

# Configuration profile states
Write-Section "CONFIGURATION PROFILE STATES"
$configStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/deviceConfigurationStates"
Write-Status "$($configStates.Count) configuration profile states" "Green"

foreach ($cs in $configStates) {
    $stateColor = switch ($cs.state) { 'compliant'{'Green'} 'conflict'{'Red'} 'error'{'Red'} 'notApplicable'{'DarkGray'} default{'Yellow'} }
    Write-Host "    [$($cs.state.ToUpper().PadRight(12))] $($cs.displayName)" -ForegroundColor $stateColor

    $ts = if ($cs.lastModifiedDateTime) { $cs.lastModifiedDateTime } elseif ($device.lastSyncDateTime) { $device.lastSyncDateTime } else { Get-Date -Format 'o' }
    $timeline.Add([PSCustomObject]@{ Timestamp=$ts; Category='Config Profile'; Event=$cs.displayName; Detail="State: $($cs.state)"; State=$cs.state })
}

# Compliance policy states
Write-Section "COMPLIANCE POLICY STATES"
$compStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/deviceCompliancePolicyStates"
Write-Status "$($compStates.Count) compliance policy states" "Green"

foreach ($cs in $compStates) {
    $stateColor = switch ($cs.state) { 'compliant'{'Green'} 'nonCompliant'{'Red'} 'conflict'{'Red'} default{'Yellow'} }
    Write-Host "    [$($cs.state.ToUpper().PadRight(12))] $($cs.displayName)" -ForegroundColor $stateColor

    $ts = if ($cs.lastModifiedDateTime) { $cs.lastModifiedDateTime } else { $device.lastSyncDateTime }
    $timeline.Add([PSCustomObject]@{ Timestamp=$ts; Category='Compliance'; Event=$cs.displayName; Detail="State: $($cs.state)"; State=$cs.state })
}

# App installation states
Write-Section "APP INSTALLATION STATES"
Write-Status "Fetching app install statuses for device..."
$appStatuses = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/managedDeviceOverview"

# Try per-device app status
$deviceApps = @()
try {
    $response = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/detectedApps" -Method GET -ErrorAction Stop
    if ($response.value) { $deviceApps = $response.value }
} catch { }

if ($deviceApps.Count -gt 0) {
    Write-Status "$($deviceApps.Count) detected apps" "Green"
    $topApps = $deviceApps | Sort-Object displayName | Select-Object -First 20
    foreach ($app in $topApps) {
        Write-Host "    $($app.displayName) v$($app.version)" -ForegroundColor White
        $timeline.Add([PSCustomObject]@{ Timestamp=$device.lastSyncDateTime; Category='Detected App'; Event=$app.displayName; Detail="Version: $($app.version)"; State='Info' })
    }
    if ($deviceApps.Count -gt 20) { Write-Host "    ... and $($deviceApps.Count - 20) more detected apps" -ForegroundColor DarkGray }
} else {
    Write-Host "    No detected app data available via this endpoint" -ForegroundColor DarkGray
}

# Hardware info
Write-Section "HARDWARE DETAILS"
$hwInfo = $device.hardwareInformation
if ($hwInfo) {
    if ($hwInfo.totalStorageSpace -and $hwInfo.totalStorageSpace -gt 0) {
        $totalGB = [math]::Round($hwInfo.totalStorageSpace / 1GB, 1)
        $freeGB = [math]::Round($hwInfo.freeStorageSpace / 1GB, 1)
        $usedPct = [math]::Round((($hwInfo.totalStorageSpace - $hwInfo.freeStorageSpace) / $hwInfo.totalStorageSpace) * 100, 1)
        Write-Host "    Storage: $freeGB GB free of $totalGB GB ($usedPct% used)" -ForegroundColor $(if($usedPct -gt 90){'Red'}elseif($usedPct -gt 80){'Yellow'}else{'White'})
    }
    if ($hwInfo.totalRam) {
        Write-Host "    RAM: $([math]::Round($hwInfo.totalRam / 1GB, 1)) GB" -ForegroundColor White
    }
    if ($hwInfo.wiredIPv4Addresses) { Write-Host "    Wired IP: $($hwInfo.wiredIPv4Addresses -join ', ')" -ForegroundColor Gray }
    if ($hwInfo.wifiMacAddress) { Write-Host "    WiFi MAC: $($hwInfo.wifiMacAddress)" -ForegroundColor Gray }
} else {
    # Try to get extended hardware info
    try {
        $fullDevice = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId`?`$select=hardwareInformation,physicalMemoryInBytes" -Method GET -ErrorAction Stop
        if ($fullDevice.physicalMemoryInBytes) {
            Write-Host "    RAM: $([math]::Round($fullDevice.physicalMemoryInBytes / 1GB, 1)) GB" -ForegroundColor White
        }
    } catch { Write-Host "    Hardware details not available" -ForegroundColor DarkGray }
}

# Defender protection state
Write-Section "DEFENDER STATUS"
try {
    $protState = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/windowsProtectionState" -Method GET -ErrorAction Stop
    Write-Host "    Real-time protection : $($protState.realTimeProtectionEnabled)" -ForegroundColor $(if($protState.realTimeProtectionEnabled){'Green'}else{'Red'})
    Write-Host "    Engine version       : $($protState.engineVersion)" -ForegroundColor White
    Write-Host "    Signature version    : $($protState.antiVirusSignatureVersion)" -ForegroundColor White
    Write-Host "    Signature updated    : $($protState.antiVirusSignatureLastUpdateDateTime)" -ForegroundColor White
    Write-Host "    Last quick scan      : $($protState.lastQuickScanDateTime)" -ForegroundColor White
    Write-Host "    Last full scan       : $($protState.lastFullScanDateTime)" -ForegroundColor Gray
    Write-Host "    Malware protection   : $($protState.malwareProtectionEnabled)" -ForegroundColor $(if($protState.malwareProtectionEnabled){'Green'}else{'Red'})
} catch {
    Write-Host "    Defender data not available" -ForegroundColor DarkGray
}

# Sort timeline chronologically
$timeline = @($timeline | Sort-Object { try { [datetime]$_.Timestamp } catch { [datetime]::MinValue } } -Descending)

Write-Section "DEVICE TIMELINE (newest first)"
Write-Host ""
foreach ($t in ($timeline | Select-Object -First 50)) {
    $stateColor = switch ($t.State) { 'compliant'{'Green'} 'Success'{'Green'} 'conflict'{'Red'} 'error'{'Red'} 'nonCompliant'{'Red'} 'notApplicable'{'DarkGray'} 'Info'{'Cyan'} default{'White'} }
    $tsDisplay = try { ([datetime]$t.Timestamp).ToString('yyyy-MM-dd HH:mm') } catch { $t.Timestamp }
    Write-Host "  $tsDisplay  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[$($t.Category.PadRight(15))] " -ForegroundColor DarkCyan -NoNewline
    Write-Host "$($t.Event)" -ForegroundColor $stateColor
    if ($t.Detail -and $t.Detail -ne "State: $($t.State)") {
        Write-Host "                                    $($t.Detail)" -ForegroundColor DarkGray
    }
}
if ($timeline.Count -gt 50) { Write-Host "  ... $($timeline.Count - 50) more events (see CSV)" -ForegroundColor DarkGray }

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "$($DeviceName)_Timeline_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$timeline | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


