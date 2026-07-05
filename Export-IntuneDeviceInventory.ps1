#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Exports a comprehensive Intune device inventory with hardware, OS,
    compliance, encryption, storage, and enrollment details.
.DESCRIPTION
    Queries Microsoft Graph to build a complete device inventory report
    combining data from Intune managed devices and Entra ID device records.
    Includes hardware specs, OS versions, compliance state, BitLocker/encryption
    status, storage capacity, primary user details, enrollment info, and
    management state. Designed for asset management, auditing, and lifecycle
    planning.
.PARAMETER OSFilter
    Filter by operating system (e.g., "Windows", "iOS", "Android", "macOS").
.PARAMETER GroupName
    Scope to devices in a specific Entra ID group.
.PARAMETER IncludeDetectedApps
    Add a count of detected (discovered) apps per device. Slower but useful
    for software auditing.
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Export-IntuneDeviceInventory.ps1
    # Full inventory of all managed devices
.EXAMPLE
    .\Export-IntuneDeviceInventory.ps1 -OSFilter "Windows" -ExportPath "C:\temp\windows_inventory.csv"
    # Windows devices only
.EXAMPLE
    .\Export-IntuneDeviceInventory.ps1 -GroupName "SG-Intune-Pilot" -IncludeDetectedApps
    # Devices in a group with app counts
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OSFilter,

    [Parameter()]
    [string]$GroupName,

    [Parameter()]
    [switch]$IncludeDetectedApps,

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

function ConvertTo-GB {
    param([long]$Bytes)
    if ($Bytes -le 0) { return '-' }
    return [math]::Round($Bytes / 1GB, 1)
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
        'Group.Read.All',
        'GroupMember.Read.All',
        'User.Read.All',
        'DeviceManagementApps.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Retrieve Devices ---
Write-Section "RETRIEVING MANAGED DEVICES"

$targetDevices = @()

if ($GroupName) {
    Write-Status "Resolving group: $GroupName"
    $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($GroupName -replace "'","''")'"
    if ($groups.Count -eq 0) {
        Write-Host "  ERROR: Group '$GroupName' not found in Entra ID." -ForegroundColor Red
        return
    }
    $groupId = $groups[0].id
    Write-Status "Group found: $($groups[0].displayName)"

    # Get device members
    Write-Status "Getting device members from group..."
    $groupMembers = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,deviceId,displayName,@odata.type"
    $deviceMembers = $groupMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }

    if ($deviceMembers.Count -gt 0) {
        Write-Status "Found $($deviceMembers.Count) device members, mapping to Intune..."
        foreach ($dm in $deviceMembers) {
            if ($dm.deviceId) {
                $intuneDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($dm.deviceId)'"
                $targetDevices += $intuneDevices
            }
        }
    } else {
        # Group might contain users - get their devices
        $userMembers = $groupMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
        if ($userMembers.Count -gt 0) {
            Write-Status "Found $($userMembers.Count) user members, retrieving their devices..."
            foreach ($um in $userMembers) {
                $userDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userId eq '$($um.id)'"
                $targetDevices += $userDevices
            }
        }
    }

    if ($targetDevices.Count -eq 0) {
        Write-Host "  ERROR: No Intune managed devices found for group '$GroupName'." -ForegroundColor Red
        return
    }
} else {
    Write-Status "Fetching all managed devices..."
    $targetDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
}

# Apply OS filter
if ($OSFilter) {
    $targetDevices = $targetDevices | Where-Object { $_.operatingSystem -eq $OSFilter }
    Write-Status "Filtered to $($targetDevices.Count) $OSFilter devices" "Green"
} else {
    Write-Status "$($targetDevices.Count) managed devices retrieved" "Green"
}

if ($targetDevices.Count -eq 0) {
    Write-Host "  No devices found matching the specified criteria." -ForegroundColor Red
    return
}
#endregion

#region --- Retrieve Entra ID Device Data ---
Write-Section "ENRICHING WITH ENTRA ID DATA"
Write-Status "Fetching Entra ID device records..."

$entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/devices?`$select=id,deviceId,displayName,approximateLastSignInDateTime,accountEnabled,trustType,registrationDateTime,isManaged,isCompliant,operatingSystem,operatingSystemVersion,profileType,mdmAppId"

$entraLookup = @{}
foreach ($ed in $entraDevices) {
    if ($ed.deviceId) { $entraLookup[$ed.deviceId] = $ed }
}
Write-Status "$($entraDevices.Count) Entra ID records loaded into lookup" "Green"
#endregion

#region --- Build Inventory ---
Write-Section "BUILDING DEVICE INVENTORY"

$inventory = [System.Collections.Generic.List[PSCustomObject]]::new()
$now = Get-Date
$deviceIndex = 0

foreach ($device in $targetDevices) {
    $deviceIndex++
    if ($deviceIndex % 50 -eq 0 -or $deviceIndex -eq 1) {
        Write-Progress -Activity "Building inventory" -Status "$deviceIndex of $($targetDevices.Count) - $($device.deviceName)" -PercentComplete (($deviceIndex / $targetDevices.Count) * 100)
    }

    # Entra ID enrichment
    $entraRecord = if ($device.azureADDeviceId) { $entraLookup[$device.azureADDeviceId] } else { $null }

    $entraLastSignIn     = if ($entraRecord) { $entraRecord.approximateLastSignInDateTime } else { '-' }
    $entraAccountEnabled = if ($entraRecord) { $entraRecord.accountEnabled } else { '-' }
    $entraTrustType      = if ($entraRecord) { $entraRecord.trustType } else { '-' }
    $entraProfileType    = if ($entraRecord) { $entraRecord.profileType } else { '-' }

    # Calculate days since last sync
    $daysSinceSync = if ($device.lastSyncDateTime) {
        [math]::Round(($now - [datetime]$device.lastSyncDateTime).TotalDays, 1)
    } else { 'N/A' }

    # Calculate device age (since enrollment)
    $deviceAge = if ($device.enrolledDateTime) {
        [math]::Round(($now - [datetime]$device.enrolledDateTime).TotalDays)
    } else { 'N/A' }

    # Storage
    $totalStorageGB = ConvertTo-GB $device.totalStorageSpaceInBytes
    $freeStorageGB  = ConvertTo-GB $device.freeStorageSpaceInBytes
    $usedStoragePct = if ($device.totalStorageSpaceInBytes -gt 0 -and $device.freeStorageSpaceInBytes -ge 0) {
        [math]::Round((1 - ($device.freeStorageSpaceInBytes / $device.totalStorageSpaceInBytes)) * 100, 1)
    } else { '-' }

    # Encryption
    $isEncrypted = $device.isEncrypted

    # Supervised (iOS)
    $isSupervised = $device.isSupervised

    # Detected apps count (optional - requires per-device API call)
    $detectedAppCount = '-'
    if ($IncludeDetectedApps) {
        $detectedApps = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/detectedApps?`$select=id"
        $detectedAppCount = $detectedApps.Count
    }

    # Management channel
    $managementAgent = $device.managementAgent
    $joinType = switch ($device.joinType) {
        'azureADJoined'          { 'Azure AD Joined' }
        'azureADRegistered'      { 'Azure AD Registered' }
        'hybridAzureADJoined'    { 'Hybrid Azure AD Joined' }
        default                  { if($entraTrustType -ne '-'){$entraTrustType}else{$device.joinType} }
    }

    # Autopilot
    $autopilotEnrolled = $device.autopilotEnrolled

    $inventory.Add([PSCustomObject]@{
        DeviceName             = $device.deviceName
        UserPrincipalName      = $device.userPrincipalName
        UserDisplayName        = $device.userDisplayName
        OperatingSystem        = $device.operatingSystem
        OSVersion              = $device.osVersion
        SKUFamily              = $device.skuFamily
        Manufacturer           = $device.manufacturer
        Model                  = $device.model
        SerialNumber           = $device.serialNumber
        WiFiMacAddress         = $device.wiFiMacAddress
        EthernetMacAddress     = $device.ethernetMacAddress
        IMEI                   = $device.imei
        PhoneNumber            = $device.phoneNumber
        TotalStorageGB         = $totalStorageGB
        FreeStorageGB          = $freeStorageGB
        StorageUsedPct         = $usedStoragePct
        ComplianceState        = $device.complianceState
        IsEncrypted            = $isEncrypted
        IsSupervised           = $isSupervised
        ManagementAgent        = $managementAgent
        JoinType               = $joinType
        Ownership              = $device.managedDeviceOwnerType
        EnrolledDateTime       = $device.enrolledDateTime
        DeviceAgeDays          = $deviceAge
        LastSyncDateTime       = $device.lastSyncDateTime
        DaysSinceSync          = $daysSinceSync
        AutopilotEnrolled      = $autopilotEnrolled
        DeviceCategory         = $device.deviceCategoryDisplayName
        EntraLastSignIn        = $entraLastSignIn
        EntraAccountEnabled    = $entraAccountEnabled
        EntraTrustType         = $entraTrustType
        EntraProfileType       = $entraProfileType
        DetectedAppCount       = $detectedAppCount
        ComplianceGraceExpiry  = $device.complianceGracePeriodExpirationDateTime
        ManagementState        = $device.managementState
        RegistrationState      = $device.deviceRegistrationState
        AzureADDeviceId        = $device.azureADDeviceId
        IntuneDeviceId         = $device.id
    })
}

Write-Progress -Activity "Building inventory" -Completed
Write-Status "Inventory built for $($inventory.Count) devices" "Green"
#endregion

#region --- Summary ---
Write-Section "INVENTORY SUMMARY"
Write-Host ""

# OS breakdown
Write-Host "  --- Devices by Operating System ---" -ForegroundColor Yellow
$osBrkdown = $inventory | Group-Object OperatingSystem | Sort-Object Count -Descending
foreach ($os in $osBrkdown) {
    Write-Host "    $($os.Name) : $($os.Count)" -ForegroundColor White
}
Write-Host ""

# Compliance breakdown
Write-Host "  --- Compliance State ---" -ForegroundColor Yellow
$compBrkdown = $inventory | Group-Object ComplianceState | Sort-Object Count -Descending
foreach ($cs in $compBrkdown) {
    $compColor = switch ($cs.Name) {
        'compliant'     { 'Green' }
        'noncompliant'  { 'Red' }
        'inGracePeriod' { 'Yellow' }
        default         { 'Gray' }
    }
    Write-Host "    $($cs.Name) : $($cs.Count)" -ForegroundColor $compColor
}
Write-Host ""

# Ownership breakdown
Write-Host "  --- Ownership ---" -ForegroundColor Yellow
$ownBrkdown = $inventory | Group-Object Ownership | Sort-Object Count -Descending
foreach ($ow in $ownBrkdown) {
    Write-Host "    $($ow.Name) : $($ow.Count)" -ForegroundColor White
}
Write-Host ""

# Encryption status
$encryptedCount = ($inventory | Where-Object { $_.IsEncrypted -eq $true }).Count
$notEncryptedCount = ($inventory | Where-Object { $_.IsEncrypted -eq $false }).Count
$unknownEncCount = $inventory.Count - $encryptedCount - $notEncryptedCount
Write-Host "  --- Encryption ---" -ForegroundColor Yellow
Write-Host "    Encrypted     : $encryptedCount" -ForegroundColor Green
Write-Host "    Not Encrypted : $notEncryptedCount" -ForegroundColor $(if($notEncryptedCount -gt 0){'Red'}else{'DarkGray'})
Write-Host "    Unknown       : $unknownEncCount" -ForegroundColor DarkGray
Write-Host ""

# Join type breakdown
Write-Host "  --- Join Type ---" -ForegroundColor Yellow
$joinBrkdown = $inventory | Group-Object JoinType | Sort-Object Count -Descending
foreach ($jt in $joinBrkdown) {
    Write-Host "    $($jt.Name) : $($jt.Count)" -ForegroundColor White
}
Write-Host ""

# Management agent breakdown
Write-Host "  --- Management Agent ---" -ForegroundColor Yellow
$agentBrkdown = $inventory | Group-Object ManagementAgent | Sort-Object Count -Descending
foreach ($ag in $agentBrkdown) {
    Write-Host "    $($ag.Name) : $($ag.Count)" -ForegroundColor White
}
Write-Host ""

# Manufacturer breakdown (top 10)
Write-Host "  --- Top Manufacturers ---" -ForegroundColor Yellow
$mfgBrkdown = $inventory | Group-Object Manufacturer | Sort-Object Count -Descending | Select-Object -First 10
foreach ($mf in $mfgBrkdown) {
    Write-Host "    $($mf.Name) : $($mf.Count)" -ForegroundColor White
}
Write-Host ""

# Model breakdown (top 10)
Write-Host "  --- Top Models ---" -ForegroundColor Yellow
$modelBrkdown = $inventory | Group-Object Model | Sort-Object Count -Descending | Select-Object -First 10
foreach ($md in $modelBrkdown) {
    Write-Host "    $($md.Name) : $($md.Count)" -ForegroundColor White
}
Write-Host ""

# Storage warnings
$lowStorageDevices = $inventory | Where-Object { $_.StorageUsedPct -ne '-' -and [double]$_.StorageUsedPct -ge 90 }
if ($lowStorageDevices.Count -gt 0) {
    Write-Section "LOW STORAGE WARNING (>90% used)"
    Write-Host ""
    foreach ($ls in ($lowStorageDevices | Sort-Object { [double]$_.StorageUsedPct } -Descending | Select-Object -First 15)) {
        Write-Host "    $($ls.DeviceName)" -ForegroundColor White -NoNewline
        Write-Host " | $($ls.StorageUsedPct)% used" -ForegroundColor Red -NoNewline
        Write-Host " | $($ls.FreeStorageGB) GB free of $($ls.TotalStorageGB) GB" -ForegroundColor DarkGray
    }
    if ($lowStorageDevices.Count -gt 15) {
        Write-Host "    ... and $($lowStorageDevices.Count - 15) more (see CSV export)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# OS version distribution (Windows)
$windowsDevices = $inventory | Where-Object { $_.OperatingSystem -eq 'Windows' }
if ($windowsDevices.Count -gt 0) {
    Write-Section "WINDOWS VERSION DISTRIBUTION"
    Write-Host ""
    $winVerBrkdown = $windowsDevices | Group-Object OSVersion | Sort-Object Name -Descending
    foreach ($wv in $winVerBrkdown) {
        $pct = [math]::Round(($wv.Count / $windowsDevices.Count) * 100, 1)
        Write-Host "    $($wv.Name) : $($wv.Count) ($pct%)" -ForegroundColor White
    }
    Write-Host ""
}

# Export
if ($ExportPath) {
    $inventory | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Status "Exported $($inventory.Count) devices to: $ExportPath" "Green"
} else {
    $scopeSafe = if ($GroupName) { $GroupName -replace '[^\w\-]','_' }
                 elseif ($OSFilter) { $OSFilter }
                 else { 'AllDevices' }
    $defaultPath = Join-Path $env:TEMP "$scopeSafe`_DeviceInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $inventory | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
    Write-Status "Auto-exported $($inventory.Count) devices to: $defaultPath" "Green"
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


