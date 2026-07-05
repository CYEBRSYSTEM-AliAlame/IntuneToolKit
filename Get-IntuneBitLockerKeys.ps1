#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves BitLocker recovery keys from Entra ID for Intune managed devices.
.DESCRIPTION
    Operates in two modes:
    1. LOOKUP - Retrieve BitLocker recovery key(s) for a specific device by name,
       serial number, or Entra device ID. Designed for helpdesk key recovery.
    2. AUDIT - Scan all Windows managed devices and report which ones have
       recovery keys escrowed to Entra ID and which are missing. Designed for
       security compliance auditing.
.PARAMETER DeviceName
    Look up recovery keys for a device by Intune device name.
.PARAMETER SerialNumber
    Look up recovery keys for a device by serial number.
.PARAMETER Audit
    Run in audit mode - check all Windows devices for escrowed BitLocker keys.
.PARAMETER GroupName
    Scope the audit to devices in a specific Entra ID group.
.PARAMETER ShowKeys
    Display the actual recovery key values in the console output.
    Without this switch, keys are masked for security. CSV export always
    includes full keys.
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneBitLockerKeys.ps1 -DeviceName "L-PF4Z0HM0" -ShowKeys
    # Retrieve and display recovery keys for a specific device
.EXAMPLE
    .\Get-IntuneBitLockerKeys.ps1 -SerialNumber "PF4Z0HM0"
    # Look up by serial number
.EXAMPLE
    .\Get-IntuneBitLockerKeys.ps1 -Audit -ExportPath "C:\temp\bitlocker_audit.csv"
    # Audit all Windows devices for escrowed keys
.EXAMPLE
    .\Get-IntuneBitLockerKeys.ps1 -Audit -GroupName "SG-Windows-Corporate"
    # Audit devices in a specific group
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$DeviceName,

    [Parameter(Mandatory, ParameterSetName = 'BySerial')]
    [string]$SerialNumber,

    [Parameter(Mandatory, ParameterSetName = 'Audit')]
    [switch]$Audit,

    [Parameter(ParameterSetName = 'Audit')]
    [string]$GroupName,

    [Parameter()]
    [switch]$ShowKeys,

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

function Mask-RecoveryKey {
    param([string]$Key)
    if (-not $Key -or $Key.Length -lt 10) { return '********' }
    return $Key.Substring(0,6) + '****-****-****-****-****-****-' + $Key.Substring($Key.Length - 6)
}

function Get-BitLockerKeysForDevice {
    <#
    .SYNOPSIS
        Retrieves BitLocker recovery keys for a device from Entra ID.
        Requires the Entra device object ID (not the deviceId/azureADDeviceId).
    #>
    param([string]$EntraObjectId, [string]$DeviceDisplayName)

    $keys = @()
    try {
        # Get BitLocker recovery keys associated with this device
        $recoveryKeys = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?`$filter=deviceId eq '$EntraObjectId'"

        foreach ($rk in $recoveryKeys) {
            # Fetch the actual key value
            $keyDetail = $null
            try {
                $keyDetail = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys/$($rk.id)?`$select=key" -Method GET -ErrorAction Stop
            } catch {
                Write-Verbose "Could not retrieve key value for key ID $($rk.id): $_"
            }

            $keys += @{
                KeyId         = $rk.id
                CreatedDateTime = $rk.createdDateTime
                VolumeType    = $rk.volumeType
                RecoveryKey   = if ($keyDetail -and $keyDetail.key) { $keyDetail.key } else { '(Access denied or unavailable)' }
            }
        }
    } catch {
        Write-Verbose "Failed to retrieve BitLocker keys for device $DeviceDisplayName : $_"
    }

    return $keys
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'DeviceManagementManagedDevices.Read.All',
        'BitlockerKey.Read.All',
        'Device.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'GroupMember.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
Write-Host ""
Write-Host "  NOTE: BitLockerKey.Read.All permission is required." -ForegroundColor DarkGray
Write-Host "  Key retrieval is audited in the Entra ID audit log." -ForegroundColor DarkGray
#endregion

if ($Audit) {
    #region --- Audit Mode ---
    Write-Section "BITLOCKER KEY AUDIT"

    # Get target devices
    $targetDevices = @()

    if ($GroupName) {
        Write-Status "Resolving group: $GroupName"
        $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($GroupName -replace "'","''")'"
        if ($groups.Count -eq 0) {
            Write-Host "  ERROR: Group '$GroupName' not found." -ForegroundColor Red
            return
        }
        $groupId = $groups[0].id
        Write-Status "Group: $($groups[0].displayName)"

        $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,deviceId,displayName,@odata.type"
        $deviceMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }

        if ($deviceMembers.Count -gt 0) {
            foreach ($dm in $deviceMembers) {
                if ($dm.deviceId) {
                    $md = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($dm.deviceId)' and operatingSystem eq 'Windows'"
                    $targetDevices += $md
                }
            }
        } else {
            $userMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
            foreach ($um in $userMembers) {
                $ud = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userId eq '$($um.id)' and operatingSystem eq 'Windows'"
                $targetDevices += $ud
            }
        }
    } else {
        Write-Status "Fetching all Windows managed devices..."
        $targetDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,azureADDeviceId,userPrincipalName,serialNumber,complianceState,isEncrypted,operatingSystem,osVersion,model,lastSyncDateTime"
    }

    Write-Status "$($targetDevices.Count) Windows devices to audit" "Green"

    # Build Entra device lookup
    Write-Status "Loading Entra ID device records..."
    $entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,deviceId,displayName"
    $entraLookup = @{}
    foreach ($ed in $entraDevices) {
        if ($ed.deviceId) { $entraLookup[$ed.deviceId] = $ed }
    }

    # Get all BitLocker recovery keys in the tenant
    Write-Status "Fetching all BitLocker recovery keys from Entra ID..."
    $allKeys = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?`$select=id,createdDateTime,deviceId,volumeType"
    Write-Status "$($allKeys.Count) recovery keys found in tenant" "Green"

    # Build a set of Entra object IDs that have keys
    $devicesWithKeys = @{}
    foreach ($k in $allKeys) {
        if ($k.deviceId) {
            if (-not $devicesWithKeys.ContainsKey($k.deviceId)) {
                $devicesWithKeys[$k.deviceId] = @()
            }
            $devicesWithKeys[$k.deviceId] += $k
        }
    }

    $auditReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hasKeyCount = 0
    $missingKeyCount = 0
    $noEntraCount = 0
    $deviceIndex = 0

    foreach ($device in $targetDevices) {
        $deviceIndex++
        if ($deviceIndex % 50 -eq 0) {
            Write-Progress -Activity "Auditing BitLocker keys" -Status "$deviceIndex of $($targetDevices.Count)" -PercentComplete (($deviceIndex / $targetDevices.Count) * 100)
        }

        $entraRecord = if ($device.azureADDeviceId) { $entraLookup[$device.azureADDeviceId] } else { $null }

        if (-not $entraRecord) {
            $noEntraCount++
            $auditReport.Add([PSCustomObject]@{
                DeviceName        = $device.deviceName
                UserPrincipalName = $device.userPrincipalName
                SerialNumber      = $device.serialNumber
                OSVersion         = $device.osVersion
                Model             = $device.model
                IsEncrypted       = $device.isEncrypted
                ComplianceState   = $device.complianceState
                KeyStatus         = 'NO ENTRA RECORD'
                KeyCount          = 0
                LatestKeyDate     = '-'
                VolumeTypes       = '-'
                LastSync          = $device.lastSyncDateTime
                IntuneDeviceId    = $device.id
                EntraDeviceId     = $device.azureADDeviceId
            })
            continue
        }

        $entraObjectId = $entraRecord.id
        $deviceKeys = $devicesWithKeys[$entraObjectId]

        if ($deviceKeys -and $deviceKeys.Count -gt 0) {
            $hasKeyCount++
            $latestKey = ($deviceKeys | Sort-Object createdDateTime -Descending | Select-Object -First 1).createdDateTime
            $volumeTypes = ($deviceKeys | Select-Object -ExpandProperty volumeType -Unique) -join ', '

            $auditReport.Add([PSCustomObject]@{
                DeviceName        = $device.deviceName
                UserPrincipalName = $device.userPrincipalName
                SerialNumber      = $device.serialNumber
                OSVersion         = $device.osVersion
                Model             = $device.model
                IsEncrypted       = $device.isEncrypted
                ComplianceState   = $device.complianceState
                KeyStatus         = 'KEY ESCROWED'
                KeyCount          = $deviceKeys.Count
                LatestKeyDate     = $latestKey
                VolumeTypes       = $volumeTypes
                LastSync          = $device.lastSyncDateTime
                IntuneDeviceId    = $device.id
                EntraDeviceId     = $device.azureADDeviceId
            })
        } else {
            $missingKeyCount++
            $auditReport.Add([PSCustomObject]@{
                DeviceName        = $device.deviceName
                UserPrincipalName = $device.userPrincipalName
                SerialNumber      = $device.serialNumber
                OSVersion         = $device.osVersion
                Model             = $device.model
                IsEncrypted       = $device.isEncrypted
                ComplianceState   = $device.complianceState
                KeyStatus         = 'KEY MISSING'
                KeyCount          = 0
                LatestKeyDate     = '-'
                VolumeTypes       = '-'
                LastSync          = $device.lastSyncDateTime
                IntuneDeviceId    = $device.id
                EntraDeviceId     = $device.azureADDeviceId
            })
        }
    }

    Write-Progress -Activity "Auditing BitLocker keys" -Completed

    # Summary
    Write-Section "BITLOCKER AUDIT SUMMARY"
    Write-Host ""
    Write-Host "  Total Windows devices  : $($targetDevices.Count)" -ForegroundColor White
    Write-Host "  Keys escrowed          : $hasKeyCount" -ForegroundColor Green
    Write-Host "  Keys MISSING           : $missingKeyCount" -ForegroundColor $(if($missingKeyCount -gt 0){'Red'}else{'Green'})
    Write-Host "  No Entra record        : $noEntraCount" -ForegroundColor $(if($noEntraCount -gt 0){'Yellow'}else{'DarkGray'})

    if ($targetDevices.Count -gt 0) {
        $escrowRate = [math]::Round(($hasKeyCount / $targetDevices.Count) * 100, 1)
        $rateColor = if ($escrowRate -ge 95) { 'Green' } elseif ($escrowRate -ge 80) { 'Yellow' } else { 'Red' }
        Write-Host ""
        Write-Host "  Key Escrow Rate        : $escrowRate%" -ForegroundColor $rateColor
    }

    # Show devices missing keys
    $missingDevices = $auditReport | Where-Object { $_.KeyStatus -eq 'KEY MISSING' }
    if ($missingDevices.Count -gt 0) {
        Write-Section "DEVICES MISSING BITLOCKER KEYS ($($missingDevices.Count))"
        Write-Host ""
        foreach ($md in ($missingDevices | Select-Object -First 20)) {
            $encColor = if ($md.IsEncrypted -eq $true) { 'Yellow' } else { 'Red' }
            $encText  = if ($md.IsEncrypted -eq $true) { 'Encrypted (key not escrowed)' } else { 'NOT encrypted' }
            Write-Host "    $($md.DeviceName)" -ForegroundColor White -NoNewline
            Write-Host " | $($md.UserPrincipalName)" -ForegroundColor Gray -NoNewline
            Write-Host " | $encText" -ForegroundColor $encColor
        }
        if ($missingDevices.Count -gt 20) {
            Write-Host "    ... and $($missingDevices.Count - 20) more (see CSV export)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Encrypted but no key - worst case
    $encryptedNoKey = $missingDevices | Where-Object { $_.IsEncrypted -eq $true }
    if ($encryptedNoKey.Count -gt 0) {
        Write-Host "  WARNING: $($encryptedNoKey.Count) device(s) are encrypted but have NO recovery key escrowed!" -ForegroundColor Red
        Write-Host "  If these devices lose their TPM or OS, recovery will be impossible." -ForegroundColor Red
        Write-Host ""
    }

    # Export
    if ($auditReport.Count -gt 0) {
        if ($ExportPath) {
            $auditReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Status "Exported $($auditReport.Count) rows to: $ExportPath" "Green"
        } else {
            $scopeSafe = if ($GroupName) { $GroupName -replace '[^\w\-]','_' } else { 'AllWindows' }
            $defaultPath = Join-Path $env:TEMP "$scopeSafe`_BitLockerAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $auditReport | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
            Write-Status "Auto-exported $($auditReport.Count) rows to: $defaultPath" "Green"
        }
    }
    #endregion

} else {
    #region --- Lookup Mode ---
    Write-Section "BITLOCKER KEY LOOKUP"

    # Resolve the device
    if ($DeviceName) {
        Write-Status "Searching for device: $DeviceName"
        $devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'&`$select=id,deviceName,azureADDeviceId,userPrincipalName,serialNumber,operatingSystem,osVersion,model,manufacturer,isEncrypted,complianceState"
    } else {
        Write-Status "Searching for serial number: $SerialNumber"
        $devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$SerialNumber'&`$select=id,deviceName,azureADDeviceId,userPrincipalName,serialNumber,operatingSystem,osVersion,model,manufacturer,isEncrypted,complianceState"
    }

    if ($devices.Count -eq 0) {
        $searchTerm = if ($DeviceName) { $DeviceName } else { $SerialNumber }
        Write-Host "  ERROR: Device '$searchTerm' not found in Intune." -ForegroundColor Red
        return
    }

    $device = $devices[0]

    Write-Host ""
    Write-Host "  Device Name    : $($device.deviceName)" -ForegroundColor White
    Write-Host "  Serial Number  : $($device.serialNumber)" -ForegroundColor Gray
    Write-Host "  User           : $($device.userPrincipalName)" -ForegroundColor White
    Write-Host "  OS             : $($device.operatingSystem) $($device.osVersion)" -ForegroundColor Gray
    Write-Host "  Model          : $($device.manufacturer) $($device.model)" -ForegroundColor Gray
    Write-Host "  Encrypted      : $($device.isEncrypted)" -ForegroundColor $(if($device.isEncrypted){'Green'}else{'Red'})
    Write-Host "  Compliance     : $($device.complianceState)" -ForegroundColor $(if($device.complianceState -eq 'compliant'){'Green'}else{'Yellow'})

    # Resolve to Entra device object
    $entraDeviceId = $device.azureADDeviceId
    if (-not $entraDeviceId) {
        Write-Host ""
        Write-Host "  ERROR: Device has no Azure AD Device ID. Cannot retrieve BitLocker keys." -ForegroundColor Red
        return
    }

    $entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$entraDeviceId'&`$select=id,deviceId,displayName"
    if ($entraDevices.Count -eq 0) {
        Write-Host ""
        Write-Host "  ERROR: No matching Entra ID device record found." -ForegroundColor Red
        return
    }

    $entraObjectId = $entraDevices[0].id

    # Retrieve keys
    Write-Status "Retrieving BitLocker recovery keys..."
    $keys = Get-BitLockerKeysForDevice -EntraObjectId $entraObjectId -DeviceDisplayName $device.deviceName

    $keyReport = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($keys.Count -eq 0) {
        Write-Host ""
        Write-Host "  No BitLocker recovery keys found for this device in Entra ID." -ForegroundColor Yellow
        if ($device.isEncrypted) {
            Write-Host "  WARNING: Device reports as encrypted but no key is escrowed!" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "  Found $($keys.Count) recovery key(s):" -ForegroundColor Green
        Write-Host ""

        foreach ($key in ($keys | Sort-Object CreatedDateTime -Descending)) {
            $displayKey = if ($ShowKeys) { $key.RecoveryKey } else { Mask-RecoveryKey $key.RecoveryKey }

            Write-Host "    Volume     : $($key.VolumeType)" -ForegroundColor White
            Write-Host "    Key ID     : $($key.KeyId)" -ForegroundColor Gray
            Write-Host "    Created    : $($key.CreatedDateTime)" -ForegroundColor Gray
            Write-Host "    Key        : $displayKey" -ForegroundColor $(if($ShowKeys){'Green'}else{'DarkGray'})
            if (-not $ShowKeys) {
                Write-Host "                 (use -ShowKeys to display full recovery key)" -ForegroundColor DarkGray
            }
            Write-Host ""

            $keyReport.Add([PSCustomObject]@{
                DeviceName    = $device.deviceName
                SerialNumber  = $device.serialNumber
                UserPrincipalName = $device.userPrincipalName
                VolumeType    = $key.VolumeType
                KeyId         = $key.KeyId
                RecoveryKey   = $key.RecoveryKey
                CreatedDateTime = $key.CreatedDateTime
                IsEncrypted   = $device.isEncrypted
                OSVersion     = $device.osVersion
                Model         = "$($device.manufacturer) $($device.model)"
            })
        }
    }

    # Export
    if ($keyReport.Count -gt 0) {
        if ($ExportPath) {
            $keyReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Status "Exported to: $ExportPath" "Green"
            Write-Host "  WARNING: CSV contains full recovery keys. Store securely!" -ForegroundColor Yellow
        } else {
            $safeName = $device.deviceName -replace '[^\w\-]','_'
            $defaultPath = Join-Path $env:TEMP "$safeName`_BitLockerKeys_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $keyReport | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
            Write-Status "Auto-exported to: $defaultPath" "Green"
            Write-Host "  WARNING: CSV contains full recovery keys. Store securely!" -ForegroundColor Yellow
        }
    }
    #endregion
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray


