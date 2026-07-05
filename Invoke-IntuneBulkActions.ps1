#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Performs bulk Intune device actions: sync, restart, BitLocker key rotation,
    Windows Defender scan, and collect diagnostics.
.DESCRIPTION
    Executes a specified remote action against multiple Intune managed devices.
    Devices can be targeted by group membership, OS type, compliance state,
    or a CSV file of device names. Includes safety confirmations, throttling
    to avoid Graph API rate limits, and detailed progress/result tracking.

    SUPPORTED ACTIONS:
    - Sync              : Force device check-in with Intune
    - Restart           : Reboot the device
    - BitLockerRotate   : Rotate BitLocker recovery keys (Windows only)
    - DefenderScan      : Trigger Windows Defender quick scan
    - DefenderSignatures: Update Defender signature definitions
    - CollectDiagnostics: Request diagnostic log collection

.PARAMETER Action
    The remote action to perform. Required.
.PARAMETER GroupName
    Target devices in a specific Entra ID group.
.PARAMETER OSFilter
    Target devices by operating system (e.g., "Windows", "iOS", "Android").
.PARAMETER DeviceNames
    Target specific devices by name (comma-separated or array).
.PARAMETER CsvPath
    Path to a CSV file with a "DeviceName" column listing target devices.
.PARAMETER NonCompliantOnly
    Only target devices in a non-compliant state.
.PARAMETER StaleOnly
    Only target devices that haven't synced in X days (default 7, use -StaleDays to adjust).
.PARAMETER StaleDays
    Days since last sync to consider a device stale. Used with -StaleOnly. Default: 7.
.PARAMETER ThrottleMs
    Milliseconds to wait between API calls to avoid rate limiting. Default: 200.
.PARAMETER Force
    Skip the confirmation prompt.
.PARAMETER ExportPath
    Optional. Export action results to CSV.
.EXAMPLE
    .\Invoke-IntuneBulkActions.ps1 -Action Sync -GroupName "SG-Windows-Pilot"
    # Sync all devices in a group
.EXAMPLE
    .\Invoke-IntuneBulkActions.ps1 -Action Sync -OSFilter "Windows" -StaleOnly -StaleDays 3
    # Sync Windows devices that haven't checked in for 3+ days
.EXAMPLE
    .\Invoke-IntuneBulkActions.ps1 -Action Restart -DeviceNames "PC-001","PC-002" -Force
    # Restart specific devices without confirmation
.EXAMPLE
    .\Invoke-IntuneBulkActions.ps1 -Action DefenderScan -NonCompliantOnly -OSFilter "Windows"
    # Trigger Defender scan on non-compliant Windows devices
.EXAMPLE
    .\Invoke-IntuneBulkActions.ps1 -Action BitLockerRotate -CsvPath "C:\temp\devices.csv"
    # Rotate BitLocker keys for devices listed in a CSV
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByGroup')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Sync','Restart','BitLockerRotate','DefenderScan','DefenderSignatures','CollectDiagnostics')]
    [string]$Action,

    [Parameter(Mandatory, ParameterSetName = 'ByGroup')]
    [string]$GroupName,

    [Parameter(Mandatory, ParameterSetName = 'ByOS')]
    [string]$OSFilter,

    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string[]]$DeviceNames,

    [Parameter(Mandatory, ParameterSetName = 'ByCsv')]
    [string]$CsvPath,

    [Parameter()]
    [switch]$NonCompliantOnly,

    [Parameter()]
    [switch]$StaleOnly,

    [Parameter()]
    [int]$StaleDays = 7,

    [Parameter()]
    [int]$ThrottleMs = 200,

    [Parameter()]
    [switch]$Force,

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

function Get-ActionEndpoint {
    param([string]$ActionName, [string]$DeviceId)
    $base = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId"
    switch ($ActionName) {
        'Sync'                { return "$base/syncDevice" }
        'Restart'             { return "$base/rebootNow" }
        'BitLockerRotate'     { return "$base/rotateBitLockerKeys" }
        'DefenderScan'        { return "$base/windowsDefenderScan" }
        'DefenderSignatures'  { return "$base/windowsDefenderUpdateSignatures" }
        'CollectDiagnostics'  { return "$base/createDeviceLogCollectionRequest" }
    }
}

function Get-ActionDescription {
    param([string]$ActionName)
    switch ($ActionName) {
        'Sync'                { return 'Force device sync (check-in)' }
        'Restart'             { return 'Reboot device' }
        'BitLockerRotate'     { return 'Rotate BitLocker recovery keys' }
        'DefenderScan'        { return 'Trigger Windows Defender quick scan' }
        'DefenderSignatures'  { return 'Update Defender signature definitions' }
        'CollectDiagnostics'  { return 'Collect device diagnostic logs' }
    }
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'DeviceManagementManagedDevices.ReadWrite.All',
        'DeviceManagementManagedDevices.PrivilegedOperations.All',
        'Device.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'GroupMember.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve Target Devices ---
Write-Section "RESOLVING TARGET DEVICES"

$targetDevices = @()

switch ($PSCmdlet.ParameterSetName) {
    'ByGroup' {
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
                    $md = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($dm.deviceId)'&`$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime"
                    $targetDevices += $md
                }
            }
        } else {
            $userMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
            foreach ($um in $userMembers) {
                $ud = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userId eq '$($um.id)'&`$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime"
                $targetDevices += $ud
            }
        }
    }
    'ByOS' {
        Write-Status "Fetching all $OSFilter devices..."
        $targetDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq '$OSFilter'&`$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime"
    }
    'ByName' {
        Write-Status "Looking up $($DeviceNames.Count) device(s) by name..."
        foreach ($name in $DeviceNames) {
            $md = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$name'&`$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime"
            if ($md.Count -eq 0) {
                Write-Host "    WARNING: Device '$name' not found, skipping." -ForegroundColor Yellow
            } else {
                $targetDevices += $md
            }
        }
    }
    'ByCsv' {
        if (-not (Test-Path $CsvPath)) {
            Write-Host "  ERROR: CSV file not found: $CsvPath" -ForegroundColor Red
            return
        }
        $csvData = Import-Csv -Path $CsvPath
        if (-not ($csvData | Get-Member -Name 'DeviceName' -ErrorAction SilentlyContinue)) {
            Write-Host "  ERROR: CSV must contain a 'DeviceName' column." -ForegroundColor Red
            return
        }
        $deviceNameList = $csvData.DeviceName | Where-Object { $_ }
        Write-Status "CSV loaded: $($deviceNameList.Count) device names"

        foreach ($name in $deviceNameList) {
            $md = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$name'&`$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime"
            if ($md.Count -eq 0) {
                Write-Host "    WARNING: Device '$name' not found, skipping." -ForegroundColor Yellow
            } else {
                $targetDevices += $md
            }
        }
    }
}

# Apply additional filters
if ($NonCompliantOnly) {
    $before = $targetDevices.Count
    $targetDevices = $targetDevices | Where-Object { $_.complianceState -ne 'compliant' }
    Write-Status "Filtered to non-compliant: $before -> $($targetDevices.Count) devices"
}

if ($StaleOnly) {
    $staleThreshold = (Get-Date).AddDays(-$StaleDays)
    $before = $targetDevices.Count
    $targetDevices = $targetDevices | Where-Object {
        $_.lastSyncDateTime -and [datetime]$_.lastSyncDateTime -lt $staleThreshold
    }
    Write-Status "Filtered to stale (>$StaleDays days): $before -> $($targetDevices.Count) devices"
}

# Deduplicate
$targetDevices = $targetDevices | Sort-Object -Property id -Unique

if ($targetDevices.Count -eq 0) {
    Write-Host "  No devices found matching the specified criteria." -ForegroundColor Yellow
    return
}

Write-Status "$($targetDevices.Count) device(s) targeted for action" "Green"
#endregion

#region --- Confirmation ---
Write-Section "ACTION CONFIRMATION"
Write-Host ""
Write-Host "  Action      : $Action - $(Get-ActionDescription $Action)" -ForegroundColor White
Write-Host "  Target count: $($targetDevices.Count) device(s)" -ForegroundColor White
Write-Host "  Throttle    : ${ThrottleMs}ms between calls" -ForegroundColor Gray
Write-Host ""

# Show sample of target devices
$showCount = [math]::Min($targetDevices.Count, 10)
Write-Host "  Target devices (showing $showCount of $($targetDevices.Count)):" -ForegroundColor DarkCyan
foreach ($d in ($targetDevices | Select-Object -First 10)) {
    $daysSince = if ($d.lastSyncDateTime) { [math]::Round(((Get-Date) - [datetime]$d.lastSyncDateTime).TotalDays, 1) } else { '?' }
    Write-Host "    $($d.deviceName) | $($d.operatingSystem) | $($d.complianceState) | Sync: ${daysSince}d ago" -ForegroundColor Gray
}
if ($targetDevices.Count -gt 10) {
    Write-Host "    ... and $($targetDevices.Count - 10) more" -ForegroundColor DarkGray
}
Write-Host ""

# Warning for destructive actions
if ($Action -in @('Restart','BitLockerRotate')) {
    Write-Host "  WARNING: '$Action' is a potentially disruptive action!" -ForegroundColor Yellow
    Write-Host "  - Restart will reboot devices immediately" -ForegroundColor Yellow
    Write-Host "  - BitLockerRotate will invalidate current recovery keys" -ForegroundColor Yellow
    Write-Host ""
}

if (-not $Force) {
    $confirm = Read-Host "  Proceed with '$Action' on $($targetDevices.Count) device(s)? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Action cancelled by user." -ForegroundColor Yellow
        return
    }
}
#endregion

#region --- Execute Actions ---
Write-Section "EXECUTING: $Action"

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$successCount = 0
$failCount = 0
$deviceIndex = 0

foreach ($device in $targetDevices) {
    $deviceIndex++
    Write-Progress -Activity "Executing $Action" -Status "$deviceIndex of $($targetDevices.Count) - $($device.deviceName)" -PercentComplete (($deviceIndex / $targetDevices.Count) * 100)

    $endpoint = Get-ActionEndpoint -ActionName $Action -DeviceId $device.id
    $status = 'Success'
    $errorMsg = '-'

    try {
        # Build the request body based on action
        $body = switch ($Action) {
            'DefenderScan' { @{ quickScan = $true } | ConvertTo-Json }
            'CollectDiagnostics' { @{ templateType = @{ '@odata.type' = '#microsoft.graph.deviceLogCollectionRequest' } } | ConvertTo-Json }
            default { $null }
        }

        if ($body) {
            Invoke-MgGraphRequest -Uri $endpoint -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
        } else {
            Invoke-MgGraphRequest -Uri $endpoint -Method POST -ErrorAction Stop | Out-Null
        }

        $successCount++
        Write-Host "    [OK] $($device.deviceName)" -ForegroundColor Green
    }
    catch {
        $failCount++
        $status = 'Failed'
        $errorMsg = $_.Exception.Message -replace "`n",' ' -replace "`r",''
        # Truncate long error messages
        if ($errorMsg.Length -gt 200) { $errorMsg = $errorMsg.Substring(0,197) + '...' }
        Write-Host "    [FAIL] $($device.deviceName) : $errorMsg" -ForegroundColor Red
    }

    $results.Add([PSCustomObject]@{
        DeviceName        = $device.deviceName
        UserPrincipalName = $device.userPrincipalName
        OperatingSystem   = $device.operatingSystem
        ComplianceState   = $device.complianceState
        Action            = $Action
        Status            = $status
        Error             = $errorMsg
        Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        DeviceId          = $device.id
    })

    # Throttle to avoid rate limiting
    if ($deviceIndex -lt $targetDevices.Count) {
        Start-Sleep -Milliseconds $ThrottleMs
    }
}

Write-Progress -Activity "Executing $Action" -Completed
#endregion

#region --- Results Summary ---
Write-Section "ACTION RESULTS: $Action"
Write-Host ""
Write-Host "  Total devices  : $($targetDevices.Count)" -ForegroundColor White
Write-Host "  Successful     : $successCount" -ForegroundColor Green
Write-Host "  Failed         : $failCount" -ForegroundColor $(if($failCount -gt 0){'Red'}else{'DarkGray'})

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "  Failed devices:" -ForegroundColor Yellow
    $failedDevices = $results | Where-Object { $_.Status -eq 'Failed' }
    foreach ($fd in ($failedDevices | Select-Object -First 20)) {
        Write-Host "    $($fd.DeviceName) : $($fd.Error)" -ForegroundColor Red
    }
    if ($failedDevices.Count -gt 20) {
        Write-Host "    ... and $($failedDevices.Count - 20) more (see CSV export)" -ForegroundColor DarkGray
    }
}

# Export
if ($results.Count -gt 0) {
    if ($ExportPath) {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status "Results exported to: $ExportPath" "Green"
    } else {
        $defaultPath = Join-Path $env:TEMP "BulkAction_$($Action)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Results auto-exported to: $defaultPath" "Green"
    }
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


