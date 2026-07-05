#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Windows patch compliance across all Intune managed devices.
.DESCRIPTION
    Pulls OS version data from all Windows managed devices and produces a
    patch compliance report showing: OS build distribution, devices on each
    build, how many builds behind each device is, devices stuck on old
    versions, and a breakdown by Windows version (21H2, 22H2, 23H2, 24H2, 25H2).
.PARAMETER MinBuild
    Minimum acceptable OS build number (e.g., "10.0.26100.0" for 24H2).
    Devices below this are flagged as outdated.
.PARAMETER GroupName
    Optional. Scope to devices in a specific Entra group.
.PARAMETER ExportPath
    Optional. Export results to CSV.
.EXAMPLE
    .\Get-IntunePatchCompliance.ps1
.EXAMPLE
    .\Get-IntunePatchCompliance.ps1 -MinBuild "10.0.22631.0"
#>

[CmdletBinding()]
param(
    [Parameter()][string]$MinBuild,
    [Parameter()][string]$GroupName,
    [Parameter()][string]$ExportPath
)

#region --- Helpers ---
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

# Windows build to version name mapping
$buildMap = @{
    '19041' = 'Windows 10 2004'
    '19042' = 'Windows 10 20H2'
    '19043' = 'Windows 10 21H1'
    '19044' = 'Windows 10 21H2'
    '19045' = 'Windows 10 22H2'
    '22000' = 'Windows 11 21H2'
    '22621' = 'Windows 11 22H2'
    '22631' = 'Windows 11 23H2'
    '26100' = 'Windows 11 24H2'
    '26200' = 'Windows 11 25H2'
}

function Get-WindowsVersion {
    param([string]$OsVersion)
    if (-not $OsVersion) { return 'Unknown' }
    $parts = $OsVersion -split '\.'
    if ($parts.Count -ge 3) {
        $build = $parts[2]
        if ($buildMap.ContainsKey($build)) { return $buildMap[$build] }
    }
    return "Build $OsVersion"
}
#endregion

#region --- Auth ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All','Device.Read.All','Group.Read.All','GroupMember.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Get Devices ---
Write-Section "COLLECTING WINDOWS DEVICES"

$filter = "operatingSystem eq 'Windows'"
$select = "id,deviceName,osVersion,operatingSystem,complianceState,lastSyncDateTime,userPrincipalName,model,manufacturer,serialNumber"
$devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=$filter&`$select=$select"
Write-Status "Found $($devices.Count) Windows devices total" "Green"

# Filter by group if specified
if ($GroupName) {
    Write-Status "Filtering to group: $GroupName..."
    $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$GroupName'&`$select=id,displayName"
    if ($groups.Count -eq 0) { Write-Host "  ERROR: Group not found." -ForegroundColor Red; return }
    $groupId = $groups[0].id
    $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,deviceId"
    $memberDeviceIds = $members | ForEach-Object { $_.deviceId }
    $devices = $devices | Where-Object { $_.azureADDeviceId -in $memberDeviceIds -or $_.id -in ($members | ForEach-Object { $_.id }) }
    Write-Status "Filtered to $($devices.Count) devices in group" "Green"
}
#endregion

#region --- Analyze ---
Write-Section "PATCH COMPLIANCE ANALYSIS"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$versionCounts = @{}
$buildCounts = @{}
$outdatedDevices = @()

foreach ($d in $devices) {
    $osVer = $d.osVersion
    $winVer = Get-WindowsVersion $osVer
    $buildNum = if ($osVer -match '10\.0\.(\d+)\.(\d+)') { [int]$Matches[1] } else { 0 }
    $patchLevel = if ($osVer -match '10\.0\.\d+\.(\d+)') { [int]$Matches[1] } else { 0 }

    $isOutdated = $false
    if ($MinBuild) {
        $minParts = $MinBuild -split '\.'
        $minBuildNum = if ($minParts.Count -ge 3) { [int]$minParts[2] } else { 0 }
        $minPatch = if ($minParts.Count -ge 4) { [int]$minParts[3] } else { 0 }
        if ($buildNum -lt $minBuildNum -or ($buildNum -eq $minBuildNum -and $patchLevel -lt $minPatch)) {
            $isOutdated = $true
        }
    }

    $daysSinceSync = if ($d.lastSyncDateTime) {
        [math]::Round(((Get-Date) - [datetime]$d.lastSyncDateTime).TotalDays, 0)
    } else { 999 }

    if (-not $versionCounts.ContainsKey($winVer)) { $versionCounts[$winVer] = 0 }
    $versionCounts[$winVer]++
    if (-not $buildCounts.ContainsKey($osVer)) { $buildCounts[$osVer] = 0 }
    $buildCounts[$osVer]++

    if ($isOutdated) { $outdatedDevices += $d }

    $report.Add([PSCustomObject]@{
        DeviceName      = $d.deviceName
        User            = $d.userPrincipalName
        OSVersion       = $osVer
        WindowsVersion  = $winVer
        BuildNumber     = $buildNum
        PatchLevel      = $patchLevel
        ComplianceState = $d.complianceState
        LastSync        = $d.lastSyncDateTime
        DaysSinceSync   = $daysSinceSync
        Model           = $d.model
        Manufacturer    = $d.manufacturer
        SerialNumber    = $d.serialNumber
        BelowMinBuild   = $isOutdated
    })
}

# Windows version distribution
Write-Host ""
Write-Host "  --- Windows Version Distribution ---" -ForegroundColor Yellow
foreach ($v in ($versionCounts.GetEnumerator() | Sort-Object { $_.Key })) {
    $pct = [math]::Round(($v.Value / $devices.Count) * 100, 1)
    $bar = '*' * [math]::Min([math]::Round($pct / 2), 30)
    $color = if ($v.Key -like '*10*') { 'DarkYellow' } else { 'Green' }
    Write-Host "    $($v.Key.PadRight(25)) : $($v.Value.ToString().PadLeft(4)) ($pct%) $bar" -ForegroundColor $color
}

# Top OS builds
Write-Host ""
Write-Host "  --- Top 15 OS Builds ---" -ForegroundColor Yellow
$topBuilds = $buildCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
foreach ($b in $topBuilds) {
    $pct = [math]::Round(($b.Value / $devices.Count) * 100, 1)
    Write-Host "    $($b.Key.PadRight(22)) : $($b.Value.ToString().PadLeft(4)) devices ($pct%)" -ForegroundColor White
}

# Outdated devices
if ($MinBuild -and $outdatedDevices.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Devices Below Minimum Build: $MinBuild ($($outdatedDevices.Count)) ---" -ForegroundColor Red
    foreach ($od in ($outdatedDevices | Sort-Object { $_.osVersion } | Select-Object -First 20)) {
        Write-Host "    $($od.deviceName) | $($od.osVersion) | $($od.userPrincipalName)" -ForegroundColor DarkYellow
    }
    if ($outdatedDevices.Count -gt 20) { Write-Host "    ... and $($outdatedDevices.Count - 20) more" -ForegroundColor DarkGray }
}

# Windows 10 EOL warning
$win10Count = ($report | Where-Object { $_.WindowsVersion -like '*10*' }).Count
if ($win10Count -gt 0) {
    Write-Host ""
    Write-Host "  WARNING: $win10Count device(s) still on Windows 10 (EOL: Oct 14, 2025)" -ForegroundColor Red
}

# Stale + outdated
$staleAndOld = $report | Where-Object { $_.DaysSinceSync -gt 30 -and $_.BelowMinBuild }
if ($staleAndOld.Count -gt 0) {
    Write-Host ""
    Write-Host "  RISK: $($staleAndOld.Count) device(s) are BOTH outdated AND haven't synced in 30+ days" -ForegroundColor Red
}
#endregion

#region --- Summary & Export ---
Write-Section "SUMMARY"
Write-Host ""
Write-Host "  Total Windows devices  : $($devices.Count)" -ForegroundColor White
Write-Host "  Unique OS builds       : $($buildCounts.Count)" -ForegroundColor White
Write-Host "  Windows versions       : $($versionCounts.Count)" -ForegroundColor White
if ($MinBuild) {
    $compliancePct = [math]::Round((($devices.Count - $outdatedDevices.Count) / [math]::Max($devices.Count, 1)) * 100, 1)
    Write-Host "  At or above min build  : $($devices.Count - $outdatedDevices.Count) ($compliancePct%)" -ForegroundColor $(if($compliancePct -ge 90){'Green'}elseif($compliancePct -ge 70){'Yellow'}else{'Red'})
    Write-Host "  Below minimum build    : $($outdatedDevices.Count)" -ForegroundColor $(if($outdatedDevices.Count -gt 0){'Red'}else{'Green'})
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "PatchCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""
#endregion


