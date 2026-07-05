#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports App Protection Policy (MAM) status across users.
.DESCRIPTION
    Shows which app protection policies exist, their configuration, and
    user check-in status. Identifies users with flagged apps and overall
    MAM enrollment health.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneAppProtectionStatus.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementApps.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# Windows App Protection Policies
Write-Section "WINDOWS APP PROTECTION POLICIES"
$winPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections"
Write-Status "Found $($winPolicies.Count) Windows app protection policies" "Green"

foreach ($p in $winPolicies) {
    Write-Host "    $($p.displayName)" -ForegroundColor White
    Write-Host "      Allowed data transfer  : $($p.allowedOutboundDataTransferDestinations)" -ForegroundColor DarkGray
    Write-Host "      Print blocked          : $($p.printBlocked)" -ForegroundColor DarkGray
    Write-Host "      Org data required      : $($p.isAssigned)" -ForegroundColor DarkGray

    $report.Add([PSCustomObject]@{
        PolicyName=$p.displayName; PolicyType='Windows MAM'; Platform='Windows'
        IsAssigned=$p.isAssigned; PrintBlocked=$p.printBlocked
        AllowedTransfer=$p.allowedOutboundDataTransferDestinations
        CreatedDateTime=$p.createdDateTime; LastModified=$p.lastModifiedDateTime
    })
}

# MAM managed app statuses
Write-Section "MANAGED APP REGISTRATIONS"
Write-Status "Fetching managed app registrations..."
$managedAppRegs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/managedAppRegistrations?`$top=100"
Write-Status "Found $($managedAppRegs.Count) managed app registrations" "Green"

$userAppCounts = @{}
$platformCounts = @{}

foreach ($reg in $managedAppRegs) {
    $userId = $reg.userId
    $platform = $reg.deviceType
    if ($null -ne $userId) {
        if (-not $userAppCounts.ContainsKey($userId)) { $userAppCounts[$userId] = 0 }
        $userAppCounts[$userId]++
    }
    if ($null -ne $platform) {
        if (-not $platformCounts.ContainsKey($platform)) { $platformCounts[$platform] = 0 }
        $platformCounts[$platform]++
    }
}

Write-Host ""
Write-Host "  Unique users with managed apps : $($userAppCounts.Count)" -ForegroundColor White
Write-Host "  Total app registrations        : $($managedAppRegs.Count)" -ForegroundColor White

if ($platformCounts.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- By Platform ---" -ForegroundColor Yellow
    foreach ($pc in ($platformCounts.GetEnumerator() | Sort-Object Value -Descending)) {
        Write-Host "    $($pc.Key) : $($pc.Value)" -ForegroundColor White
    }
}

# Flagged users
$flaggedUsers = $managedAppRegs | Where-Object { $_.flaggedReasons -and $_.flaggedReasons.Count -gt 0 }
if ($flaggedUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Flagged Users ($($flaggedUsers.Count)) ---" -ForegroundColor Red
    foreach ($fu in ($flaggedUsers | Select-Object -First 15)) {
        Write-Host "    User: $($fu.userId) | Reason: $($fu.flaggedReasons -join ', ')" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "AppProtectionStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


