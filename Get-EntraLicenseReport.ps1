#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Entra ID license utilization and identifies waste.
.DESCRIPTION
    Lists all license SKUs with assigned vs available counts, identifies
    users with no licenses, disabled accounts still consuming licenses,
    and calculates license utilization rates.
.PARAMETER ExportPath
    Optional. Export user license data to CSV.
.EXAMPLE
    .\Get-EntraLicenseReport.ps1
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
    Connect-MgGraph -Scopes 'Organization.Read.All','User.Read.All','Directory.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

# Get subscribed SKUs
Write-Section "LICENSE SKU OVERVIEW"
$skus = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
Write-Status "$($skus.Count) license SKUs" "Green"
Write-Host ""

$totalPurchased = 0; $totalConsumed = 0; $totalAvailable = 0

foreach ($sku in ($skus | Sort-Object skuPartNumber)) {
    $purchased = $sku.prepaidUnits.enabled
    $consumed = $sku.consumedUnits
    $available = $purchased - $consumed
    $utilPct = if ($purchased -gt 0) { [math]::Round(($consumed / $purchased) * 100, 1) } else { 0 }

    $totalPurchased += $purchased; $totalConsumed += $consumed; $totalAvailable += $available

    $pctColor = if ($utilPct -ge 95) { 'Red' } elseif ($utilPct -ge 80) { 'Yellow' } elseif ($utilPct -lt 50 -and $purchased -gt 5) { 'DarkYellow' } else { 'Green' }
    $bar = '*' * [math]::Min([math]::Round($utilPct / 5), 20)

    Write-Host "  $($sku.skuPartNumber)" -ForegroundColor White
    Write-Host "    Purchased: $purchased | Consumed: $consumed | Available: $available | $utilPct% $bar" -ForegroundColor $pctColor

    if ($available -lt 0) { Write-Host "    WARNING: Over-allocated by $([math]::Abs($available)) licenses!" -ForegroundColor Red }
}

Write-Host ""
Write-Host "  --- Totals ---" -ForegroundColor Yellow
Write-Host "  Total purchased : $totalPurchased" -ForegroundColor White
Write-Host "  Total consumed  : $totalConsumed" -ForegroundColor White
Write-Host "  Total available : $totalAvailable" -ForegroundColor $(if($totalAvailable -gt 0){'Green'}else{'Red'})

# Get all users with license info
Write-Section "USER LICENSE ANALYSIS"
Write-Status "Fetching all users with license data..."
$users = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,displayName,accountEnabled,assignedLicenses,userType&`$top=999"
Write-Status "$($users.Count) users retrieved" "Green"

$licensedUsers = $users | Where-Object { $_.assignedLicenses -and $_.assignedLicenses.Count -gt 0 }
$unlicensedUsers = $users | Where-Object { -not $_.assignedLicenses -or $_.assignedLicenses.Count -eq 0 }
$disabledWithLicense = $licensedUsers | Where-Object { -not $_.accountEnabled }
$guestsWithLicense = $licensedUsers | Where-Object { $_.userType -eq 'Guest' }

$skuIdMap = @{}
foreach ($sku in $skus) { $skuIdMap[$sku.skuId] = $sku.skuPartNumber }

Write-Host ""
Write-Host "  Total users             : $($users.Count)" -ForegroundColor White
Write-Host "  Licensed users          : $($licensedUsers.Count)" -ForegroundColor Green
Write-Host "  Unlicensed users        : $($unlicensedUsers.Count)" -ForegroundColor DarkGray
Write-Host "  Disabled with licenses  : $($disabledWithLicense.Count)" -ForegroundColor $(if($disabledWithLicense.Count -gt 0){'Red'}else{'Green'})
Write-Host "  Guests with licenses    : $($guestsWithLicense.Count)" -ForegroundColor $(if($guestsWithLicense.Count -gt 0){'Yellow'}else{'Green'})

if ($disabledWithLicense.Count -gt 0) {
    $wastedLicenseCount = ($disabledWithLicense | ForEach-Object { $_.assignedLicenses.Count } | Measure-Object -Sum).Sum
    Write-Host ""
    Write-Host "  --- Disabled Accounts with Licenses ($($disabledWithLicense.Count)) = $wastedLicenseCount wasted ---" -ForegroundColor Red
    foreach ($du in ($disabledWithLicense | Select-Object -First 15)) {
        $licNames = ($du.assignedLicenses | ForEach-Object { if ($skuIdMap.ContainsKey($_.skuId)) { $skuIdMap[$_.skuId] } else { $_.skuId.Substring(0,8) } }) -join ', '
        Write-Host "    $($du.userPrincipalName) | $licNames" -ForegroundColor DarkYellow
    }
    if ($disabledWithLicense.Count -gt 15) { Write-Host "    ... and $($disabledWithLicense.Count - 15) more" -ForegroundColor DarkGray }
}

# License distribution
Write-Host ""
Write-Host "  --- License Assignment Distribution ---" -ForegroundColor Yellow
$licCounts = $licensedUsers | ForEach-Object { $_.assignedLicenses.Count } | Group-Object | Sort-Object Name
foreach ($lc in $licCounts) {
    Write-Host "    $($lc.Name) license(s) : $($lc.Count) user(s)" -ForegroundColor White
}

# Export
$userReport = foreach ($u in $users) {
    $licNames = if ($u.assignedLicenses) {
        ($u.assignedLicenses | ForEach-Object { if ($skuIdMap.ContainsKey($_.skuId)) { $skuIdMap[$_.skuId] } else { $_.skuId } }) -join '; '
    } else { '(none)' }

    [PSCustomObject]@{
        UserPrincipalName = $u.userPrincipalName
        DisplayName       = $u.displayName
        AccountEnabled    = $u.accountEnabled
        UserType          = $u.userType
        LicenseCount      = if ($u.assignedLicenses) { $u.assignedLicenses.Count } else { 0 }
        Licenses          = $licNames
        IsWaste           = (-not $u.accountEnabled -and $u.assignedLicenses -and $u.assignedLicenses.Count -gt 0)
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "LicenseReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$userReport | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($userReport.Count) rows)" "Green"
Write-Host ""


