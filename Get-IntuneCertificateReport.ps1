#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports certificate deployment status across Intune managed devices.
.DESCRIPTION
    Lists all certificate profiles (SCEP, PKCS, trusted root) and their
    deployment status. Identifies profiles with failures and shows
    overall certificate health.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneCertificateReport.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "CERTIFICATE PROFILES"
$allConfigs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"

# Filter to certificate-related profiles
$certProfiles = $allConfigs | Where-Object {
    $_.'@odata.type' -like '*certificate*' -or
    $_.'@odata.type' -like '*scep*' -or
    $_.'@odata.type' -like '*pkcs*' -or
    $_.'@odata.type' -like '*trustedRoot*' -or
    $_.displayName -like '*cert*' -or
    $_.displayName -like '*SCEP*' -or
    $_.displayName -like '*PKCS*' -or
    $_.displayName -like '*root*CA*'
}

Write-Status "Found $($certProfiles.Count) certificate-related profiles" "Green"

if ($certProfiles.Count -eq 0) {
    Write-Host ""
    Write-Host "  No certificate profiles found. Checking Settings Catalog for cert settings..." -ForegroundColor DarkGray
    $catalogPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name"
    $certCatalog = $catalogPolicies | Where-Object { $_.name -like '*cert*' -or $_.name -like '*SCEP*' -or $_.name -like '*PKCS*' }
    if ($certCatalog.Count -gt 0) {
        Write-Host "  Found $($certCatalog.Count) certificate-related Settings Catalog policies" -ForegroundColor Yellow
        foreach ($cc in $certCatalog) { Write-Host "    $($cc.name)" -ForegroundColor White }
    } else {
        Write-Host "  No certificate configurations found in this tenant." -ForegroundColor DarkGray
    }
    return
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cp in ($certProfiles | Sort-Object displayName)) {
    $cpName = $cp.displayName
    $cpType = ($cp.'@odata.type' -replace '#microsoft.graph.','')

    try {
        $summary = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($cp.id)/deviceStatusOverview" -Method GET -ErrorAction Stop
    } catch { $summary = $null }

    $succeeded = 0; $failed = 0; $error_ = 0; $pending = 0; $conflict = 0
    if ($summary) {
        $succeeded = if ($summary.configurationAppliedDeviceCount) { $summary.configurationAppliedDeviceCount } elseif ($summary.successCount) { $summary.successCount } else { 0 }
        $failed = if ($summary.failedCount) { $summary.failedCount } else { 0 }
        $error_ = if ($summary.errorCount) { $summary.errorCount } else { 0 }
        $conflict = if ($summary.conflictCount) { $summary.conflictCount } else { 0 }
        $pending = if ($summary.pendingCount) { $summary.pendingCount } else { 0 }
    }
    $total = $succeeded + $failed + $error_ + $pending
    $healthPct = if ($total -gt 0) { [math]::Round(($succeeded / $total) * 100, 1) } else { 0 }
    $hasIssues = ($failed + $error_) -gt 0
    $nameColor = if ($hasIssues) { 'Red' } else { 'Green' }

    Write-Host "    $cpName [$cpType]" -ForegroundColor $nameColor
    Write-Host "      OK: $succeeded | Failed: $failed | Error: $error_ | Pending: $pending | Health: $healthPct%" -ForegroundColor $(if($hasIssues){'DarkYellow'}else{'DarkGray'})

    $report.Add([PSCustomObject]@{
        ProfileName=$cpName; ProfileType=$cpType; Succeeded=$succeeded
        Failed=$failed; Error=$error_; Conflict=$conflict; Pending=$pending
        TotalTargeted=$total; SuccessRate=$healthPct
    })
}

Write-Section "CERTIFICATE HEALTH SUMMARY"
$totalProfiles = $report.Count
$failingProfiles = ($report | Where-Object { ($_.Failed + $_.Error) -gt 0 }).Count
Write-Host ""
Write-Host "  Total cert profiles    : $totalProfiles" -ForegroundColor White
Write-Host "  Healthy                : $($totalProfiles - $failingProfiles)" -ForegroundColor Green
Write-Host "  With failures          : $failingProfiles" -ForegroundColor $(if($failingProfiles -gt 0){'Red'}else{'Green'})

if ($failingProfiles -gt 0) {
    Write-Host ""
    Write-Host "  --- Failing Certificate Profiles ---" -ForegroundColor Red
    foreach ($fp in ($report | Where-Object { ($_.Failed + $_.Error) -gt 0 } | Sort-Object { $_.Failed + $_.Error } -Descending)) {
        Write-Host "    $($fp.ProfileName) : $($fp.Failed + $fp.Error) failure(s)" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "CertificateReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


