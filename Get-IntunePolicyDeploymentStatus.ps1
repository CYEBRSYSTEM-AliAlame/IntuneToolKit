#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports deployment status for all configuration policies across devices.
.DESCRIPTION
    Shows per-policy deployment health: how many devices succeeded, failed,
    are pending, have conflicts, or errors. Identifies the most-failing
    policies and the policies with the highest error rates.
.PARAMETER ExportPath
    Optional. Export results to CSV.
.EXAMPLE
    .\Get-IntunePolicyDeploymentStatus.ps1
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

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# Device Configuration Profiles
Write-Section "DEVICE CONFIGURATION PROFILES"
$configs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=id,displayName"
Write-Status "Found $($configs.Count) configuration profiles" "Green"

foreach ($c in $configs) {
    try {
        $summary = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($c.id)/deviceStatusOverview" -Method GET -ErrorAction Stop
    } catch { continue }

    $succeeded = if ($summary.configurationAppliedDeviceCount) { $summary.configurationAppliedDeviceCount } elseif ($summary.successCount) { $summary.successCount } else { 0 }
    $failed = if ($summary.failedCount) { $summary.failedCount } else { 0 }
    $error_ = if ($summary.errorCount) { $summary.errorCount } else { 0 }
    $conflict = if ($summary.conflictCount) { $summary.conflictCount } else { 0 }
    $pending = if ($summary.pendingCount) { $summary.pendingCount } else { 0 }
    $na = if ($summary.notApplicableCount) { $summary.notApplicableCount } else { 0 }
    $total = $succeeded + $failed + $error_ + $conflict + $pending

    $healthPct = if ($total -gt 0) { [math]::Round(($succeeded / $total) * 100, 1) } else { 0 }
    $hasIssues = ($failed + $error_ + $conflict) -gt 0
    $color = if ($hasIssues) { 'Yellow' } else { 'Green' }

    if ($hasIssues) {
        Write-Host "    $($c.displayName)" -ForegroundColor White
        Write-Host "      OK:$succeeded  Fail:$failed  Error:$error_  Conflict:$conflict  Pending:$pending  ($healthPct%)" -ForegroundColor $color
    }

    $report.Add([PSCustomObject]@{
        PolicyName=$c.displayName; PolicyType='Device Configuration'; Succeeded=$succeeded
        Failed=$failed; Error=$error_; Conflict=$conflict; Pending=$pending; NotApplicable=$na
        TotalTargeted=$total; SuccessRate=$healthPct
    })
}

# Settings Catalog
Write-Section "SETTINGS CATALOG POLICIES"
$catalogs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name"
Write-Status "Found $($catalogs.Count) Settings Catalog policies" "Green"

foreach ($c in $catalogs) {
    $pName = if ($c.name) { $c.name } else { $c.displayName }
    try {
        $summary = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($c.id)/deviceStatusOverview" -Method GET -ErrorAction Stop
    } catch { continue }

    $succeeded = if ($summary.succeededDeviceCount) { $summary.succeededDeviceCount } else { 0 }
    $failed = if ($summary.failedDeviceCount) { $summary.failedDeviceCount } else { 0 }
    $error_ = if ($summary.errorDeviceCount) { $summary.errorDeviceCount } else { 0 }
    $conflict = if ($summary.conflictDeviceCount) { $summary.conflictDeviceCount } else { 0 }
    $pending = if ($summary.pendingDeviceCount) { $summary.pendingDeviceCount } else { 0 }
    $na = if ($summary.notApplicableDeviceCount) { $summary.notApplicableDeviceCount } else { 0 }
    $total = $succeeded + $failed + $error_ + $conflict + $pending

    $healthPct = if ($total -gt 0) { [math]::Round(($succeeded / $total) * 100, 1) } else { 0 }
    $hasIssues = ($failed + $error_ + $conflict) -gt 0

    if ($hasIssues) {
        Write-Host "    $pName" -ForegroundColor White
        Write-Host "      OK:$succeeded  Fail:$failed  Error:$error_  Conflict:$conflict  Pending:$pending  ($healthPct%)" -ForegroundColor Yellow
    }

    $report.Add([PSCustomObject]@{
        PolicyName=$pName; PolicyType='Settings Catalog'; Succeeded=$succeeded
        Failed=$failed; Error=$error_; Conflict=$conflict; Pending=$pending; NotApplicable=$na
        TotalTargeted=$total; SuccessRate=$healthPct
    })
}

# Compliance Policies
Write-Section "COMPLIANCE POLICIES"
$compPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=id,displayName"
Write-Status "Found $($compPolicies.Count) compliance policies" "Green"

foreach ($c in $compPolicies) {
    try {
        $summary = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($c.id)/deviceStatusOverview" -Method GET -ErrorAction Stop
    } catch { continue }

    $succeeded = if ($summary.succeedCount) { $summary.succeedCount } elseif ($summary.configurationAppliedDeviceCount) { $summary.configurationAppliedDeviceCount } else { 0 }
    $failed = if ($summary.failedCount) { $summary.failedCount } else { 0 }
    $error_ = if ($summary.errorCount) { $summary.errorCount } else { 0 }
    $conflict = if ($summary.conflictCount) { $summary.conflictCount } else { 0 }
    $pending = if ($summary.pendingCount) { $summary.pendingCount } else { 0 }
    $total = $succeeded + $failed + $error_ + $conflict + $pending

    $healthPct = if ($total -gt 0) { [math]::Round(($succeeded / $total) * 100, 1) } else { 0 }
    $hasIssues = ($failed + $error_ + $conflict) -gt 0

    if ($hasIssues) {
        Write-Host "    $($c.displayName)" -ForegroundColor White
        Write-Host "      OK:$succeeded  Fail:$failed  Error:$error_  Conflict:$conflict  Pending:$pending  ($healthPct%)" -ForegroundColor Yellow
    }

    $report.Add([PSCustomObject]@{
        PolicyName=$c.displayName; PolicyType='Compliance'; Succeeded=$succeeded
        Failed=$failed; Error=$error_; Conflict=$conflict; Pending=$pending; NotApplicable=0
        TotalTargeted=$total; SuccessRate=$healthPct
    })
}

# Summary
Write-Section "DEPLOYMENT HEALTH SUMMARY"
$totalPolicies = $report.Count
$problemPolicies = ($report | Where-Object { ($_.Failed + $_.Error + $_.Conflict) -gt 0 }).Count
$perfectPolicies = ($report | Where-Object { $_.Failed -eq 0 -and $_.Error -eq 0 -and $_.Conflict -eq 0 -and $_.TotalTargeted -gt 0 }).Count

Write-Host ""
Write-Host "  Total policies tracked   : $totalPolicies" -ForegroundColor White
Write-Host "  Fully healthy (100%)     : $perfectPolicies" -ForegroundColor Green
Write-Host "  With issues              : $problemPolicies" -ForegroundColor $(if($problemPolicies -gt 0){'Yellow'}else{'Green'})
Write-Host ""

# Top failing policies
$topFailing = $report | Where-Object { ($_.Failed + $_.Error + $_.Conflict) -gt 0 } | Sort-Object { $_.Failed + $_.Error + $_.Conflict } -Descending | Select-Object -First 15
if ($topFailing.Count -gt 0) {
    Write-Host "  --- Top Failing Policies ---" -ForegroundColor Red
    foreach ($tf in $topFailing) {
        $issues = $tf.Failed + $tf.Error + $tf.Conflict
        Write-Host "    [$($tf.PolicyType)] $($tf.PolicyName)" -ForegroundColor White
        Write-Host "      $issues issue(s): Fail=$($tf.Failed) Error=$($tf.Error) Conflict=$($tf.Conflict) | Success rate: $($tf.SuccessRate)%" -ForegroundColor DarkYellow
    }
}

# Lowest success rates
$lowSuccess = $report | Where-Object { $_.TotalTargeted -gt 5 -and $_.SuccessRate -lt 80 } | Sort-Object SuccessRate | Select-Object -First 10
if ($lowSuccess.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Lowest Success Rates (<80%) ---" -ForegroundColor Red
    foreach ($ls in $lowSuccess) {
        Write-Host "    $($ls.SuccessRate)% | [$($ls.PolicyType)] $($ls.PolicyName)" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "PolicyDeployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


