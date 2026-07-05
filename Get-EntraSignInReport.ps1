#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Analyzes Entra ID sign-in logs for security issues.
.DESCRIPTION
    Pulls recent sign-in logs and reports: failed sign-ins, MFA failures,
    legacy authentication usage, conditional access failures, sign-ins from
    unusual locations, top failing users, and top failing apps. Essential
    for security audits and incident investigation.

    Note: Requires Entra ID P1/P2 license for sign-in log access.
    Sign-in data is retained for 30 days maximum.

.PARAMETER Hours
    Number of hours to look back. Default: 24. Max practical: 720 (30 days).
.PARAMETER IncludeSuccessful
    Include successful sign-ins (off by default to focus on failures).
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraSignInReport.ps1
    # Last 24 hours of failed sign-ins
.EXAMPLE
    .\Get-EntraSignInReport.ps1 -Hours 168 -IncludeSuccessful
    # Last 7 days including successes
#>

[CmdletBinding()]
param(
    [Parameter()][int]$Hours = 24,
    [Parameter()][switch]$IncludeSuccessful,
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
    Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "FETCHING SIGN-IN LOGS (last $Hours hours)"
$startDate = (Get-Date).AddHours(-$Hours).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "createdDateTime ge $startDate"
if (-not $IncludeSuccessful) {
    $filter += " and status/errorCode ne 0"
}

Write-Status "Querying sign-in logs..."
$signIns = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=500&`$orderby=createdDateTime desc"
Write-Status "$($signIns.Count) sign-in events retrieved" "Green"

if ($signIns.Count -eq 0) {
    Write-Host "  No sign-in events found for the specified period." -ForegroundColor Yellow
    return
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

$failedCount = 0; $mfaFailCount = 0; $legacyAuthCount = 0; $caFailCount = 0

foreach ($si in $signIns) {
    $errorCode = $si.status.errorCode
    $failureReason = $si.status.failureReason
    $isFailure = $errorCode -ne 0
    $isMfaFail = $errorCode -in @(50074, 50076, 50079, 50072, 53003, 500121, 50158)
    $isLegacyAuth = $si.clientAppUsed -in @('Exchange ActiveSync','Authenticated SMTP','IMAP4','POP3','MAPI Over HTTP','Autodiscover','Exchange Online PowerShell','Remote PowerShell','Exchange Web Services','Other clients')
    $caStatus = $si.conditionalAccessStatus

    if ($isFailure) { $failedCount++ }
    if ($isMfaFail) { $mfaFailCount++ }
    if ($isLegacyAuth) { $legacyAuthCount++ }
    if ($caStatus -eq 'failure') { $caFailCount++ }

    $location = ''
    if ($si.location) {
        $city = $si.location.city
        $state = $si.location.state
        $country = $si.location.countryOrRegion
        $location = @($city, $state, $country) | Where-Object { $_ } | Join-String -Separator ', '
    }

    $report.Add([PSCustomObject]@{
        Timestamp         = $si.createdDateTime
        UserPrincipalName = $si.userPrincipalName
        UserDisplayName   = $si.userDisplayName
        AppDisplayName    = $si.appDisplayName
        ClientApp         = $si.clientAppUsed
        IPAddress         = $si.ipAddress
        Location          = $location
        Status            = if ($isFailure) { 'Failed' } else { 'Success' }
        ErrorCode         = $errorCode
        FailureReason     = $failureReason
        ConditionalAccess = $caStatus
        MfaDetail         = if ($si.mfaDetail) { $si.mfaDetail.authMethod } else { '-' }
        IsLegacyAuth      = $isLegacyAuth
        IsMfaFailure      = $isMfaFail
        DeviceDetail      = if ($si.deviceDetail.operatingSystem) { "$($si.deviceDetail.operatingSystem) / $($si.deviceDetail.browser)" } else { '-' }
        RiskLevel         = $si.riskLevelDuringSignIn
        RiskState         = $si.riskState
        ResourceDisplayName = $si.resourceDisplayName
    })
}

Write-Section "SIGN-IN ANALYSIS"
Write-Host ""
Write-Host "  Total events            : $($signIns.Count)" -ForegroundColor White
Write-Host "  Failed sign-ins         : $failedCount" -ForegroundColor $(if($failedCount -gt 0){'Red'}else{'Green'})
Write-Host "  MFA failures            : $mfaFailCount" -ForegroundColor $(if($mfaFailCount -gt 0){'Red'}else{'Green'})
Write-Host "  Legacy auth attempts    : $legacyAuthCount" -ForegroundColor $(if($legacyAuthCount -gt 0){'Red'}else{'Green'})
Write-Host "  CA policy failures      : $caFailCount" -ForegroundColor $(if($caFailCount -gt 0){'Yellow'}else{'Green'})

# Top failing users
$topUsers = $report | Where-Object { $_.Status -eq 'Failed' } | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10
if ($topUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Failing Users ---" -ForegroundColor Yellow
    foreach ($u in $topUsers) {
        Write-Host "    $($u.Name) : $($u.Count) failures" -ForegroundColor White
    }
}

# Top failing apps
$topApps = $report | Where-Object { $_.Status -eq 'Failed' } | Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 10
if ($topApps.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Failing Apps ---" -ForegroundColor Yellow
    foreach ($a in $topApps) {
        Write-Host "    $($a.Name) : $($a.Count) failures" -ForegroundColor White
    }
}

# Top error codes
$topErrors = $report | Where-Object { $_.ErrorCode -ne 0 } | Group-Object { "$($_.ErrorCode): $($_.FailureReason)" } | Sort-Object Count -Descending | Select-Object -First 10
if ($topErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Error Codes ---" -ForegroundColor Yellow
    foreach ($e in $topErrors) {
        Write-Host "    $($e.Name) ($($e.Count)x)" -ForegroundColor DarkYellow
    }
}

# Legacy auth
if ($legacyAuthCount -gt 0) {
    $legacyApps = $report | Where-Object { $_.IsLegacyAuth } | Group-Object ClientApp | Sort-Object Count -Descending
    Write-Host ""
    Write-Host "  --- Legacy Authentication Protocols ---" -ForegroundColor Red
    foreach ($la in $legacyApps) {
        Write-Host "    $($la.Name) : $($la.Count) attempts" -ForegroundColor DarkYellow
    }
}

# Locations
$topLocations = $report | Where-Object { $_.Location -and $_.Status -eq 'Failed' } | Group-Object Location | Sort-Object Count -Descending | Select-Object -First 10
if ($topLocations.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Locations (failed sign-ins) ---" -ForegroundColor Yellow
    foreach ($l in $topLocations) {
        Write-Host "    $($l.Name) : $($l.Count)" -ForegroundColor White
    }
}

# Risky sign-ins
$risky = $report | Where-Object { $_.RiskLevel -and $_.RiskLevel -notin @('none','hidden','') }
if ($risky.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Risky Sign-Ins ($($risky.Count)) ---" -ForegroundColor Red
    foreach ($r in ($risky | Select-Object -First 10)) {
        Write-Host "    $($r.UserPrincipalName) | Risk: $($r.RiskLevel) | $($r.Location) | $($r.AppDisplayName)" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "SignInReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


