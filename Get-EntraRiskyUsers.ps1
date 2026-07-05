#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports risky users and risk detections from Entra ID Protection.
.DESCRIPTION
    Pulls risky users and risk detection events. Shows risk level, risk state,
    risk detail, last detection time, and whether the risk has been remediated.
    Requires Entra ID P2 license.
.PARAMETER IncludeDismissed
    Include users whose risk has been dismissed. Off by default.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraRiskyUsers.ps1
.EXAMPLE
    .\Get-EntraRiskyUsers.ps1 -IncludeDismissed
#>

[CmdletBinding()]
param(
    [Parameter()][switch]$IncludeDismissed,
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
    Connect-MgGraph -Scopes 'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

# Risky users
Write-Section "RISKY USERS"
$filter = if (-not $IncludeDismissed) { "?`$filter=riskState ne 'dismissed' and riskState ne 'remediated' and riskLevel ne 'none'" } else { '' }
$riskyUsers = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers$filter"
Write-Status "$($riskyUsers.Count) risky user(s) found" "Green"

$userReport = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($riskyUsers.Count -gt 0) {
    $highCount = ($riskyUsers | Where-Object { $_.riskLevel -eq 'high' }).Count
    $medCount = ($riskyUsers | Where-Object { $_.riskLevel -eq 'medium' }).Count
    $lowCount = ($riskyUsers | Where-Object { $_.riskLevel -eq 'low' }).Count

    Write-Host ""
    Write-Host "  High risk   : $highCount" -ForegroundColor $(if($highCount -gt 0){'Red'}else{'Green'})
    Write-Host "  Medium risk : $medCount" -ForegroundColor $(if($medCount -gt 0){'Yellow'}else{'Green'})
    Write-Host "  Low risk    : $lowCount" -ForegroundColor $(if($lowCount -gt 0){'DarkYellow'}else{'Green'})
    Write-Host ""

    foreach ($ru in ($riskyUsers | Sort-Object { switch($_.riskLevel){'high'{0}'medium'{1}'low'{2}default{3}} })) {
        $riskColor = switch ($ru.riskLevel) { 'high'{'Red'} 'medium'{'Yellow'} 'low'{'DarkYellow'} default{'DarkGray'} }
        Write-Host "  [$($ru.riskLevel.ToUpper())] $($ru.userDisplayName) ($($ru.userPrincipalName))" -ForegroundColor $riskColor
        Write-Host "    State: $($ru.riskState) | Detail: $($ru.riskDetail) | Last updated: $($ru.riskLastUpdatedDateTime)" -ForegroundColor DarkGray

        $userReport.Add([PSCustomObject]@{
            Type='RiskyUser'; UserPrincipalName=$ru.userPrincipalName; DisplayName=$ru.userDisplayName
            RiskLevel=$ru.riskLevel; RiskState=$ru.riskState; RiskDetail=$ru.riskDetail
            RiskLastUpdated=$ru.riskLastUpdatedDateTime; IsDeleted=$ru.isDeleted
            DetectionType='-'; IPAddress='-'; Location='-'; Activity='-'
        })
    }
} else {
    Write-Host "  No risky users found." -ForegroundColor Green
}

# Risk detections (last 14 days)
Write-Section "RISK DETECTIONS (last 14 days)"
$startDate = (Get-Date).AddDays(-14).ToString('yyyy-MM-ddTHH:mm:ssZ')
$riskDetections = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $startDate&`$top=200&`$orderby=detectedDateTime desc"
Write-Status "$($riskDetections.Count) risk detection(s)" "Green"

if ($riskDetections.Count -gt 0) {
    # Detection type breakdown
    $typeGroups = $riskDetections | Group-Object riskEventType | Sort-Object Count -Descending
    Write-Host ""
    Write-Host "  --- Detection Types ---" -ForegroundColor Yellow
    foreach ($tg in $typeGroups) {
        Write-Host "    $($tg.Name) : $($tg.Count)" -ForegroundColor White
    }

    # Risk level breakdown
    $levelGroups = $riskDetections | Group-Object riskLevel | Sort-Object { switch($_.Name){'high'{0}'medium'{1}'low'{2}default{3}} }
    Write-Host ""
    Write-Host "  --- By Risk Level ---" -ForegroundColor Yellow
    foreach ($lg in $levelGroups) {
        $c = switch ($lg.Name) { 'high'{'Red'} 'medium'{'Yellow'} 'low'{'DarkYellow'} default{'DarkGray'} }
        Write-Host "    $($lg.Name) : $($lg.Count)" -ForegroundColor $c
    }

    # Recent high-risk detections
    $highDetections = $riskDetections | Where-Object { $_.riskLevel -eq 'high' } | Select-Object -First 10
    if ($highDetections.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- Recent High-Risk Detections ---" -ForegroundColor Red
        foreach ($hd in $highDetections) {
            $loc = if ($hd.location) { "$($hd.location.city), $($hd.location.countryOrRegion)" } else { '-' }
            Write-Host "    $($hd.userDisplayName) | $($hd.riskEventType) | IP: $($hd.ipAddress) | $loc" -ForegroundColor DarkYellow
        }
    }

    foreach ($rd in $riskDetections) {
        $loc = if ($rd.location) { "$($rd.location.city), $($rd.location.countryOrRegion)" } else { '-' }
        $userReport.Add([PSCustomObject]@{
            Type='RiskDetection'; UserPrincipalName=$rd.userPrincipalName; DisplayName=$rd.userDisplayName
            RiskLevel=$rd.riskLevel; RiskState=$rd.riskState; RiskDetail=$rd.riskDetail
            RiskLastUpdated=$rd.detectedDateTime; IsDeleted='-'
            DetectionType=$rd.riskEventType; IPAddress=$rd.ipAddress; Location=$loc; Activity=$rd.activity
        })
    }
}

Write-Section "SUMMARY"
Write-Host ""
Write-Host "  Risky users       : $($riskyUsers.Count)" -ForegroundColor $(if($riskyUsers.Count -gt 0){'Red'}else{'Green'})
Write-Host "  Risk detections   : $($riskDetections.Count) (14 days)" -ForegroundColor $(if($riskDetections.Count -gt 0){'Yellow'}else{'Green'})

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "RiskyUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$userReport | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($userReport.Count) rows)" "Green"
Write-Host ""


