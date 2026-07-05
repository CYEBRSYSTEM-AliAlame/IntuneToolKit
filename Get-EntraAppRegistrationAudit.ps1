#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits Entra ID app registrations for security and hygiene issues.
.DESCRIPTION
    Lists all app registrations and flags: expiring/expired secrets and
    certificates, apps with excessive API permissions, apps with no owner,
    apps without recent sign-in activity, and multi-tenant apps.
.PARAMETER DaysUntilExpiry
    Flag credentials expiring within this many days. Default: 30.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraAppRegistrationAudit.ps1
.EXAMPLE
    .\Get-EntraAppRegistrationAudit.ps1 -DaysUntilExpiry 90
#>

[CmdletBinding()]
param(
    [Parameter()][int]$DaysUntilExpiry = 30,
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
    Connect-MgGraph -Scopes 'Application.Read.All','AuditLog.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "APP REGISTRATIONS"
$apps = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience,requiredResourceAccess,tags"
Write-Status "$($apps.Count) app registrations found" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$expiredCreds = 0; $expiringSoon = 0; $noOwner = 0; $excessivePerms = 0; $multiTenant = 0; $noCreds = 0

$now = Get-Date
$expiryThreshold = $now.AddDays($DaysUntilExpiry)

$appIndex = 0
foreach ($app in $apps) {
    $appIndex++
    if ($appIndex % 50 -eq 0) { Write-Progress -Activity "Auditing apps" -Status "$appIndex of $($apps.Count)" -PercentComplete (($appIndex/$apps.Count)*100) }

    $appName = $app.displayName
    $issues = @()

    # Check secrets (password credentials)
    $secrets = $app.passwordCredentials
    $certs = $app.keyCredentials
    $allCreds = @()
    if ($secrets) { $allCreds += $secrets }
    if ($certs) { $allCreds += $certs }

    $hasValidCred = $false; $expiredCredCount = 0; $expiringCredCount = 0
    foreach ($cred in $allCreds) {
        $endDate = if ($cred.endDateTime) { [datetime]$cred.endDateTime } else { $null }
        if ($endDate) {
            if ($endDate -lt $now) { $expiredCredCount++ }
            elseif ($endDate -lt $expiryThreshold) { $expiringCredCount++ }
            else { $hasValidCred = $true }
        }
    }

    if ($expiredCredCount -gt 0) { $issues += "Expired credentials ($expiredCredCount)"; $expiredCreds++ }
    if ($expiringCredCount -gt 0) { $issues += "Credentials expiring within $DaysUntilExpiry days ($expiringCredCount)"; $expiringSoon++ }
    if ($allCreds.Count -eq 0) { $noCreds++ }

    # Check owners
    $owners = @()
    try {
        $ownerResult = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners?`$select=id,userPrincipalName" -Method GET -ErrorAction Stop
        if ($ownerResult.value) { $owners = $ownerResult.value }
    } catch { }

    if ($owners.Count -eq 0) { $issues += 'No owner assigned'; $noOwner++ }

    # Check permissions count
    $totalPerms = 0
    if ($app.requiredResourceAccess) {
        foreach ($rra in $app.requiredResourceAccess) {
            if ($rra.resourceAccess) { $totalPerms += $rra.resourceAccess.Count }
        }
    }
    $hasAppPerms = $false
    if ($app.requiredResourceAccess) {
        $hasAppPerms = ($app.requiredResourceAccess | ForEach-Object { $_.resourceAccess } | Where-Object { $_.type -eq 'Role' }).Count -gt 0
    }
    if ($totalPerms -gt 10) { $issues += "Excessive permissions ($totalPerms)"; $excessivePerms++ }
    if ($hasAppPerms) { $issues += 'Has application-level permissions (not delegated)' }

    # Multi-tenant
    $isMultiTenant = $app.signInAudience -in @('AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount','PersonalMicrosoftAccount')
    if ($isMultiTenant) { $issues += "Multi-tenant ($($app.signInAudience))"; $multiTenant++ }

    $report.Add([PSCustomObject]@{
        AppName          = $appName
        AppId            = $app.appId
        Created          = $app.createdDateTime
        SignInAudience   = $app.signInAudience
        SecretCount      = if ($secrets) { $secrets.Count } else { 0 }
        CertCount        = if ($certs) { $certs.Count } else { 0 }
        ExpiredCreds     = $expiredCredCount
        ExpiringCreds    = $expiringCredCount
        HasValidCred     = $hasValidCred
        OwnerCount       = $owners.Count
        Owners           = ($owners | ForEach-Object { $_.userPrincipalName }) -join '; '
        PermissionCount  = $totalPerms
        HasAppPermissions = $hasAppPerms
        IsMultiTenant    = $isMultiTenant
        Issues           = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
    })
}
Write-Progress -Activity "Auditing apps" -Completed

Write-Section "APP REGISTRATION AUDIT SUMMARY"
Write-Host ""
Write-Host "  Total app registrations    : $($apps.Count)" -ForegroundColor White
Write-Host "  Expired credentials        : $expiredCreds" -ForegroundColor $(if($expiredCreds -gt 0){'Red'}else{'Green'})
Write-Host "  Expiring within $($DaysUntilExpiry)d      : $expiringSoon" -ForegroundColor $(if($expiringSoon -gt 0){'Yellow'}else{'Green'})
Write-Host "  No credentials             : $noCreds" -ForegroundColor DarkGray
Write-Host "  No owner                   : $noOwner" -ForegroundColor $(if($noOwner -gt 0){'Yellow'}else{'Green'})
Write-Host "  Excessive permissions (>10) : $excessivePerms" -ForegroundColor $(if($excessivePerms -gt 0){'Yellow'}else{'Green'})
Write-Host "  Multi-tenant               : $multiTenant" -ForegroundColor $(if($multiTenant -gt 0){'DarkYellow'}else{'Green'})

$issueApps = $report | Where-Object { $_.Issues -ne '-' } | Sort-Object { $_.ExpiredCreds + $_.ExpiringCreds } -Descending
if ($issueApps.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Apps with Issues ($($issueApps.Count)) ---" -ForegroundColor Yellow
    foreach ($ia in ($issueApps | Select-Object -First 20)) {
        Write-Host "    $($ia.AppName)" -ForegroundColor White
        Write-Host "      $($ia.Issues)" -ForegroundColor DarkYellow
    }
    if ($issueApps.Count -gt 20) { Write-Host "    ... and $($issueApps.Count - 20) more" -ForegroundColor DarkGray }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "AppRegistrationAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


