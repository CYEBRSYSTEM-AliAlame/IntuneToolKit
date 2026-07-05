#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports recent Entra ID directory changes from audit logs.
.DESCRIPTION
    Pulls directory audit logs showing recent changes: user modifications,
    group membership changes, app registration updates, role assignments,
    conditional access policy changes, and more. Shows who made each change.
.PARAMETER Hours
    Hours to look back. Default: 24.
.PARAMETER Category
    Filter by category: All (default), User, Group, Application, Role, Policy.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraDirectoryAudit.ps1
.EXAMPLE
    .\Get-EntraDirectoryAudit.ps1 -Hours 168 -Category Role
#>

[CmdletBinding()]
param(
    [Parameter()][int]$Hours = 24,
    [Parameter()][ValidateSet('All','User','Group','Application','Role','Policy')][string]$Category = 'All',
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

Write-Section "DIRECTORY AUDIT LOG (last $Hours hours)"
$startDate = (Get-Date).AddHours(-$Hours).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "activityDateTime ge $startDate"

# Category filters map to audit log categories
$categoryMap = @{
    'User'        = "UserManagement"
    'Group'       = "GroupManagement"
    'Application' = "ApplicationManagement"
    'Role'        = "RoleManagement"
    'Policy'      = "Policy"
}

if ($Category -ne 'All' -and $categoryMap.ContainsKey($Category)) {
    $filter += " and category eq '$($categoryMap[$Category])'"
}

Write-Status "Querying audit logs..."
$auditLogs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$filter&`$top=500&`$orderby=activityDateTime desc"
Write-Status "$($auditLogs.Count) audit events retrieved" "Green"

if ($auditLogs.Count -eq 0) {
    Write-Host "  No audit events found for the specified period." -ForegroundColor Yellow
    return
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# Category breakdown
$catGroups = $auditLogs | Group-Object category | Sort-Object Count -Descending
Write-Host ""
Write-Host "  --- Events by Category ---" -ForegroundColor Yellow
foreach ($cg in $catGroups) {
    Write-Host "    $($cg.Name) : $($cg.Count)" -ForegroundColor White
}

# Activity breakdown
$actGroups = $auditLogs | Group-Object activityDisplayName | Sort-Object Count -Descending | Select-Object -First 15
Write-Host ""
Write-Host "  --- Top Activities ---" -ForegroundColor Yellow
foreach ($ag in $actGroups) {
    Write-Host "    $($ag.Name) : $($ag.Count)" -ForegroundColor White
}

# Initiated by breakdown
$initiatorGroups = $auditLogs | Group-Object {
    if ($_.initiatedBy.user.userPrincipalName) { $_.initiatedBy.user.userPrincipalName }
    elseif ($_.initiatedBy.app.displayName) { "[App] $($_.initiatedBy.app.displayName)" }
    else { 'Unknown' }
} | Sort-Object Count -Descending | Select-Object -First 10
Write-Host ""
Write-Host "  --- Top Initiators ---" -ForegroundColor Yellow
foreach ($ig in $initiatorGroups) {
    Write-Host "    $($ig.Name) : $($ig.Count) change(s)" -ForegroundColor White
}

# Process events
Write-Section "RECENT CHANGES (newest first)"
Write-Host ""

foreach ($event in ($auditLogs | Select-Object -First 50)) {
    $activity = $event.activityDisplayName
    $cat = $event.category
    $result = $event.result
    $timestamp = $event.activityDateTime

    $initiator = 'Unknown'
    if ($event.initiatedBy.user.userPrincipalName) { $initiator = $event.initiatedBy.user.userPrincipalName }
    elseif ($event.initiatedBy.app.displayName) { $initiator = "[App] $($event.initiatedBy.app.displayName)" }

    $targets = @()
    if ($event.targetResources) {
        foreach ($tr in $event.targetResources) {
            $targetName = if ($tr.userPrincipalName) { $tr.userPrincipalName }
                          elseif ($tr.displayName) { $tr.displayName }
                          else { $tr.id }
            $targets += "$($tr.type): $targetName"
        }
    }
    $targetStr = if ($targets.Count -gt 0) { $targets -join '; ' } else { '-' }

    # Extract modified properties
    $changes = @()
    if ($event.targetResources) {
        foreach ($tr in $event.targetResources) {
            if ($tr.modifiedProperties) {
                foreach ($mp in $tr.modifiedProperties) {
                    if ($mp.displayName -and $mp.newValue) {
                        $oldVal = if ($mp.oldValue) { $mp.oldValue } else { '(empty)' }
                        $newVal = $mp.newValue
                        if ($oldVal.Length -gt 50) { $oldVal = $oldVal.Substring(0,47) + '...' }
                        if ($newVal.Length -gt 50) { $newVal = $newVal.Substring(0,47) + '...' }
                        $changes += "$($mp.displayName): $oldVal -> $newVal"
                    }
                }
            }
        }
    }
    $changeStr = if ($changes.Count -gt 0) { $changes -join '; ' } else { '-' }

    $resultColor = if ($result -eq 'success') { 'Green' } elseif ($result -eq 'failure') { 'Red' } else { 'DarkGray' }
    $tsDisplay = try { ([datetime]$timestamp).ToString('yyyy-MM-dd HH:mm') } catch { $timestamp }

    Write-Host "  $tsDisplay [$result] $activity" -ForegroundColor $resultColor
    Write-Host "    By: $initiator | Target: $targetStr" -ForegroundColor DarkGray
    if ($changeStr -ne '-') {
        Write-Host "    Changes: $changeStr" -ForegroundColor DarkCyan
    }

    $report.Add([PSCustomObject]@{
        Timestamp     = $timestamp
        Activity      = $activity
        Category      = $cat
        Result        = $result
        InitiatedBy   = $initiator
        Targets       = $targetStr
        Changes       = $changeStr
        CorrelationId = $event.correlationId
    })
}

if ($auditLogs.Count -gt 50) {
    Write-Host ""
    Write-Host "  ... $($auditLogs.Count - 50) more events (see CSV)" -ForegroundColor DarkGray
}

# High-risk operations
$highRiskOps = @('Delete user','Add member to role','Remove member from role','Add app role assignment',
                 'Add owner to application','Consent to application','Update conditional access policy',
                 'Delete conditional access policy','Reset user password','Update application')
$riskyEvents = $auditLogs | Where-Object { $_.activityDisplayName -in $highRiskOps }
if ($riskyEvents.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Sensitive Operations ($($riskyEvents.Count)) ---" -ForegroundColor Red
    foreach ($re in ($riskyEvents | Select-Object -First 15)) {
        $init = if ($re.initiatedBy.user.userPrincipalName) { $re.initiatedBy.user.userPrincipalName } else { '[App]' }
        Write-Host "    $($re.activityDisplayName) by $init" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "DirectoryAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


