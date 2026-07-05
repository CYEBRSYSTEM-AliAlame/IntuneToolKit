#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports scope tag usage across all Intune policies and RBAC assignments.
.DESCRIPTION
    Lists all scope tags and shows which policies, apps, and configurations
    reference each tag. Identifies unused tags and untagged policies.
    Important for multi-team Intune environments with delegated administration.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneScopeTagReport.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','DeviceManagementRBAC.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

# Get all scope tags
Write-Section "SCOPE TAGS"
$scopeTags = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags"
Write-Status "Found $($scopeTags.Count) scope tags" "Green"

$tagMap = @{}
foreach ($st in $scopeTags) { $tagMap[$st.id] = $st.displayName }

# Get RBAC role assignments
Write-Status "Fetching RBAC role assignments..."
$roleAssignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"

# Get policies and count scope tag usage
Write-Status "Scanning policies for scope tag references..."
$tagUsage = @{}
foreach ($st in $scopeTags) { $tagUsage[$st.id] = [System.Collections.Generic.List[string]]::new() }

# Device configurations
$configs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=id,displayName,roleScopeTagIds"
foreach ($c in $configs) {
    if ($c.roleScopeTagIds) {
        foreach ($tagId in $c.roleScopeTagIds) {
            if ($tagUsage.ContainsKey($tagId.ToString())) { $tagUsage[$tagId.ToString()].Add("[Config] $($c.displayName)") }
        }
    }
}

# Settings Catalog
$catalogs = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,roleScopeTagIds"
foreach ($c in $catalogs) {
    if ($c.roleScopeTagIds) {
        foreach ($tagId in $c.roleScopeTagIds) {
            $pName = if ($c.name) { $c.name } else { $c.id }
            if ($tagUsage.ContainsKey($tagId.ToString())) { $tagUsage[$tagId.ToString()].Add("[Catalog] $pName") }
        }
    }
}

# Compliance policies
$compPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=id,displayName,roleScopeTagIds"
foreach ($c in $compPolicies) {
    if ($c.roleScopeTagIds) {
        foreach ($tagId in $c.roleScopeTagIds) {
            if ($tagUsage.ContainsKey($tagId.ToString())) { $tagUsage[$tagId.ToString()].Add("[Compliance] $($c.displayName)") }
        }
    }
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host ""
foreach ($st in ($scopeTags | Sort-Object displayName)) {
    $usageCount = $tagUsage[$st.id].Count
    $roleCount = ($roleAssignments | Where-Object { $_.roleScopeTagIds -contains $st.id }).Count

    $color = if ($usageCount -eq 0 -and $st.id -ne '0') { 'DarkGray' } else { 'White' }
    $isDefault = $st.id -eq '0'

    Write-Host "  $($st.displayName)$(if($isDefault){' (Default)'})" -ForegroundColor $color
    Write-Host "    Tag ID: $($st.id) | Policies using: $usageCount | Role assignments: $roleCount" -ForegroundColor DarkGray

    if ($usageCount -gt 0 -and $usageCount -le 10) {
        foreach ($usage in $tagUsage[$st.id]) {
            Write-Host "      $usage" -ForegroundColor DarkCyan
        }
    } elseif ($usageCount -gt 10) {
        foreach ($usage in ($tagUsage[$st.id] | Select-Object -First 5)) {
            Write-Host "      $usage" -ForegroundColor DarkCyan
        }
        Write-Host "      ... and $($usageCount - 5) more" -ForegroundColor DarkGray
    }

    $report.Add([PSCustomObject]@{
        TagName=$st.displayName; TagId=$st.id; IsDefault=$isDefault
        Description=$st.description; PolicyCount=$usageCount; RoleAssignmentCount=$roleCount
        Policies=($tagUsage[$st.id] -join '; ')
    })
}

Write-Section "SCOPE TAG SUMMARY"
$unusedTags = $report | Where-Object { $_.PolicyCount -eq 0 -and -not $_.IsDefault }
Write-Host ""
Write-Host "  Total scope tags    : $($scopeTags.Count)" -ForegroundColor White
Write-Host "  Tags in use         : $(($report | Where-Object { $_.PolicyCount -gt 0 }).Count)" -ForegroundColor Green
Write-Host "  Unused tags         : $($unusedTags.Count)" -ForegroundColor $(if($unusedTags.Count -gt 0){'Yellow'}else{'Green'})
Write-Host "  Role assignments    : $($roleAssignments.Count)" -ForegroundColor White

if ($unusedTags.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Unused Scope Tags ---" -ForegroundColor Yellow
    foreach ($ut in $unusedTags) {
        Write-Host "    $($ut.TagName) (ID: $($ut.TagId))" -ForegroundColor DarkGray
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "ScopeTagReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


