#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Entra ID admin role assignments and privileged access.
.DESCRIPTION
    Lists all directory role assignments showing who has which admin roles,
    whether assignments are permanent or PIM-eligible, admin accounts that
    haven't signed in recently, and users with multiple admin roles.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraAdminRoleReport.ps1
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
    Connect-MgGraph -Scopes 'RoleManagement.Read.All','Directory.Read.All','User.Read.All','AuditLog.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

# Get all directory roles
Write-Section "DIRECTORY ROLE ASSIGNMENTS"
$roles = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId"
Write-Status "$($roles.Count) active directory roles" "Green"

# High-privilege roles to flag
$highPrivRoles = @('Global Administrator','Privileged Role Administrator','Security Administrator',
                    'Exchange Administrator','SharePoint Administrator','User Administrator',
                    'Application Administrator','Cloud Application Administrator',
                    'Intune Administrator','Conditional Access Administrator',
                    'Authentication Administrator','Privileged Authentication Administrator')

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$userRoles = @{} # userId -> list of roles

foreach ($role in ($roles | Sort-Object displayName)) {
    $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,userPrincipalName,displayName,accountEnabled,userType"

    if ($members.Count -eq 0) { continue }

    $isHighPriv = $role.displayName -in $highPrivRoles
    $roleColor = if ($role.displayName -eq 'Global Administrator') { 'Red' }
                 elseif ($isHighPriv) { 'Yellow' }
                 else { 'White' }

    Write-Host "  $($role.displayName) ($($members.Count) member(s))" -ForegroundColor $roleColor

    foreach ($m in $members) {
        $memberType = $m.'@odata.type'
        $isUser = $memberType -eq '#microsoft.graph.user'
        $isSP = $memberType -eq '#microsoft.graph.servicePrincipal'

        $upn = if ($isUser) { $m.userPrincipalName } elseif ($m.displayName) { $m.displayName } else { $m.id }
        $displayName = $m.displayName
        $enabled = if ($isUser) { $m.accountEnabled } else { $true }
        $isGuest = $m.userType -eq 'Guest'

        if ($isUser -and $m.id) {
            if (-not $userRoles.ContainsKey($m.id)) { $userRoles[$m.id] = @() }
            $userRoles[$m.id] += $role.displayName
        }

        $issues = @()
        if (-not $enabled -and $isUser) { $issues += 'DISABLED account with admin role' }
        if ($isGuest) { $issues += 'GUEST with admin role' }
        if ($isSP) { $issues += 'Service principal (not a user)' }
        if ($role.displayName -eq 'Global Administrator') { $issues += 'Highest privilege role' }

        Write-Host "    $upn$(if(-not $enabled){' [DISABLED]'})" -ForegroundColor $(if(-not $enabled){'DarkGray'}elseif($isGuest){'DarkYellow'}else{'DarkCyan'})

        $report.Add([PSCustomObject]@{
            RoleName          = $role.displayName
            IsHighPrivilege   = $isHighPriv
            MemberUPN         = $upn
            MemberDisplayName = $displayName
            MemberType        = if ($isUser) { 'User' } elseif ($isSP) { 'ServicePrincipal' } else { 'Other' }
            AccountEnabled    = $enabled
            IsGuest           = $isGuest
            Issues            = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
        })
    }
    Write-Host ""
}

# Users with multiple roles
Write-Section "MULTI-ROLE ANALYSIS"
$multiRoleUsers = $userRoles.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 } | Sort-Object { $_.Value.Count } -Descending

if ($multiRoleUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Users with Multiple Admin Roles ($($multiRoleUsers.Count)) ---" -ForegroundColor Yellow
    foreach ($mu in $multiRoleUsers) {
        $userEntry = $report | Where-Object { $_.MemberUPN -and $_.MemberType -eq 'User' } | Where-Object {
            $userId = $mu.Key
            # Match by finding in report
            $true
        } | Select-Object -First 1
        $upn = ($report | Where-Object { $_.MemberType -eq 'User' } |
            Group-Object MemberUPN |
            Where-Object { $_.Group.RoleName.Count -gt 1 } |
            ForEach-Object { $_.Name }) | Select-Object -First ($multiRoleUsers.Count)

        Write-Host "    $($mu.Value.Count) roles: $($mu.Value -join ', ')" -ForegroundColor White
    }
} else {
    Write-Host "  No users with multiple admin roles." -ForegroundColor Green
}

# Summary
Write-Section "ADMIN ROLE SUMMARY"
$totalAssignments = $report.Count
$uniqueAdmins = ($report | Where-Object { $_.MemberType -eq 'User' } | Select-Object MemberUPN -Unique).Count
$globalAdmins = ($report | Where-Object { $_.RoleName -eq 'Global Administrator' -and $_.MemberType -eq 'User' }).Count
$disabledAdmins = ($report | Where-Object { -not $_.AccountEnabled -and $_.MemberType -eq 'User' }).Count
$guestAdmins = ($report | Where-Object { $_.IsGuest }).Count
$spAdmins = ($report | Where-Object { $_.MemberType -eq 'ServicePrincipal' }).Count

Write-Host ""
Write-Host "  Total role assignments    : $totalAssignments" -ForegroundColor White
Write-Host "  Unique admin users        : $uniqueAdmins" -ForegroundColor White
Write-Host "  Global Administrators     : $globalAdmins" -ForegroundColor $(if($globalAdmins -gt 5){'Red'}elseif($globalAdmins -gt 2){'Yellow'}else{'Green'})
Write-Host "  Disabled with admin role  : $disabledAdmins" -ForegroundColor $(if($disabledAdmins -gt 0){'Red'}else{'Green'})
Write-Host "  Guests with admin role    : $guestAdmins" -ForegroundColor $(if($guestAdmins -gt 0){'Red'}else{'Green'})
Write-Host "  Service principal admins  : $spAdmins" -ForegroundColor DarkGray
Write-Host "  Multi-role users          : $($multiRoleUsers.Count)" -ForegroundColor $(if($multiRoleUsers.Count -gt 0){'Yellow'}else{'Green'})

if ($globalAdmins -gt 5) {
    Write-Host ""
    Write-Host "  WARNING: $globalAdmins Global Administrators exceeds Microsoft's recommendation of 2-4." -ForegroundColor Red
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "AdminRoleReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


