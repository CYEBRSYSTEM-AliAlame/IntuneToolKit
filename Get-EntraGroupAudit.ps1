#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits Entra ID group membership, ownership, nesting, and configuration.
.DESCRIPTION
    Provides detailed group analysis including:
    - All members (users, devices, service principals, nested groups)
    - Direct vs transitive membership distinction
    - Group owners
    - Dynamic membership rules and evaluation
    - Nested group hierarchy
    - License assignments on the group
    - Group type classification (security, M365, dynamic, assigned, role-assignable)
    Supports single-group deep dive or bulk audit mode for empty/large/ownerless groups.
.PARAMETER GroupName
    Audit a specific group by display name.
.PARAMETER GroupId
    Audit a specific group by object ID.
.PARAMETER BulkAudit
    Run a health audit across all groups, flagging empty groups, groups with
    no owners, very large groups, and stale dynamic groups.
.PARAMETER IncludeMembers
    In single-group mode, list all individual members in the export.
    In bulk audit mode, this is ignored (would be too large).
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-EntraGroupAudit.ps1 -GroupName "SG-Intune-Windows-Devices"
    # Deep dive on a single group
.EXAMPLE
    .\Get-EntraGroupAudit.ps1 -GroupName "SG-Intune-Pilot" -IncludeMembers -ExportPath "C:\temp\members.csv"
    # Export all members of a group to CSV
.EXAMPLE
    .\Get-EntraGroupAudit.ps1 -BulkAudit -ExportPath "C:\temp\group_health.csv"
    # Health audit across all groups
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$GroupName,

    [Parameter(Mandatory, ParameterSetName = 'ById')]
    [string]$GroupId,

    [Parameter(Mandatory, ParameterSetName = 'BulkAudit')]
    [switch]$BulkAudit,

    [Parameter(ParameterSetName = 'ByName')]
    [Parameter(ParameterSetName = 'ById')]
    [switch]$IncludeMembers,

    [Parameter()]
    [string]$ExportPath
)

#region --- Helpers ---
function Write-Status { param([string]$Msg, [string]$Color = 'Cyan') ; Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg) ; Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri, [string]$Method = 'GET')
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
    }
    catch {
        Write-Verbose "Graph call failed for $Uri : $_"
        return @()
    }
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'Directory.Read.All',
        'Group.Read.All',
        'GroupMember.Read.All',
        'User.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

if ($BulkAudit) {
    #region --- Bulk Audit Mode ---
    Write-Section "BULK GROUP HEALTH AUDIT"

    Write-Status "Fetching all groups..."
    $allGroups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,groupTypes,securityEnabled,mailEnabled,membershipRule,membershipRuleProcessingState,createdDateTime,renewedDateTime,description,isAssignableToRole"
    Write-Status "$($allGroups.Count) groups found" "Green"

    $auditReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $emptyCount = 0
    $noOwnerCount = 0
    $largeCount = 0
    $dynamicCount = 0
    $groupIndex = 0

    foreach ($g in $allGroups) {
        $groupIndex++
        if ($groupIndex % 50 -eq 0) {
            Write-Progress -Activity "Auditing groups" -Status "$groupIndex of $($allGroups.Count) - $($g.displayName)" -PercentComplete (($groupIndex / $allGroups.Count) * 100)
        }

        # Classify group type
        $isDynamic = $g.groupTypes -contains 'DynamicMembership'
        $isM365 = $g.groupTypes -contains 'Unified'
        $groupTypeLabel = if ($isM365 -and $isDynamic) { 'M365 Dynamic' }
                          elseif ($isM365) { 'M365 Assigned' }
                          elseif ($isDynamic -and $g.securityEnabled) { 'Security Dynamic' }
                          elseif ($g.securityEnabled -and $g.mailEnabled) { 'Mail-Enabled Security' }
                          elseif ($g.securityEnabled) { 'Security Assigned' }
                          elseif ($g.mailEnabled) { 'Distribution' }
                          else { 'Other' }

        if ($isDynamic) { $dynamicCount++ }

        # Get member count (using $count for efficiency)
        $memberCount = 0
        try {
            $countResult = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/`$count" -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
            $memberCount = [int]$countResult
        } catch {
            # Fallback - fetch a page and count
            $membersPage = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$top=1&`$select=id"
            $memberCount = $membersPage.Count
        }

        if ($memberCount -eq 0) { $emptyCount++ }
        if ($memberCount -ge 500) { $largeCount++ }

        # Get owner count
        $owners = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)/owners?`$select=id,displayName"
        $ownerCount = $owners.Count
        $ownerNames = ($owners | ForEach-Object { $_.displayName }) -join '; '
        if ($ownerCount -eq 0) { $noOwnerCount++ }

        # Determine age
        $groupAge = if ($g.createdDateTime) { [math]::Round(((Get-Date) - [datetime]$g.createdDateTime).TotalDays) } else { 'N/A' }

        # Issues detection
        $issues = @()
        if ($memberCount -eq 0) { $issues += 'Empty group' }
        if ($ownerCount -eq 0) { $issues += 'No owners' }
        if ($memberCount -ge 5000) { $issues += 'Very large (5000+)' }
        if ($isDynamic -and $g.membershipRuleProcessingState -eq 'Paused') { $issues += 'Dynamic rule paused' }

        $auditReport.Add([PSCustomObject]@{
            GroupName             = $g.displayName
            GroupType             = $groupTypeLabel
            MemberCount           = $memberCount
            OwnerCount            = $ownerCount
            Owners                = if ($ownerNames) { $ownerNames } else { '-' }
            SecurityEnabled       = $g.securityEnabled
            MailEnabled           = $g.mailEnabled
            IsRoleAssignable      = $g.isAssignableToRole
            IsDynamic             = $isDynamic
            MembershipRule        = if ($g.membershipRule) { $g.membershipRule } else { '-' }
            RuleProcessingState   = if ($g.membershipRuleProcessingState) { $g.membershipRuleProcessingState } else { '-' }
            CreatedDateTime       = $g.createdDateTime
            GroupAgeDays          = $groupAge
            Description           = if ($g.description) { $g.description } else { '-' }
            Issues                = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
            GroupId               = $g.id
        })
    }

    Write-Progress -Activity "Auditing groups" -Completed

    # Summary
    Write-Section "GROUP HEALTH SUMMARY"
    Write-Host ""
    Write-Host "  Total groups       : $($allGroups.Count)" -ForegroundColor White
    Write-Host ""

    # Type breakdown
    Write-Host "  --- Group Types ---" -ForegroundColor Yellow
    $typeGroups = $auditReport | Group-Object GroupType | Sort-Object Count -Descending
    foreach ($tg in $typeGroups) {
        Write-Host "    $($tg.Name) : $($tg.Count)" -ForegroundColor White
    }
    Write-Host ""

    # Health flags
    Write-Host "  --- Health Flags ---" -ForegroundColor Yellow
    Write-Host "    Empty groups (0 members)  : $emptyCount" -ForegroundColor $(if($emptyCount -gt 0){'Yellow'}else{'DarkGray'})
    Write-Host "    No owners assigned        : $noOwnerCount" -ForegroundColor $(if($noOwnerCount -gt 0){'Yellow'}else{'DarkGray'})
    Write-Host "    Large groups (500+)       : $largeCount" -ForegroundColor $(if($largeCount -gt 0){'DarkYellow'}else{'DarkGray'})
    Write-Host "    Dynamic groups            : $dynamicCount" -ForegroundColor White
    Write-Host ""

    # Show empty groups
    $emptyGroups = $auditReport | Where-Object { $_.MemberCount -eq 0 } | Sort-Object GroupName
    if ($emptyGroups.Count -gt 0) {
        Write-Section "EMPTY GROUPS ($($emptyGroups.Count))"
        Write-Host ""
        foreach ($eg in ($emptyGroups | Select-Object -First 20)) {
            Write-Host "    $($eg.GroupName)" -ForegroundColor Yellow -NoNewline
            Write-Host " | $($eg.GroupType) | Age: $($eg.GroupAgeDays)d" -ForegroundColor DarkGray
        }
        if ($emptyGroups.Count -gt 20) {
            Write-Host "    ... and $($emptyGroups.Count - 20) more" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Show ownerless groups
    $ownerlessGroups = $auditReport | Where-Object { $_.OwnerCount -eq 0 } | Sort-Object GroupName
    if ($ownerlessGroups.Count -gt 0) {
        Write-Section "GROUPS WITH NO OWNERS ($($ownerlessGroups.Count))"
        Write-Host ""
        foreach ($og in ($ownerlessGroups | Select-Object -First 20)) {
            Write-Host "    $($og.GroupName)" -ForegroundColor Yellow -NoNewline
            Write-Host " | $($og.GroupType) | Members: $($og.MemberCount)" -ForegroundColor DarkGray
        }
        if ($ownerlessGroups.Count -gt 20) {
            Write-Host "    ... and $($ownerlessGroups.Count - 20) more" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Export
    if ($auditReport.Count -gt 0) {
        if ($ExportPath) {
            $auditReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Status "Exported $($auditReport.Count) groups to: $ExportPath" "Green"
        } else {
            $defaultPath = Join-Path $env:TEMP "GroupHealthAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $auditReport | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
            Write-Status "Auto-exported $($auditReport.Count) groups to: $defaultPath" "Green"
        }
    }
    #endregion

} else {
    #region --- Single Group Deep Dive ---
    Write-Section "RESOLVING GROUP"

    if ($GroupName) {
        Write-Status "Searching for group: $GroupName"
        $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($GroupName -replace "'","''")'"
        if ($groups.Count -eq 0) {
            Write-Host "  ERROR: Group '$GroupName' not found." -ForegroundColor Red
            return
        }
        $group = $groups[0]
    } else {
        Write-Status "Looking up group ID: $GroupId"
        $group = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId"
        if (-not $group -or $group.Count -eq 0) {
            Write-Host "  ERROR: Group ID '$GroupId' not found." -ForegroundColor Red
            return
        }
        if ($group -is [array]) { $group = $group[0] }
    }

    $gId = $group.id
    $isDynamic = $group.groupTypes -contains 'DynamicMembership'
    $isM365 = $group.groupTypes -contains 'Unified'
    $groupTypeLabel = if ($isM365 -and $isDynamic) { 'M365 Dynamic' }
                      elseif ($isM365) { 'M365 Assigned' }
                      elseif ($isDynamic -and $group.securityEnabled) { 'Security Dynamic' }
                      elseif ($group.securityEnabled -and $group.mailEnabled) { 'Mail-Enabled Security' }
                      elseif ($group.securityEnabled) { 'Security Assigned' }
                      elseif ($group.mailEnabled) { 'Distribution' }
                      else { 'Other' }

    Write-Host ""
    Write-Host "  Group Name         : $($group.displayName)" -ForegroundColor White
    Write-Host "  Group ID           : $gId" -ForegroundColor Gray
    Write-Host "  Group Type         : $groupTypeLabel" -ForegroundColor White
    Write-Host "  Security Enabled   : $($group.securityEnabled)" -ForegroundColor Gray
    Write-Host "  Mail Enabled       : $($group.mailEnabled)" -ForegroundColor Gray
    Write-Host "  Role Assignable    : $($group.isAssignableToRole)" -ForegroundColor Gray
    Write-Host "  Created            : $($group.createdDateTime)" -ForegroundColor Gray
    if ($group.description) {
        Write-Host "  Description        : $($group.description)" -ForegroundColor DarkCyan
    }
    if ($isDynamic -and $group.membershipRule) {
        Write-Host "  Membership Rule    : $($group.membershipRule)" -ForegroundColor DarkCyan
        Write-Host "  Rule Processing    : $($group.membershipRuleProcessingState)" -ForegroundColor $(if($group.membershipRuleProcessingState -eq 'On'){'Green'}else{'Yellow'})
    }

    # --- Owners ---
    Write-Section "GROUP OWNERS"
    $owners = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$gId/owners?`$select=id,displayName,userPrincipalName,@odata.type"
    if ($owners.Count -eq 0) {
        Write-Host "  No owners assigned." -ForegroundColor Yellow
    } else {
        Write-Status "$($owners.Count) owner(s):" "Green"
        foreach ($o in $owners) {
            $ownerType = switch -Wildcard ($o.'@odata.type') { '*user*' { 'User' } ; '*servicePrincipal*' { 'App' } ; default { '' } }
            Write-Host "    $($o.displayName)" -ForegroundColor White -NoNewline
            Write-Host " ($($o.userPrincipalName)) [$ownerType]" -ForegroundColor Gray
        }
    }

    # --- Members ---
    Write-Section "GROUP MEMBERS"
    $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$gId/members?`$select=id,displayName,userPrincipalName,mail,@odata.type,accountEnabled,deviceId,operatingSystem"

    $userMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
    $deviceMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }
    $groupMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
    $spMembers = $members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }

    Write-Host "  Total members      : $($members.Count)" -ForegroundColor White
    Write-Host "  Users              : $($userMembers.Count)" -ForegroundColor $(if($userMembers.Count -gt 0){'White'}else{'DarkGray'})
    Write-Host "  Devices            : $($deviceMembers.Count)" -ForegroundColor $(if($deviceMembers.Count -gt 0){'White'}else{'DarkGray'})
    Write-Host "  Nested groups      : $($groupMembers.Count)" -ForegroundColor $(if($groupMembers.Count -gt 0){'White'}else{'DarkGray'})
    Write-Host "  Service principals : $($spMembers.Count)" -ForegroundColor $(if($spMembers.Count -gt 0){'White'}else{'DarkGray'})

    # Show nested groups
    if ($groupMembers.Count -gt 0) {
        Write-Host ""
        Write-Host "  Nested groups:" -ForegroundColor Yellow
        foreach ($ng in $groupMembers) {
            Write-Host "    $($ng.displayName) ($($ng.id))" -ForegroundColor DarkCyan
        }
    }

    # User account status
    if ($userMembers.Count -gt 0) {
        $disabledUsers = $userMembers | Where-Object { $_.accountEnabled -eq $false }
        if ($disabledUsers.Count -gt 0) {
            Write-Host ""
            Write-Host "  WARNING: $($disabledUsers.Count) disabled user account(s) in this group:" -ForegroundColor Yellow
            foreach ($du in ($disabledUsers | Select-Object -First 10)) {
                Write-Host "    $($du.displayName) ($($du.userPrincipalName))" -ForegroundColor DarkYellow
            }
            if ($disabledUsers.Count -gt 10) {
                Write-Host "    ... and $($disabledUsers.Count - 10) more" -ForegroundColor DarkGray
            }
        }
    }

    # Device OS breakdown
    if ($deviceMembers.Count -gt 0) {
        Write-Host ""
        Write-Host "  Device OS breakdown:" -ForegroundColor Yellow
        $osGroups = $deviceMembers | Group-Object operatingSystem | Sort-Object Count -Descending
        foreach ($os in $osGroups) {
            Write-Host "    $($os.Name) : $($os.Count)" -ForegroundColor White
        }
    }

    # --- Parent Groups (nesting) ---
    Write-Section "PARENT GROUP MEMBERSHIPS"
    $parentGroups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$gId/transitiveMemberOf?`$select=id,displayName,@odata.type"
    $parentGroupList = $parentGroups | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }

    if ($parentGroupList.Count -eq 0) {
        Write-Host "  This group is not nested inside any other groups." -ForegroundColor DarkGray
    } else {
        Write-Status "Nested inside $($parentGroupList.Count) parent group(s):" "White"
        foreach ($pg in $parentGroupList) {
            Write-Host "    $($pg.displayName) ($($pg.id))" -ForegroundColor DarkCyan
        }
    }

    # --- License Assignments ---
    Write-Section "LICENSE ASSIGNMENTS"
    try {
        $groupDetail = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$gId`?`$select=assignedLicenses" -ErrorAction Stop
        if ($groupDetail.assignedLicenses -and $groupDetail.assignedLicenses.Count -gt 0) {
            Write-Status "$($groupDetail.assignedLicenses.Count) license(s) assigned to this group:" "Green"
            # Resolve SKU IDs to names
            $skus = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuId,skuPartNumber"
            $skuMap = @{}
            foreach ($sku in $skus) { $skuMap[$sku.skuId] = $sku.skuPartNumber }

            foreach ($lic in $groupDetail.assignedLicenses) {
                $skuName = if ($skuMap.ContainsKey($lic.skuId)) { $skuMap[$lic.skuId] } else { $lic.skuId }
                $disabledPlans = if ($lic.disabledPlans -and $lic.disabledPlans.Count -gt 0) { " ($($lic.disabledPlans.Count) plans disabled)" } else { '' }
                Write-Host "    $skuName$disabledPlans" -ForegroundColor White
            }
        } else {
            Write-Host "  No licenses assigned to this group." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  Could not retrieve license information." -ForegroundColor DarkGray
    }

    # --- Export Members ---
    if ($IncludeMembers -and $members.Count -gt 0) {
        $memberReport = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($m in $members) {
            $memberType = switch -Wildcard ($m.'@odata.type') {
                '*user*'             { 'User' }
                '*device*'           { 'Device' }
                '*group*'            { 'Nested Group' }
                '*servicePrincipal*' { 'Service Principal' }
                default              { 'Unknown' }
            }

            $memberReport.Add([PSCustomObject]@{
                GroupName         = $group.displayName
                GroupId           = $gId
                GroupType         = $groupTypeLabel
                MemberName        = $m.displayName
                MemberType        = $memberType
                UserPrincipalName = if ($m.userPrincipalName) { $m.userPrincipalName } else { '-' }
                Mail              = if ($m.mail) { $m.mail } else { '-' }
                AccountEnabled    = if ($null -ne $m.accountEnabled) { $m.accountEnabled } else { '-' }
                OperatingSystem   = if ($m.operatingSystem) { $m.operatingSystem } else { '-' }
                MemberId          = $m.id
            })
        }

        if ($ExportPath) {
            $memberReport | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Status "Exported $($memberReport.Count) members to: $ExportPath" "Green"
        } else {
            $safeName = $group.displayName -replace '[^\w\-]','_'
            $defaultPath = Join-Path $env:TEMP "$safeName`_Members_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $memberReport | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
            Write-Status "Auto-exported $($memberReport.Count) members to: $defaultPath" "Green"
        }
    } elseif (-not $IncludeMembers -and $members.Count -gt 0) {
        Write-Host ""
        Write-Status "Use -IncludeMembers to export the full member list to CSV" "DarkGray"
    }
    #endregion
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray


