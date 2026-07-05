#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves all Intune policies and apps assigned to a specific user.
.DESCRIPTION
    Queries Microsoft Graph to find every policy (configuration profiles, compliance,
    Settings Catalog, endpoint security, update rings, scripts, app config, app protection, etc.)
    assigned to a user via their transitive group memberships, "All Users", or "All Licensed Users".
    Also shows the user's Intune-managed devices and their compliance state.
.PARAMETER UserPrincipalName
    The user's UPN (e.g., jsmith@contoso.com).
.PARAMETER UserId
    The Entra ID user object ID (GUID).
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneUserPolicies.ps1 -UserPrincipalName "jsmith@contoso.com"
.EXAMPLE
    .\Get-IntuneUserPolicies.ps1 -UserId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ExportPath "C:\temp\user_policies.csv"
#>

[CmdletBinding(DefaultParameterSetName = 'ByUPN')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByUPN')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'ById')]
    [string]$UserId,

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

function Get-PolicyAssignments {
    param([string]$PolicyId, [string]$BaseUri)
    $uri = "$BaseUri/$PolicyId/assignments"
    return Invoke-MgGraph-Safe -Uri $uri
}

function Test-UserAssignmentMatch {
    <#
    .SYNOPSIS
        Checks if a policy's assignments target a user via their group memberships
        or via "All Users" / "All Licensed Users" global assignments.
        Returns match info with Include/Exclude and which group triggered the match.
    #>
    param(
        [array]$Assignments,
        [array]$UserGroupIds,
        [hashtable]$GroupNameMap
    )
    $matchResults = @()

    foreach ($a in $Assignments) {
        $target = $a.target
        if (-not $target) { continue }
        $type = $target.'@odata.type'

        switch ($type) {
            '#microsoft.graph.allUsersAssignmentTarget' {
                $matchResults += @{ AssignmentType = 'Include'; Via = 'All Users' }
            }
            '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                $matchResults += @{ AssignmentType = 'Include'; Via = 'All Licensed Users' }
            }
            '#microsoft.graph.groupAssignmentTarget' {
                $gid = $target.groupId
                if ($UserGroupIds -contains $gid) {
                    $gName = if ($GroupNameMap.ContainsKey($gid)) { "$($GroupNameMap[$gid]) ($gid)" } else { $gid }
                    $matchResults += @{ AssignmentType = 'Include'; Via = "Group: $gName" }
                }
            }
            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                $gid = $target.groupId
                if ($UserGroupIds -contains $gid) {
                    $gName = if ($GroupNameMap.ContainsKey($gid)) { "$($GroupNameMap[$gid]) ($gid)" } else { $gid }
                    $matchResults += @{ AssignmentType = 'Exclude'; Via = "Group Exclusion: $gName" }
                }
            }
        }
    }
    return $matchResults
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'Device.Read.All',
        'Directory.Read.All',
        'Group.Read.All',
        'GroupMember.Read.All',
        'User.Read.All',
        'DeviceManagementApps.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve User ---
Write-Section "RESOLVING USER"

if ($UserPrincipalName) {
    Write-Status "Looking up user: $UserPrincipalName"
    # Try direct GET first, then filter as fallback
    $user = $null
    try {
        Write-Status "Trying direct GET..." "DarkGray"
        $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$UserPrincipalName" -Method GET -ErrorAction Stop
        Write-Status "Direct GET succeeded" "Green"
    } catch {
        Write-Host "  Direct GET failed: $_" -ForegroundColor Yellow
        # Direct GET failed - try with filter
        try {
            Write-Status "Trying filter query..." "DarkGray"
            $filterUri = "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$UserPrincipalName' or userPrincipalName eq '$UserPrincipalName'"
            $filterResult = Invoke-MgGraphRequest -Uri $filterUri -Method GET -ErrorAction Stop
            if ($filterResult.value -and $filterResult.value.Count -gt 0) {
                $user = $filterResult.value[0]
                Write-Status "Filter query succeeded" "Green"
            } else {
                Write-Host "  Filter returned 0 results" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Filter query failed: $_" -ForegroundColor Yellow
        }
    }
    if (-not $user -or -not $user.id) {
        Write-Host "  ERROR: User '$UserPrincipalName' not found in Entra ID." -ForegroundColor Red
        return
    }
} else {
    Write-Status "Looking up user ID: $UserId"
    try {
        $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$UserId" -Method GET -ErrorAction Stop
    } catch {
        $user = $null
    }
    if (-not $user) {
        Write-Host "  ERROR: User ID '$UserId' not found in Entra ID." -ForegroundColor Red
        return
    }
}

$targetUserId  = $user.id
$targetUPN     = $user.userPrincipalName
$displayName   = $user.displayName
$jobTitle      = $user.jobTitle
$department    = $user.department
$accountEnabled = $user.accountEnabled
$licenseCount  = if ($user.assignedLicenses) { $user.assignedLicenses.Count } else { 0 }

Write-Host ""
Write-Host "  Display Name     : $displayName" -ForegroundColor White
Write-Host "  UPN              : $targetUPN" -ForegroundColor White
Write-Host "  User ID          : $targetUserId" -ForegroundColor Gray
Write-Host "  Job Title        : $(if($jobTitle){$jobTitle}else{'-'})" -ForegroundColor Gray
Write-Host "  Department       : $(if($department){$department}else{'-'})" -ForegroundColor Gray
Write-Host "  Account Enabled  : $accountEnabled" -ForegroundColor $(if($accountEnabled){'Green'}else{'Red'})
Write-Host "  Assigned Licenses: $licenseCount" -ForegroundColor Gray
#endregion

#region --- User's Managed Devices ---
Write-Section "USER'S INTUNE MANAGED DEVICES"
$managedDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userPrincipalName eq '$targetUPN'"

if ($managedDevices.Count -eq 0) {
    Write-Host "  No Intune managed devices found for this user." -ForegroundColor DarkGray
} else {
    Write-Status "$($managedDevices.Count) managed device(s) found:" "Green"
    foreach ($md in $managedDevices) {
        $compColor = if ($md.complianceState -eq 'compliant') { 'Green' } elseif ($md.complianceState -eq 'noncompliant') { 'Red' } else { 'Yellow' }
        Write-Host "    $($md.deviceName)" -ForegroundColor White -NoNewline
        Write-Host " | $($md.operatingSystem) $($md.osVersion)" -ForegroundColor Gray -NoNewline
        Write-Host " | $($md.complianceState)" -ForegroundColor $compColor -NoNewline
        Write-Host " | Last sync: $($md.lastSyncDateTime)" -ForegroundColor DarkGray
    }
}
#endregion

#region --- Resolve Group Memberships ---
Write-Section "RESOLVING USER GROUP MEMBERSHIPS"

Write-Status "Getting transitive group memberships for $targetUPN..."
$userMemberships = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/users/$targetUserId/transitiveMemberOf?`$select=id,displayName,@odata.type"
$userGroups = $userMemberships | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
$userGroupIds = $userGroups | ForEach-Object { $_.id }

$groupNameMap = @{}
foreach ($g in $userGroups) {
    if ($g.id -and $g.displayName) { $groupNameMap[$g.id] = $g.displayName }
}

Write-Status "User is a member of $($userGroupIds.Count) groups" "Green"
if ($userGroupIds.Count -gt 0 -and $userGroupIds.Count -le 20) {
    foreach ($g in $userGroups) {
        Write-Host "    - $($g.displayName)" -ForegroundColor DarkCyan
    }
} elseif ($userGroupIds.Count -gt 20) {
    foreach ($g in ($userGroups | Select-Object -First 20)) {
        Write-Host "    - $($g.displayName)" -ForegroundColor DarkCyan
    }
    Write-Host "    ... and $($userGroupIds.Count - 20) more" -ForegroundColor DarkGray
}
#endregion

#region --- Policy Discovery ---
$allPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()

# --- Standard policy types ---
$policyTypes = @(
    @{ Name = 'Device Configuration Profiles';   Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations';          NameProp = 'displayName'; SupportsExpand = $true }
    @{ Name = 'Settings Catalog Policies';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies';        NameProp = 'name';        SupportsExpand = $true }
    @{ Name = 'Compliance Policies';              Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies';     NameProp = 'displayName'; SupportsExpand = $true }
    @{ Name = 'Group Policy Configurations';      Uri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations';    NameProp = 'displayName'; SupportsExpand = $true }
    @{ Name = 'Device Management Scripts';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts';      NameProp = 'displayName'; SupportsExpand = $true }
    @{ Name = 'Health/Remediation Scripts';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts';          NameProp = 'displayName'; SupportsExpand = $true }
    @{ Name = 'App Configuration Policies (MDM)'; Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceAppManagement/mobileAppConfigurations'; NameProp = 'displayName'; SupportsExpand = $false }
    @{ Name = 'Windows Autopilot Profiles';       Uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles'; NameProp = 'displayName'; SupportsExpand = $true }
)

foreach ($pt in $policyTypes) {
    Write-Section "SCANNING: $($pt.Name)"

    $policies = @()
    $expandWorked = $false
    if ($pt.SupportsExpand) {
        $expandUri = "$($pt.Uri)?`$expand=Assignments"
        $policies = Invoke-MgGraph-Safe -Uri $expandUri
        if ($policies.Count -gt 0 -and $null -ne $policies[0].assignments) {
            $expandWorked = $true
        } else {
            $policies = Invoke-MgGraph-Safe -Uri $pt.Uri
        }
    } else {
        $policies = Invoke-MgGraph-Safe -Uri $pt.Uri
    }

    Write-Status "Found $($policies.Count) total policies$(if($expandWorked){' (assignments pre-loaded)'}), checking assignments..."
    $matchCount = 0

    foreach ($p in $policies) {
        $assignments = if ($expandWorked -and $p.assignments) {
            $p.assignments
        } else {
            Get-PolicyAssignments -PolicyId $p.id -BaseUri $pt.Uri
        }

        $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

        foreach ($result in $results) {
            $matchCount++

            $policyName = $p.($pt.NameProp)
            if (-not $policyName) { $policyName = $p.displayName }
            if (-not $policyName) { $policyName = $p.name }
            if (-not $policyName) { $policyName = "(Unnamed - $($p.id))" }

            $odataType = $p.'@odata.type'
            $platformText = switch -Wildcard ($odataType) {
                '*windows*'  { 'Windows' }
                '*ios*'      { 'iOS' }
                '*android*'  { 'Android' }
                '*macOS*'    { 'macOS' }
                default      { if ($p.platforms) { $p.platforms } elseif ($p.platformType) { $p.platformType } else { '-' } }
            }

            $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
            $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

            Write-Host "    [$assignTag] $policyName" -ForegroundColor $assignColor
            Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

            $allPolicies.Add([PSCustomObject]@{
                PolicyType     = $pt.Name
                PolicyName     = $policyName
                Platform       = $platformText
                AssignmentType = $result.AssignmentType
                AssignedVia    = $result.Via
                PolicyId       = $p.id
            })
        }
    }
    Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
}

#region --- Endpoint Security Policies (Intents) ---
Write-Section "SCANNING: Endpoint Security Policies"
$templates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=templateType eq 'securityBaseline' or templateType eq 'cloudPC' or templateType eq 'firewall' or templateType eq 'attackSurfaceReduction' or templateType eq 'endpointDetectionAndResponse' or templateType eq 'accountProtection' or templateType eq 'antivirus' or templateType eq 'diskEncryption'"
$intents = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/intents"
Write-Status "Found $($intents.Count) endpoint security policies, checking assignments..."
$matchCount = 0

foreach ($intent in $intents) {
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($intent.id)/assignments"
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        $templateName = ($templates | Where-Object { $_.id -eq $intent.templateId }).displayName
        $intentName = $intent.displayName
        if ($templateName) { $intentName = "$intentName [$templateName]" }

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $intentName" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = "Endpoint Security ($templateName)"
            PolicyName     = $intent.displayName
            Platform       = 'Windows'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $intent.id
        })
    }
}
Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- Update Rings ---
Write-Section "SCANNING: Windows Update Rings"
$updateRings = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"
Write-Status "Found $($updateRings.Count) update rings, checking assignments..."
$matchCount = 0

foreach ($ring in $updateRings) {
    $assignments = Get-PolicyAssignments -PolicyId $ring.id -BaseUri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        if ($allPolicies | Where-Object { $_.PolicyId -eq $ring.id }) { continue }
        $matchCount++

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $($ring.displayName)" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = 'Windows Update Ring'
            PolicyName     = $ring.displayName
            Platform       = 'Windows'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $ring.id
        })
    }
}
Write-Status "$matchCount additional update rings found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- Feature Update Policies ---
Write-Section "SCANNING: Feature Update Policies"
$featureUpdates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
Write-Status "Found $($featureUpdates.Count) feature update policies, checking assignments..."
$matchCount = 0

foreach ($fu in $featureUpdates) {
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$($fu.id)/assignments"
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $($fu.displayName)" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = 'Feature Update Policy'
            PolicyName     = $fu.displayName
            Platform       = 'Windows'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $fu.id
        })
    }
}
Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- Driver Update Policies ---
Write-Section "SCANNING: Driver Update Policies"
$driverUpdates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles"
Write-Status "Found $($driverUpdates.Count) driver update policies, checking assignments..."
$matchCount = 0

foreach ($du in $driverUpdates) {
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$($du.id)/assignments"
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $($du.displayName)" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = 'Driver Update Policy'
            PolicyName     = $du.displayName
            Platform       = 'Windows'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $du.id
        })
    }
}
Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- Quality Update Policies ---
Write-Section "SCANNING: Quality (Expedited) Update Policies"
$qualityUpdates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles"
Write-Status "Found $($qualityUpdates.Count) quality update policies, checking assignments..."
$matchCount = 0

foreach ($qu in $qualityUpdates) {
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles/$($qu.id)/assignments"
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $($qu.displayName)" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = 'Quality Update Policy'
            PolicyName     = $qu.displayName
            Platform       = 'Windows'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $qu.id
        })
    }
}
Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- App Protection Policies ---
Write-Section "SCANNING: App Protection Policies"

$iosAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections?`$expand=Assignments"
$androidAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?`$expand=Assignments"
$windowsAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies?`$expand=Assignments"
$windowsMdmProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies?`$expand=Assignments"

$allAppProtection = @()
$allAppProtection += $iosAppProtection     | ForEach-Object { $_ | Add-Member -NotePropertyName '_platform' -NotePropertyValue 'iOS'     -PassThru -Force }
$allAppProtection += $androidAppProtection | ForEach-Object { $_ | Add-Member -NotePropertyName '_platform' -NotePropertyValue 'Android' -PassThru -Force }
$allAppProtection += $windowsAppProtection | ForEach-Object { $_ | Add-Member -NotePropertyName '_platform' -NotePropertyValue 'Windows' -PassThru -Force }
$allAppProtection += $windowsMdmProtection | ForEach-Object { $_ | Add-Member -NotePropertyName '_platform' -NotePropertyValue 'Windows' -PassThru -Force }

Write-Status "Found $($allAppProtection.Count) app protection policies, checking assignments..."
$matchCount = 0

foreach ($ap in $allAppProtection) {
    $assignments = $ap.assignments
    if (-not $assignments) { continue }
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }

        Write-Host "    [$assignTag] $($ap.displayName)" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via) | Platform: $($ap._platform)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = 'App Protection Policy'
            PolicyName     = $ap.displayName
            Platform       = $ap._platform
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $ap.id
        })
    }
}
Write-Status "$matchCount matching assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#region --- App Assignments ---
Write-Section "SCANNING: App Assignments"
$apps = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true)&`$select=id,displayName,isAssigned"
Write-Status "Found $($apps.Count) apps, checking assignments..."
$matchCount = 0

foreach ($app in $apps) {
    if (-not $app.isAssigned) { continue }
    $assignments = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"
    $results = Test-UserAssignmentMatch -Assignments $assignments -UserGroupIds $userGroupIds -GroupNameMap $groupNameMap

    foreach ($result in $results) {
        $matchCount++

        # Determine install intent for the matching assignment
        $intent = ($assignments | Where-Object {
            $t = $_.target.'@odata.type'
            ($t -eq '#microsoft.graph.groupAssignmentTarget' -and $userGroupIds -contains $_.target.groupId) -or
            ($t -eq '#microsoft.graph.allUsersAssignmentTarget') -or
            ($t -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
        } | Select-Object -First 1).intent

        $assignColor = if ($result.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'Green' }
        $assignTag   = if ($result.AssignmentType -eq 'Exclude') { 'EXCLUDE' } else { 'INCLUDE' }
        $intentText  = if ($intent) { " (Intent: $intent)" } else { '' }

        Write-Host "    [$assignTag] $($app.displayName)$intentText" -ForegroundColor $assignColor
        Write-Host "              via: $($result.Via)" -ForegroundColor DarkCyan

        $allPolicies.Add([PSCustomObject]@{
            PolicyType     = "App Assignment$(if($intent){" ($intent)"})"
            PolicyName     = $app.displayName
            Platform       = '-'
            AssignmentType = $result.AssignmentType
            AssignedVia    = $result.Via
            PolicyId       = $app.id
        })
    }
}
Write-Status "$matchCount matching app assignments found" $(if($matchCount -gt 0){'Green'}else{'DarkGray'})
#endregion

#endregion

#region --- Summary ---
Write-Section "SUMMARY FOR USER: $displayName ($targetUPN)"
Write-Host ""

if ($allPolicies.Count -eq 0) {
    Write-Host "  No policies found assigned to this user." -ForegroundColor DarkGray
} else {
    $includeCount = ($allPolicies | Where-Object { $_.AssignmentType -eq 'Include' }).Count
    $excludeCount = ($allPolicies | Where-Object { $_.AssignmentType -eq 'Exclude' }).Count
    Write-Host "  Total assignments found : $($allPolicies.Count)" -ForegroundColor Green
    Write-Host "  Included                : $includeCount" -ForegroundColor Green
    Write-Host "  Excluded                : $excludeCount" -ForegroundColor $(if($excludeCount -gt 0){'DarkYellow'}else{'DarkGray'})
    Write-Host "  User is in              : $($userGroupIds.Count) groups" -ForegroundColor Gray
    Write-Host "  Managed devices         : $($managedDevices.Count)" -ForegroundColor Gray
    Write-Host ""

    $grouped = $allPolicies | Group-Object PolicyType | Sort-Object Name
    foreach ($grp in $grouped) {
        Write-Host "  $($grp.Name) ($($grp.Count))" -ForegroundColor Yellow
        foreach ($p in $grp.Group) {
            $prefix = if ($p.AssignmentType -eq 'Exclude') { '[EXCLUDE]' } else { '[INCLUDE]' }
            $color  = if ($p.AssignmentType -eq 'Exclude') { 'DarkYellow' } else { 'White' }
            Write-Host "    $prefix $($p.PolicyName)" -ForegroundColor $color
            Write-Host "      via: $($p.AssignedVia)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    if ($ExportPath) {
        $allPolicies | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status "Exported to: $ExportPath" "Green"
    } else {
        $safeName = ($targetUPN -split '@')[0] -replace '[^\w\-]','_'
        $defaultPath = Join-Path $env:TEMP "$safeName`_IntunePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $allPolicies | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported to: $defaultPath" "Green"
    }
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion

