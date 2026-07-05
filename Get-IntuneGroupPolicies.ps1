#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves all Intune policies and apps assigned to a specific Entra ID group.
.DESCRIPTION
    Queries Microsoft Graph to find every policy (configuration profiles, compliance,
    Settings Catalog, endpoint security, update rings, scripts, app config, etc.)
    that targets a specific Entra ID group - either as an Include or Exclude assignment.
    Also reports "All Devices", "All Users", and "All Licensed Users" assignments.
.PARAMETER GroupName
    The Entra ID group display name (e.g., "SG-Intune-Windows-Devices").
.PARAMETER GroupId
    The Entra ID group object ID (GUID).
.PARAMETER IncludeAllDevicesAllUsers
    Switch. Also report policies assigned to "All Devices", "All Users", and
    "All Licensed Users" (these apply to every group implicitly).
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-IntuneGroupPolicies.ps1 -GroupName "SG-Intune-Windows-Devices"
.EXAMPLE
    .\Get-IntuneGroupPolicies.ps1 -GroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ExportPath "C:\temp\group_policies.csv"
.EXAMPLE
    .\Get-IntuneGroupPolicies.ps1 -GroupName "SG-Intune-Pilot" -IncludeAllDevicesAllUsers
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$GroupName,

    [Parameter(Mandatory, ParameterSetName = 'ById')]
    [string]$GroupId,

    [Parameter()]
    [switch]$IncludeAllDevicesAllUsers,

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

function Test-GroupAssignment {
    <#
    .SYNOPSIS
        Checks if a policy's assignments target a specific group.
        Returns match info including whether the group is Included or Excluded.
    #>
    param(
        [array]$Assignments,
        [string]$TargetGroupId,
        [bool]$IncludeGlobalAssignments = $false
    )
    $matchResults = @()

    foreach ($a in $Assignments) {
        $target = $a.target
        if (-not $target) { continue }
        $type = $target.'@odata.type'

        switch ($type) {
            '#microsoft.graph.allDevicesAssignmentTarget' {
                if ($IncludeGlobalAssignments) {
                    $matchResults += @{ AssignmentType = 'Include'; Via = 'All Devices' }
                }
            }
            '#microsoft.graph.allUsersAssignmentTarget' {
                if ($IncludeGlobalAssignments) {
                    $matchResults += @{ AssignmentType = 'Include'; Via = 'All Users' }
                }
            }
            '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                if ($IncludeGlobalAssignments) {
                    $matchResults += @{ AssignmentType = 'Include'; Via = 'All Licensed Users' }
                }
            }
            '#microsoft.graph.groupAssignmentTarget' {
                if ($target.groupId -eq $TargetGroupId) {
                    $matchResults += @{ AssignmentType = 'Include'; Via = 'Direct Group Assignment' }
                }
            }
            '#microsoft.graph.exclusionGroupAssignmentTarget' {
                if ($target.groupId -eq $TargetGroupId) {
                    $matchResults += @{ AssignmentType = 'Exclude'; Via = 'Direct Group Exclusion' }
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
        'DeviceManagementApps.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve Group ---
Write-Section "RESOLVING GROUP"

if ($GroupName) {
    Write-Status "Searching for group: $GroupName"
    $groups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($GroupName -replace "'","''")'"
    if ($groups.Count -eq 0) {
        Write-Host "  ERROR: Group '$GroupName' not found in Entra ID." -ForegroundColor Red
        return
    }
    if ($groups.Count -gt 1) {
        Write-Host "  WARNING: Multiple groups found with name '$GroupName'. Using first match." -ForegroundColor Yellow
    }
    $group = $groups[0]
} else {
    Write-Status "Looking up group ID: $GroupId"
    $group = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId"
    if (-not $group -or $group.Count -eq 0) {
        Write-Host "  ERROR: Group ID '$GroupId' not found in Entra ID." -ForegroundColor Red
        return
    }
    if ($group -is [array]) { $group = $group[0] }
}

$targetGroupId   = $group.id
$targetGroupName = $group.displayName
$groupType       = if ($group.groupTypes -contains 'DynamicMembership') { 'Dynamic' } else { 'Assigned' }
$membershipRule  = $group.membershipRule
$securityEnabled = $group.securityEnabled
$mailEnabled     = $group.mailEnabled

# Get member count
$members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members?`$count=true&`$top=1" 2>$null
$memberCount = if ($members -is [array]) { $members.Count } else { 'Unknown' }
# Try to get the actual count from the response header approach
$memberCountUri = "https://graph.microsoft.com/v1.0/groups/$targetGroupId/members/`$count"
try {
    $actualCount = Invoke-MgGraphRequest -Uri $memberCountUri -Method GET -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
    $memberCount = $actualCount
} catch {
    # Fall back to the basic count
}

Write-Host ""
Write-Host "  Group Name       : $targetGroupName" -ForegroundColor White
Write-Host "  Group ID         : $targetGroupId" -ForegroundColor Gray
Write-Host "  Group Type       : $groupType" -ForegroundColor Gray
Write-Host "  Security Enabled : $securityEnabled" -ForegroundColor Gray
Write-Host "  Mail Enabled     : $mailEnabled" -ForegroundColor Gray
Write-Host "  Member Count     : $memberCount" -ForegroundColor Gray
if ($membershipRule) {
    Write-Host "  Membership Rule  : $membershipRule" -ForegroundColor DarkCyan
}

# Get parent groups (groups this group is a member of)
Write-Status "Checking parent group memberships..."
$parentGroups = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$targetGroupId/transitiveMemberOf?`$select=id,displayName"
$parentGroupList = $parentGroups | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
if ($parentGroupList.Count -gt 0) {
    Write-Status "Group is nested inside $($parentGroupList.Count) parent group(s):" "White"
    foreach ($pg in $parentGroupList) {
        Write-Host "    - $($pg.displayName) ($($pg.id))" -ForegroundColor DarkCyan
    }
} else {
    Write-Status "Group is not nested inside any other groups" "DarkGray"
}
#endregion

#region --- Policy Discovery ---
$allPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()
$includeGlobal = $IncludeAllDevicesAllUsers.IsPresent

# --- Standard policy types (use $expand=Assignments for efficiency where supported) ---
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

    # Try $expand=Assignments to reduce API calls
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
        # Get assignments either from expanded data or separate call
        $assignments = if ($expandWorked -and $p.assignments) {
            $p.assignments
        } else {
            Get-PolicyAssignments -PolicyId $p.id -BaseUri $pt.Uri
        }

        $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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

# iOS App Protection
$iosAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections?`$expand=Assignments"
# Android App Protection
$androidAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?`$expand=Assignments"
# Windows Information Protection (without device enrollment)
$windowsAppProtection = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies?`$expand=Assignments"
# Windows Information Protection (MDM)
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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

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
    $results = Test-GroupAssignment -Assignments $assignments -TargetGroupId $targetGroupId -IncludeGlobalAssignments $includeGlobal

    foreach ($result in $results) {
        $matchCount++

        # Determine install intent for this specific assignment
        $intent = ($assignments | Where-Object {
            $t = $_.target.'@odata.type'
            ($t -eq '#microsoft.graph.groupAssignmentTarget' -and $_.target.groupId -eq $targetGroupId) -or
            ($t -eq '#microsoft.graph.allDevicesAssignmentTarget') -or
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
Write-Section "SUMMARY FOR GROUP: $targetGroupName"
Write-Host ""

if ($allPolicies.Count -eq 0) {
    Write-Host "  No policies found assigned to this group." -ForegroundColor DarkGray
} else {
    $includeCount = ($allPolicies | Where-Object { $_.AssignmentType -eq 'Include' }).Count
    $excludeCount = ($allPolicies | Where-Object { $_.AssignmentType -eq 'Exclude' }).Count
    Write-Host "  Total assignments found : $($allPolicies.Count)" -ForegroundColor Green
    Write-Host "  Included                : $includeCount" -ForegroundColor Green
    Write-Host "  Excluded                : $excludeCount" -ForegroundColor $(if($excludeCount -gt 0){'DarkYellow'}else{'DarkGray'})
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
        $defaultPath = Join-Path $env:TEMP "$($targetGroupName -replace '[^\w\-]','_')_IntunePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $allPolicies | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported to: $defaultPath" "Green"
    }
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


