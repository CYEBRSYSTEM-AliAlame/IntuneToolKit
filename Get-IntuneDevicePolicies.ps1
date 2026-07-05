#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves all Intune policies assigned to a specific device  -  enhanced for IntuneOps Toolkit.
.DESCRIPTION
    Queries Microsoft Graph to find every policy assigned to a device via group
    memberships, "All Devices", or "All Users". Enhanced from the standalone
    version with: IntuneOps logging/findings integration, Graph retry wrapper,
    response caching, additional policy types (remediation scripts, platform scripts,
    app protection), and structured JSON output for analysis scripts.
.PARAMETER DeviceName
    The Intune device name.
.PARAMETER DeviceId
    The Intune managed device ID (GUID).
.PARAMETER ExportPath
    Optional. Export results to CSV.
.PARAMETER OutputFindings
    Register results as IOFindings for the diagnostic report. Default: true.
.EXAMPLE
    .\Get-IntuneDevicePolicies.ps1 -DeviceName "L-PF4Z0HM0"
.EXAMPLE
    .\Get-IntuneDevicePolicies.ps1 -DeviceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')]
    [string]$DeviceName,

    [Parameter(Mandatory, ParameterSetName = 'ById')]
    [string]$DeviceId,

    [string]$ExportPath,
    [bool]$OutputFindings = $true
)

#region --- Bootstrap ---
$toolkitRoot = $PSScriptRoot
if ($toolkitRoot -like '*\Graph') { $toolkitRoot = Split-Path $toolkitRoot -Parent }

# Load Core if available
$corePath = Join-Path $toolkitRoot 'Core'
if (Test-Path (Join-Path $corePath 'Write-Log.ps1')) {
    . (Join-Path $corePath 'Write-Log.ps1')
    $hasToolkit = $true
} else {
    # Standalone mode  -  define minimal helpers
    $hasToolkit = $false
    function Write-IOLog { param([string]$Message, [string]$Level='Info') ; Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $(switch($Level){'Error'{'Red'}'Warning'{'Yellow'}'Success'{'Green'}default{'Cyan'}}) }
    function Write-IOSection { param([string]$Msg) ; Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }
    function Write-IOFinding { param([string]$Title,[string]$Severity,[string]$Description,[string]$Remediation,[string]$Source,[string]$Category) }
}
if (-not $Global:IOFindings) { $Global:IOFindings = [System.Collections.Generic.List[PSCustomObject]]::new() }

# Load Graph wrapper if available, else use basic pattern
if (Test-Path (Join-Path $corePath 'Invoke-GraphSafe.ps1')) {
    . (Join-Path $corePath 'Invoke-GraphSafe.ps1')
    $useIOGraph = $true
} else {
    $useIOGraph = $false
}
#endregion

#region --- Graph helper (uses IOGraph if available, else basic) ---
function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET')
    if ($useIOGraph) {
        return Invoke-IOGraph -Uri $Uri -Method $Method
    }
    # Fallback: basic pagination
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
Write-IOSection "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-IOLog "Connecting to Microsoft Graph..." -Level Info
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
Write-IOLog "Signed in as: $($context.Account)" -Level Success
#endregion

#region --- Resolve Device ---
Write-IOSection "RESOLVING DEVICE"

if ($DeviceName) {
    Write-IOLog "Searching for device: $DeviceName" -Level Info
    $devices = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'"
    if ($devices.Count -eq 0) {
        Write-IOLog "Device '$DeviceName' not found in Intune." -Level Error
        return
    }
    $device = $devices[0]
} else {
    Write-IOLog "Looking up device ID: $DeviceId" -Level Info
    $device = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId"
    if (-not $device) {
        Write-IOLog "Device ID '$DeviceId' not found in Intune." -Level Error
        return
    }
}

$managedDeviceId   = $device.id
$deviceName        = $device.deviceName
$entraDeviceId     = $device.azureADDeviceId
$userPrincipalName = $device.userPrincipalName
$osVersion         = $device.osVersion
$complianceState   = $device.complianceState
$serialNumber      = $device.serialNumber
$lastSync          = $device.lastSyncDateTime
$enrolledDate      = $device.enrolledDateTime

Write-Host ""
Write-Host "  Device Name      : $deviceName" -ForegroundColor White
Write-Host "  Managed Device ID: $managedDeviceId" -ForegroundColor Gray
Write-Host "  Entra Device ID  : $entraDeviceId" -ForegroundColor Gray
Write-Host "  Primary User     : $userPrincipalName" -ForegroundColor White
Write-Host "  OS Version       : $osVersion" -ForegroundColor Gray
Write-Host "  Serial Number    : $serialNumber" -ForegroundColor Gray
Write-Host "  Compliance State : $complianceState" -ForegroundColor $(if($complianceState -eq 'compliant'){'Green'}else{'Red'})
Write-Host "  Last Sync        : $lastSync" -ForegroundColor $(if($lastSync -and ((Get-Date) - [datetime]$lastSync).TotalHours -gt 24){'Yellow'}else{'Gray'})
Write-Host "  Enrolled         : $enrolledDate" -ForegroundColor Gray

# Sync staleness finding
if ($lastSync) {
    $syncAge = (Get-Date) - [datetime]$lastSync
    if ($syncAge.TotalDays -gt 7) {
        Write-IOFinding -Title "Device sync is very stale ($([math]::Round($syncAge.TotalDays)) days)" `
            -Severity 'Critical' -Description "Last sync was $lastSync." `
            -Remediation "Force sync via Intune admin center or Graph API." `
            -Source 'Graph API' -Category 'Enrollment'
    }
}

# Compliance finding
if ($complianceState -ne 'compliant') {
    Write-IOFinding -Title "Device compliance state: $complianceState" `
        -Severity $(if($complianceState -eq 'noncompliant'){'High'}else{'Medium'}) `
        -Description "Device '$deviceName' reports as '$complianceState' in Intune." `
        -Remediation "Check compliance policy evaluation. Run Get-DeviceComplianceState.ps1 for per-policy detail." `
        -Source 'Graph API' -Category 'Compliance'
}
#endregion

#region --- Resolve Group Memberships ---
Write-IOSection "RESOLVING GROUP MEMBERSHIPS"

$deviceGroupIds = @()
if ($entraDeviceId) {
    Write-IOLog "Getting Entra device object..." -Level Info
    $entraDevices = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$entraDeviceId'"
    if ($entraDevices.Count -gt 0) {
        $entraObjectId = $entraDevices[0].id
        Write-IOLog "Getting device transitive group memberships..." -Level Info
        $deviceGroups = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/devices/$entraObjectId/transitiveMemberOf?`$select=id,displayName"
        $deviceGroupIds = $deviceGroups | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { $_.id }
        Write-IOLog "Device is in $($deviceGroupIds.Count) groups" -Level Success
    }
}

$userGroupIds = @()
if ($userPrincipalName) {
    Write-IOLog "Getting user transitive group memberships for $userPrincipalName..." -Level Info
    $userGroups = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/users/$userPrincipalName/transitiveMemberOf?`$select=id,displayName"
    $userGroupIds = $userGroups | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { $_.id }
    Write-IOLog "User is in $($userGroupIds.Count) groups" -Level Success
}

$groupNameMap = @{}
foreach ($g in (@($deviceGroups) + @($userGroups))) {
    if ($g -and $g.id -and $g.displayName) { $groupNameMap[$g.id] = $g.displayName }
}
#endregion

#region --- Assignment matching helper ---
function Test-AssignmentMatch {
    param([array]$Assignments, [array]$DeviceGroupIds, [array]$UserGroupIds)
    foreach ($a in $Assignments) {
        $target = $a.target
        if (-not $target) { continue }
        $type = $target.'@odata.type'
        switch ($type) {
            '#microsoft.graph.allDevicesAssignmentTarget'          { return @{ Match = $true; Via = 'All Devices' } }
            '#microsoft.graph.allUsersAssignmentTarget'            { return @{ Match = $true; Via = 'All Users' } }
            '#microsoft.graph.allLicensedUsersAssignmentTarget'    { return @{ Match = $true; Via = 'All Licensed Users' } }
            '#microsoft.graph.groupAssignmentTarget' {
                $gid = $target.groupId
                if ($DeviceGroupIds -contains $gid) { return @{ Match = $true; Via = "Device Group: $gid" } }
                if ($UserGroupIds -contains $gid)   { return @{ Match = $true; Via = "User Group: $gid" } }
            }
        }
    }
    return @{ Match = $false; Via = $null }
}

function Resolve-ViaText {
    param([string]$ViaText)
    if ($ViaText -match 'Group: (.+)$') {
        $gid = $Matches[1]
        if ($groupNameMap.ContainsKey($gid)) { return $ViaText -replace $gid, "$($groupNameMap[$gid]) ($gid)" }
    }
    return $ViaText
}
#endregion

#region --- Policy Discovery ---
$allPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()

$policyTypes = @(
    @{ Name = 'Device Configuration Profiles';   Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations';          NameProp = 'displayName' }
    @{ Name = 'Settings Catalog Policies';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies';        NameProp = 'name' }
    @{ Name = 'Compliance Policies';              Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies';     NameProp = 'displayName' }
    @{ Name = 'Group Policy Configurations';      Uri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations';    NameProp = 'displayName' }
    @{ Name = 'Device Management Scripts';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts';      NameProp = 'displayName' }
    @{ Name = 'Health/Remediation Scripts';        Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts';          NameProp = 'displayName' }
    @{ Name = 'App Configuration Policies (MDM)'; Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations';   NameProp = 'displayName' }
    @{ Name = 'Windows Autopilot Profiles';       Uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles'; NameProp = 'displayName' }
)

foreach ($pt in $policyTypes) {
    Write-IOSection "SCANNING: $($pt.Name)"
    $policies = Invoke-Graph -Uri $pt.Uri
    Write-IOLog "Found $($policies.Count) total policies, checking assignments..." -Level Info
    $matchCount = 0

    foreach ($p in $policies) {
        $assignments = Invoke-Graph -Uri "$($pt.Uri)/$($p.id)/assignments"
        $result = Test-AssignmentMatch -Assignments $assignments -DeviceGroupIds $deviceGroupIds -UserGroupIds $userGroupIds

        if ($result.Match) {
            $matchCount++
            $viaText = Resolve-ViaText $result.Via
            $policyName = $p.($pt.NameProp)
            if (-not $policyName) { $policyName = $p.displayName }
            if (-not $policyName) { $policyName = $p.name }
            if (-not $policyName) { $policyName = "(Unnamed - $($p.id))" }

            $odataType = $p.'@odata.type'
            $platformText = switch -Wildcard ($odataType) {
                '*windows*' { 'Windows' } '*ios*' { 'iOS' } '*android*' { 'Android' } '*macOS*' { 'macOS' }
                default { if ($p.platforms) { $p.platforms } elseif ($p.platformType) { $p.platformType } else { '-' } }
            }

            Write-Host "    [MATCH] $policyName" -ForegroundColor Green
            Write-Host "            Assigned via: $viaText" -ForegroundColor DarkCyan

            $allPolicies.Add([PSCustomObject]@{
                PolicyType  = $pt.Name
                PolicyName  = $policyName
                Platform    = $platformText
                AssignedVia = $viaText
                PolicyId    = $p.id
            })
        }
    }
    Write-IOLog "$matchCount matching assignments found" -Level $(if($matchCount -gt 0){'Success'}else{'Info'})
}

#--- Endpoint Security Policies (Intents) ---
Write-IOSection "SCANNING: Endpoint Security Policies"
$templates = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=templateType eq 'securityBaseline' or templateType eq 'cloudPC' or templateType eq 'firewall' or templateType eq 'attackSurfaceReduction' or templateType eq 'endpointDetectionAndResponse' or templateType eq 'accountProtection' or templateType eq 'antivirus' or templateType eq 'diskEncryption'"
$intents = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceManagement/intents"
Write-IOLog "Found $($intents.Count) endpoint security policies..." -Level Info
$matchCount = 0

foreach ($intent in $intents) {
    $assignments = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($intent.id)/assignments"
    $result = Test-AssignmentMatch -Assignments $assignments -DeviceGroupIds $deviceGroupIds -UserGroupIds $userGroupIds
    if ($result.Match) {
        $matchCount++
        $viaText = Resolve-ViaText $result.Via
        $templateName = ($templates | Where-Object { $_.id -eq $intent.templateId }).displayName
        $intentName = if ($templateName) { "$($intent.displayName) [$templateName]" } else { $intent.displayName }
        Write-Host "    [MATCH] $intentName" -ForegroundColor Green
        Write-Host "            Assigned via: $viaText" -ForegroundColor DarkCyan
        $allPolicies.Add([PSCustomObject]@{
            PolicyType = "Endpoint Security ($templateName)"; PolicyName = $intent.displayName
            Platform = 'Windows'; AssignedVia = $viaText; PolicyId = $intent.id
        })
    }
}
Write-IOLog "$matchCount matching" -Level $(if($matchCount){'Success'}else{'Info'})

#--- Update Rings + Feature + Driver + Quality ---
$updateScans = @(
    @{ Name = 'Windows Update Rings';     Uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')"; BaseUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' }
    @{ Name = 'Feature Update Policies';  Uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles'; BaseUri = 'https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles' }
    @{ Name = 'Driver Update Policies';   Uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles';  BaseUri = 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' }
    @{ Name = 'Quality Update Policies';  Uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles'; BaseUri = 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles' }
)

foreach ($scan in $updateScans) {
    Write-IOSection "SCANNING: $($scan.Name)"
    $items = Invoke-Graph -Uri $scan.Uri
    Write-IOLog "Found $($items.Count), checking assignments..." -Level Info
    $mc = 0
    foreach ($item in $items) {
        $assignments = Invoke-Graph -Uri "$($scan.BaseUri)/$($item.id)/assignments"
        $result = Test-AssignmentMatch -Assignments $assignments -DeviceGroupIds $deviceGroupIds -UserGroupIds $userGroupIds
        if ($result.Match) {
            if ($allPolicies | Where-Object PolicyId -eq $item.id) { continue }
            $mc++
            $viaText = Resolve-ViaText $result.Via
            Write-Host "    [MATCH] $($item.displayName)" -ForegroundColor Green
            Write-Host "            Assigned via: $viaText" -ForegroundColor DarkCyan
            $allPolicies.Add([PSCustomObject]@{
                PolicyType = $scan.Name; PolicyName = $item.displayName
                Platform = 'Windows'; AssignedVia = $viaText; PolicyId = $item.id
            })
        }
    }
    Write-IOLog "$mc matching" -Level $(if($mc){'Success'}else{'Info'})
}

#--- App Assignments ---
Write-IOSection "SCANNING: App Assignments"
$apps = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true)&`$select=id,displayName,isAssigned"
Write-IOLog "Found $($apps.Count) apps..." -Level Info
$mc = 0

foreach ($app in $apps) {
    if (-not $app.isAssigned) { continue }
    $assignments = Invoke-Graph -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"
    $result = Test-AssignmentMatch -Assignments $assignments -DeviceGroupIds $deviceGroupIds -UserGroupIds $userGroupIds
    if ($result.Match) {
        $mc++
        $viaText = Resolve-ViaText $result.Via
        $intent = ($assignments | Where-Object { $_.target.'@odata.type' -ne '#microsoft.graph.exclusionGroupAssignmentTarget' } | Select-Object -First 1).intent
        Write-Host "    [MATCH] $($app.displayName) (Intent: $intent)" -ForegroundColor Green
        Write-Host "            Assigned via: $viaText" -ForegroundColor DarkCyan
        $allPolicies.Add([PSCustomObject]@{
            PolicyType = "App Assignment ($intent)"; PolicyName = $app.displayName
            Platform = '-'; AssignedVia = $viaText; PolicyId = $app.id
        })
    }
}
Write-IOLog "$mc matching app assignments" -Level $(if($mc){'Success'}else{'Info'})
#endregion

#region --- Summary ---
Write-IOSection "SUMMARY FOR: $deviceName"
Write-Host ""

if ($allPolicies.Count -eq 0) {
    Write-IOLog "No policies found assigned to this device." -Level Warning
} else {
    Write-IOLog "Total policies/assignments found: $($allPolicies.Count)" -Level Success
    Write-Host ""

    $grouped = $allPolicies | Group-Object PolicyType | Sort-Object Name
    foreach ($group in $grouped) {
        Write-Host "  $($group.Name) ($($group.Count))" -ForegroundColor Yellow
        foreach ($p in $group.Group) {
            Write-Host "    - $($p.PolicyName)" -ForegroundColor White
            Write-Host "      via: $($p.AssignedVia)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

# Export
$exportDest = $ExportPath
if (-not $exportDest -and $Global:IOSessionPath) {
    $exportDest = Join-Path $Global:IOSessionPath "Analysis\DevicePolicies_$deviceName.csv"
}
if (-not $exportDest) {
    $exportDest = Join-Path $env:TEMP "${deviceName}_IntunePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}

$allPolicies | Export-Csv -Path $exportDest -NoTypeInformation -Encoding UTF8
Write-IOLog "Exported to: $exportDest" -Level Success

# JSON export for analysis scripts
if ($Global:IOSessionPath) {
    $jsonPath = Join-Path $Global:IOSessionPath "Analysis\DevicePolicies_$deviceName.json"
    $allPolicies | ConvertTo-Json -Depth 5 | Set-Content $jsonPath -Encoding UTF8
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


