#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a comprehensive Conditional Access policy report from Entra ID.
.DESCRIPTION
    Queries Microsoft Graph to retrieve all Conditional Access policies and
    expands them into a readable report showing:
    - Policy state (enabled, disabled, report-only)
    - User/group inclusions and exclusions (names resolved from IDs)
    - Application targets
    - Platform, location, risk, and device state conditions
    - Grant controls (MFA, compliant device, etc.)
    - Session controls (sign-in frequency, persistent browser, etc.)
    Designed for security auditing, documentation, and change review.
.PARAMETER PolicyName
    Filter by policy display name (supports partial match / contains).
.PARAMETER EnabledOnly
    Only show policies that are enabled (excludes disabled and report-only).
.PARAMETER IncludeDisabled
    Include disabled policies. By default, enabled and report-only are shown.
.PARAMETER ExportPath
    Optional. Export results to CSV at the specified path.
.EXAMPLE
    .\Get-EntraCAReport.ps1
    # All enabled and report-only policies
.EXAMPLE
    .\Get-EntraCAReport.ps1 -PolicyName "MFA" -IncludeDisabled
    # Policies matching "MFA" including disabled ones
.EXAMPLE
    .\Get-EntraCAReport.ps1 -EnabledOnly -ExportPath "C:\temp\ca_policies.csv"
    # Active policies only, exported to CSV
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PolicyName,

    [Parameter()]
    [switch]$EnabledOnly,

    [Parameter()]
    [switch]$IncludeDisabled,

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

function Resolve-DirectoryObjectNames {
    <#
    .SYNOPSIS
        Resolves a list of Entra ID object IDs (users, groups, roles) to display names.
        Caches results to avoid repeated lookups.
    #>
    param(
        [string[]]$ObjectIds,
        [hashtable]$Cache
    )
    $names = @()
    foreach ($id in $ObjectIds) {
        if ($id -eq 'All') { $names += 'All Users'; continue }
        if ($id -eq 'GuestsOrExternalUsers') { $names += 'Guests/External Users'; continue }
        if ($id -eq 'None') { continue }

        if ($Cache.ContainsKey($id)) {
            $names += $Cache[$id]
        } else {
            $obj = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$id`?`$select=displayName,@odata.type"
            if ($obj -and $obj.displayName) {
                $typeShort = switch -Wildcard ($obj.'@odata.type') {
                    '*group*' { 'Group' }
                    '*user*'  { 'User' }
                    '*servicePrincipal*' { 'App' }
                    '*directoryRole*' { 'Role' }
                    default { '' }
                }
                $resolved = if ($typeShort) { "$($obj.displayName) [$typeShort]" } else { $obj.displayName }
                $Cache[$id] = $resolved
                $names += $resolved
            } else {
                $Cache[$id] = $id
                $names += $id
            }
        }
    }
    return $names
}

function Resolve-AppNames {
    param(
        [string[]]$AppIds,
        [hashtable]$Cache
    )
    $names = @()
    foreach ($id in $AppIds) {
        # Well-known application IDs
        $wellKnown = switch ($id) {
            'All'                                    { 'All cloud apps' }
            'Office365'                              { 'Office 365' }
            'MicrosoftAdminPortals'                  { 'Microsoft Admin Portals' }
            '00000002-0000-0ff1-ce00-000000000000'   { 'Office 365 Exchange Online' }
            '00000003-0000-0ff1-ce00-000000000000'   { 'Office 365 SharePoint Online' }
            '00000004-0000-0ff1-ce00-000000000000'   { 'Skype for Business' }
            '797f4846-ba00-4fd7-ba43-dac1f8f63013'   { 'Windows Azure Service Management API' }
            '0000000c-0000-0000-c000-000000000000'   { 'Microsoft App Access Panel' }
            '00000002-0000-0000-c000-000000000000'   { 'Microsoft Graph (legacy)' }
            '00000003-0000-0000-c000-000000000000'   { 'Microsoft Graph' }
            default { $null }
        }

        if ($wellKnown) {
            $names += $wellKnown
        } elseif ($Cache.ContainsKey($id)) {
            $names += $Cache[$id]
        } else {
            $sp = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$id'&`$select=displayName"
            if ($sp -and $sp.Count -gt 0 -and $sp[0].displayName) {
                $Cache[$id] = $sp[0].displayName
                $names += $sp[0].displayName
            } else {
                $Cache[$id] = $id
                $names += $id
            }
        }
    }
    return $names
}

function Resolve-NamedLocations {
    param(
        [string[]]$LocationIds,
        [hashtable]$LocationMap
    )
    $names = @()
    foreach ($id in $LocationIds) {
        if ($id -eq 'All') { $names += 'All locations'; continue }
        if ($id -eq 'AllTrusted') { $names += 'All trusted locations'; continue }
        if ($id -eq '00000000-0000-0000-0000-000000000000') { $names += 'MFA Trusted IPs'; continue }

        if ($LocationMap.ContainsKey($id)) {
            $names += $LocationMap[$id]
        } else {
            $names += $id
        }
    }
    return $names
}

function Format-List { param([array]$Items) ; if ($Items.Count -eq 0) { return '-' } ; return ($Items -join '; ') }
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes @(
        'Policy.Read.All',
        'Directory.Read.All',
        'Application.Read.All',
        'Group.Read.All'
    ) -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Retrieve Policies ---
Write-Section "RETRIEVING CONDITIONAL ACCESS POLICIES"

$allPolicies = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
Write-Status "$($allPolicies.Count) total policies found" "Green"

# Apply name filter
if ($PolicyName) {
    $allPolicies = $allPolicies | Where-Object { $_.displayName -like "*$PolicyName*" }
    Write-Status "Filtered to $($allPolicies.Count) policies matching '$PolicyName'"
}

# Apply state filter
if ($EnabledOnly) {
    $allPolicies = $allPolicies | Where-Object { $_.state -eq 'enabled' }
    Write-Status "Filtered to $($allPolicies.Count) enabled policies"
} elseif (-not $IncludeDisabled) {
    $allPolicies = $allPolicies | Where-Object { $_.state -ne 'disabled' }
    Write-Status "Showing $($allPolicies.Count) enabled/report-only policies (use -IncludeDisabled for all)"
}

if ($allPolicies.Count -eq 0) {
    Write-Host "  No policies found matching the specified criteria." -ForegroundColor Yellow
    return
}

# Pre-load named locations for resolution
Write-Status "Loading named locations..."
$namedLocations = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
$locationMap = @{}
foreach ($nl in $namedLocations) {
    if ($null -ne $nl -and $null -ne $nl.id) {
        $locationMap[$nl.id] = $nl.displayName
    }
}
Write-Status "$($namedLocations.Count) named locations loaded"
#endregion

#region --- Process Policies ---
Write-Section "PROCESSING POLICIES"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$nameCache = @{}
$appCache = @{}
$policyIndex = 0

foreach ($policy in $allPolicies) {
    $policyIndex++
    Write-Progress -Activity "Processing CA policies" -Status "$policyIndex of $($allPolicies.Count) - $($policy.displayName)" -PercentComplete (($policyIndex / $allPolicies.Count) * 100)

    $conditions = $policy.conditions
    $grantControls = $policy.grantControls
    $sessionControls = $policy.sessionControls

    # --- Users ---
    $includeUsers = @()
    $excludeUsers = @()
    if ($conditions.users) {
        if ($conditions.users.includeUsers) { $includeUsers += $conditions.users.includeUsers }
        if ($conditions.users.includeGroups) {
            $includeUsers += Resolve-DirectoryObjectNames -ObjectIds $conditions.users.includeGroups -Cache $nameCache
        }
        if ($conditions.users.includeRoles) {
            $includeUsers += Resolve-DirectoryObjectNames -ObjectIds $conditions.users.includeRoles -Cache $nameCache
        }
        if ($conditions.users.includeGuestsOrExternalUsers) { $includeUsers += 'Guests/External Users' }

        if ($conditions.users.excludeUsers) {
            $excludeUsers += Resolve-DirectoryObjectNames -ObjectIds $conditions.users.excludeUsers -Cache $nameCache
        }
        if ($conditions.users.excludeGroups) {
            $excludeUsers += Resolve-DirectoryObjectNames -ObjectIds $conditions.users.excludeGroups -Cache $nameCache
        }
        if ($conditions.users.excludeRoles) {
            $excludeUsers += Resolve-DirectoryObjectNames -ObjectIds $conditions.users.excludeRoles -Cache $nameCache
        }
    }

    # --- Applications ---
    $includeApps = @()
    $excludeApps = @()
    if ($conditions.applications) {
        if ($conditions.applications.includeApplications) {
            $includeApps = Resolve-AppNames -AppIds $conditions.applications.includeApplications -Cache $appCache
        }
        if ($conditions.applications.excludeApplications) {
            $excludeApps = Resolve-AppNames -AppIds $conditions.applications.excludeApplications -Cache $appCache
        }
        if ($conditions.applications.includeUserActions) {
            $includeApps += $conditions.applications.includeUserActions | ForEach-Object {
                switch ($_) {
                    'urn:user:registersecurityinfo' { 'Register security info' }
                    'urn:user:registerdevice'       { 'Register or join devices' }
                    default { $_ }
                }
            }
        }
    }

    # --- Platforms ---
    $platforms = '-'
    if ($conditions.platforms) {
        $incPlat = if ($conditions.platforms.includePlatforms) { $conditions.platforms.includePlatforms -join ', ' } else { '' }
        $excPlat = if ($conditions.platforms.excludePlatforms) { " (excl: $($conditions.platforms.excludePlatforms -join ', '))" } else { '' }
        $platforms = "$incPlat$excPlat"
    }

    # --- Locations ---
    $includeLocations = '-'
    $excludeLocations = '-'
    if ($conditions.locations) {
        if ($conditions.locations.includeLocations) {
            $includeLocations = Format-List (Resolve-NamedLocations -LocationIds $conditions.locations.includeLocations -LocationMap $locationMap)
        }
        if ($conditions.locations.excludeLocations) {
            $excludeLocations = Format-List (Resolve-NamedLocations -LocationIds $conditions.locations.excludeLocations -LocationMap $locationMap)
        }
    }

    # --- Risk levels ---
    $signInRisk = if ($conditions.signInRiskLevels -and $conditions.signInRiskLevels.Count -gt 0) { $conditions.signInRiskLevels -join ', ' } else { '-' }
    $userRisk   = if ($conditions.userRiskLevels -and $conditions.userRiskLevels.Count -gt 0) { $conditions.userRiskLevels -join ', ' } else { '-' }

    # --- Client app types ---
    $clientApps = if ($conditions.clientAppTypes -and $conditions.clientAppTypes.Count -gt 0) { $conditions.clientAppTypes -join ', ' } else { '-' }

    # --- Device state / filters ---
    $deviceFilter = '-'
    if ($conditions.devices -and $conditions.devices.deviceFilter) {
        $mode = $conditions.devices.deviceFilter.mode
        $rule = $conditions.devices.deviceFilter.rule
        $deviceFilter = "$mode : $rule"
    }

    # --- Grant controls ---
    $grantOperator = if ($grantControls.operator) { $grantControls.operator } else { '-' }
    $grants = @()
    if ($grantControls.builtInControls) { $grants += $grantControls.builtInControls }
    if ($grantControls.customAuthenticationFactors) { $grants += $grantControls.customAuthenticationFactors }
    if ($grantControls.termsOfUse) { $grants += "ToU: $($grantControls.termsOfUse -join ', ')" }
    if ($grantControls.authenticationStrength) {
        $grants += "Auth Strength: $($grantControls.authenticationStrength.displayName)"
    }
    $grantText = if ($grants.Count -gt 0) { "($grantOperator) $($grants -join '; ')" } else { 'Block or not configured' }

    # --- Session controls ---
    $sessionParts = @()
    if ($sessionControls.signInFrequency) {
        $freq = $sessionControls.signInFrequency
        if ($freq.isEnabled) {
            $sessionParts += "Sign-in freq: $($freq.value) $($freq.type)$(if($freq.frequencyInterval){" ($($freq.frequencyInterval))"})"
        }
    }
    if ($sessionControls.persistentBrowser) {
        $pb = $sessionControls.persistentBrowser
        if ($pb.isEnabled) { $sessionParts += "Persistent browser: $($pb.mode)" }
    }
    if ($sessionControls.cloudAppSecurity) {
        $cas = $sessionControls.cloudAppSecurity
        if ($cas.isEnabled) { $sessionParts += "Cloud App Security: $($cas.cloudAppSecurityType)" }
    }
    if ($sessionControls.applicationEnforcedRestrictions) {
        if ($sessionControls.applicationEnforcedRestrictions.isEnabled) { $sessionParts += 'App-enforced restrictions' }
    }
    if ($sessionControls.continuousAccessEvaluation) {
        $cae = $sessionControls.continuousAccessEvaluation
        if ($cae.mode) { $sessionParts += "CAE: $($cae.mode)" }
    }
    $sessionText = if ($sessionParts.Count -gt 0) { $sessionParts -join '; ' } else { '-' }

    # State color for console
    $stateColor = switch ($policy.state) {
        'enabled'    { 'Green' }
        'disabled'   { 'Red' }
        'enabledForReportingButNotEnforced' { 'Yellow' }
        default      { 'Gray' }
    }
    $stateLabel = switch ($policy.state) {
        'enabled'    { 'Enabled' }
        'disabled'   { 'Disabled' }
        'enabledForReportingButNotEnforced' { 'Report-Only' }
        default      { $policy.state }
    }

    Write-Host "  [$stateLabel] $($policy.displayName)" -ForegroundColor $stateColor

    $report.Add([PSCustomObject]@{
        PolicyName         = $policy.displayName
        State              = $stateLabel
        CreatedDateTime    = $policy.createdDateTime
        ModifiedDateTime   = $policy.modifiedDateTime
        IncludeUsers       = Format-List $includeUsers
        ExcludeUsers       = Format-List $excludeUsers
        IncludeApps        = Format-List $includeApps
        ExcludeApps        = Format-List $excludeApps
        Platforms          = $platforms
        ClientAppTypes     = $clientApps
        IncludeLocations   = $includeLocations
        ExcludeLocations   = $excludeLocations
        SignInRiskLevels   = $signInRisk
        UserRiskLevels     = $userRisk
        DeviceFilter       = $deviceFilter
        GrantControls      = $grantText
        SessionControls    = $sessionText
        PolicyId           = $policy.id
    })
}

Write-Progress -Activity "Processing CA policies" -Completed
#endregion

#region --- Summary ---
Write-Section "CONDITIONAL ACCESS SUMMARY"
Write-Host ""

# State breakdown
$stateGroups = $report | Group-Object State | Sort-Object Name
foreach ($sg in $stateGroups) {
    $sColor = switch ($sg.Name) {
        'Enabled'     { 'Green' }
        'Report-Only' { 'Yellow' }
        'Disabled'    { 'Red' }
        default       { 'Gray' }
    }
    Write-Host "  $($sg.Name) : $($sg.Count)" -ForegroundColor $sColor
}
Write-Host ""

# Grant controls breakdown
Write-Host "  --- Grant Controls Used ---" -ForegroundColor Yellow
$grantTypes = @{}
foreach ($r in $report) {
    $r.GrantControls -split ';' | ForEach-Object {
        $g = $_.Trim()
        if ($g -and $g -ne '-' -and $g -ne 'Block or not configured') {
            if (-not $grantTypes.ContainsKey($g)) { $grantTypes[$g] = 0 }
            $grantTypes[$g]++
        }
    }
}
foreach ($gt in ($grantTypes.GetEnumerator() | Sort-Object Value -Descending)) {
    Write-Host "    $($gt.Key) : $($gt.Value) policy/policies" -ForegroundColor White
}
Write-Host ""

# Policies targeting All Users
$allUserPolicies = $report | Where-Object { $_.IncludeUsers -match 'All Users' }
if ($allUserPolicies.Count -gt 0) {
    Write-Host "  --- Policies Targeting All Users ($($allUserPolicies.Count)) ---" -ForegroundColor Yellow
    foreach ($au in $allUserPolicies) {
        Write-Host "    [$($au.State)] $($au.PolicyName)" -ForegroundColor White
    }
    Write-Host ""
}

# Policies targeting All Cloud Apps
$allAppPolicies = $report | Where-Object { $_.IncludeApps -match 'All cloud apps' }
if ($allAppPolicies.Count -gt 0) {
    Write-Host "  --- Policies Targeting All Cloud Apps ($($allAppPolicies.Count)) ---" -ForegroundColor Yellow
    foreach ($aa in $allAppPolicies) {
        Write-Host "    [$($aa.State)] $($aa.PolicyName)" -ForegroundColor White
    }
    Write-Host ""
}

# Policies with no exclusions (potential lockout risk)
$noExclusions = $report | Where-Object { $_.ExcludeUsers -eq '-' -and $_.State -eq 'Enabled' -and $_.IncludeUsers -match 'All Users' }
if ($noExclusions.Count -gt 0) {
    Write-Host "  --- WARNING: Enabled Policies with All Users and No Exclusions ---" -ForegroundColor Red
    foreach ($ne in $noExclusions) {
        Write-Host "    $($ne.PolicyName)" -ForegroundColor Red
        Write-Host "      Grant: $($ne.GrantControls)" -ForegroundColor DarkGray
    }
    Write-Host "  These policies risk locking out break-glass accounts if misconfigured." -ForegroundColor Yellow
    Write-Host ""
}

# Report-only policies (might be forgotten)
$reportOnly = $report | Where-Object { $_.State -eq 'Report-Only' }
if ($reportOnly.Count -gt 0) {
    Write-Host "  --- Report-Only Policies ($($reportOnly.Count)) ---" -ForegroundColor Yellow
    Write-Host "  Review these to determine if they should be enabled:" -ForegroundColor DarkGray
    foreach ($ro in $reportOnly) {
        $age = if ($ro.CreatedDateTime) { [math]::Round(((Get-Date) - [datetime]$ro.CreatedDateTime).TotalDays) } else { '?' }
        Write-Host "    $($ro.PolicyName) (created ${age}d ago)" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

# Export
if ($report.Count -gt 0) {
    if ($ExportPath) {
        $report | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Status "Exported $($report.Count) policies to: $ExportPath" "Green"
    } else {
        $defaultPath = Join-Path $env:TEMP "CAPolicy_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $report | Export-Csv -Path $defaultPath -NoTypeInformation -Encoding UTF8
        Write-Status "Auto-exported $($report.Count) policies to: $defaultPath" "Green"
    }
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray
#endregion


