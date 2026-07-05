#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Troubleshoots Intune policy issues on a device - conflicts, hardening
    side effects, and behavioral breakage - using three escalating modes.
.DESCRIPTION
    Three modes of operation, use in order:

    ANALYZE (default, read-only):
      Finds settings in Conflict or Error state and shows which policies
      touch the same CSP path. Best for: actual policy conflicts.

    INVESTIGATE (read-only):
      Full X-ray of EVERY setting applied to the device for a specific
      feature area - including settings that applied SUCCESSFULLY but may
      be causing side effects. Maps Windows feature dependencies so when
      you say "Hello is broken" it checks TPM, biometrics, PIN, credential
      providers, passkeys, FIDO2, and Kerberos settings across all policies.
      Best for: hardening broke a feature, no conflict reported.

    ISOLATE (interactive, temporary changes):
      Guided binary search - removes half the policies, you test, narrows
      down in O(log n) rounds. All assignments restored at the end.
      Best for: nothing else found the cause, need brute-force isolation.

.PARAMETER DeviceName
    The Intune device name to troubleshoot.
.PARAMETER Mode
    "Analyze" (default), "Investigate", or "Isolate".
.PARAMETER Feature
    Feature area to investigate. Used with -Mode Investigate.
    Built-in maps: Hello, BitLocker, Firewall, Defender, WiFi, VPN,
    Edge, OneDrive, Updates, AppLocker, Encryption, Certificates, Proxy.
    Or enter a custom keyword to match against setting paths/names.
.PARAMETER ExportPath
    Optional. Export results to CSV.
.EXAMPLE
    .\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0"
    # Analyze: find conflicts and errors
.EXAMPLE
    .\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature Hello
    # X-ray every setting that could affect Windows Hello
.EXAMPLE
    .\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Investigate -Feature BitLocker
    # X-ray every setting that could affect BitLocker
.EXAMPLE
    .\Find-IntunePolicyConflict.ps1 -DeviceName "L-PF4Z0HM0" -Mode Isolate
    # Binary search to find the culprit policy
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DeviceName,

    [Parameter()]
    [ValidateSet('Analyze','Investigate','Isolate')]
    [string]$Mode = 'Analyze',

    [Parameter()]
    [string]$Feature,

    [Parameter()]
    [string]$ExportPath
)

#region --- Feature Dependency Maps ---
# Each feature maps to keywords that appear in CSP paths, setting names, or OMA-URIs.
# A hardening policy may break a feature by touching ANY of these areas.
$featureMaps = @{
    'Hello' = @(
        'Hello', 'WHfB', 'WindowsHelloForBusiness', 'PassportForWork',
        'Biometric', 'Fingerprint', 'FacialRecognition', 'PIN', 'PinComplexity',
        'TPM', 'TrustedPlatformModule', 'NGC', 'CredentialProvider',
        'Passkey', 'FIDO', 'FIDO2', 'WebAuthn', 'SmartCard',
        'Kerberos', 'CloudKerberosTicket', 'DeviceRegistration',
        'KeyCredentialManager', 'EnrollmentStatusPage', 'CompanionDevice',
        'SecurityDevice', 'AllowDomainPINLogon', 'UseSecurityKeyForSignin',
        'EnablePinRecovery', 'RequireSecurityDevice'
    )
    'BitLocker' = @(
        'BitLocker', 'Encryption', 'EncryptionMethod', 'SystemDrivesRequireStartupAuthentication',
        'RequireDeviceEncryption', 'AllowWarningForOtherDiskEncryption',
        'FixedDrivesRecovery', 'SystemDrivesRecovery', 'RemovableDrivesRecovery',
        'EncryptionReportPolicy', 'TPM', 'StartupAuthentication',
        'RecoveryKey', 'RecoveryPassword', 'DiskEncryption',
        'AllowStandardUserEncryption', 'ConfigureRecoveryPasswordRotation',
        'SilentEncryption', 'VolumeDiskEncryption'
    )
    'Firewall' = @(
        'Firewall', 'MdmStore', 'FirewallRules', 'DomainProfile',
        'PrivateProfile', 'PublicProfile', 'EnableFirewall',
        'DisableInboundNotifications', 'DefaultInboundAction',
        'DefaultOutboundAction', 'Shielded', 'WindowsFirewall',
        'FirewallEnabled', 'StealthMode', 'AllowLocalPolicyMerge'
    )
    'Defender' = @(
        'Defender', 'Antivirus', 'AntiMalware', 'WindowsDefender',
        'RealTimeMonitoring', 'CloudProtection', 'SubmitSamplesConsent',
        'AttackSurfaceReduction', 'ASR', 'ControlledFolderAccess',
        'NetworkProtection', 'ExploitGuard', 'PUAProtection',
        'ScanSchedule', 'SignatureUpdate', 'TamperProtection',
        'EndpointDetection', 'EDR', 'SenseIsRunning', 'OnboardingState',
        'BehaviorMonitoring', 'DeviceControl', 'SmartScreen',
        'ExploitProtection', 'ScheduledScan'
    )
    'WiFi' = @(
        'WiFi', 'Wi-Fi', 'Wireless', 'WLAN', 'WLANSvc',
        'WirelessProfile', 'NetworkProfile', '802.1x', 'EAP',
        'SSID', 'WPA', 'WPA2', 'WPA3', 'NetworkAuthentication',
        'Proxy', 'DnsClient'
    )
    'VPN' = @(
        'VPN', 'AlwaysOn', 'VPNv2', 'RasMan', 'RemoteAccess',
        'Tunnel', 'SplitTunnel', 'PluginProfile', 'NativeProfile',
        'TrafficFilter', 'Route', 'DnsSuffix', 'Proxy',
        'TrustedNetworkDetection', 'DeviceTunnel'
    )
    'Edge' = @(
        'Edge', 'Browser', 'InternetExplorer', 'MicrosoftEdge',
        'ExtensionInstallForcelist', 'HomepageLocation',
        'PasswordManager', 'PopupBlocking', 'SmartScreen',
        'SSLErrorOverride', 'CookieBlocking', 'TrackingPrevention',
        'DefaultSearchProvider', 'ProxySettings', 'EnterpriseModeSiteList'
    )
    'OneDrive' = @(
        'OneDrive', 'KFM', 'KnownFolderMove', 'FilesOnDemand',
        'SilentAccountConfig', 'TenantId', 'AllowTenantList',
        'BlockTenantList', 'SyncClientUpdate', 'SharePoint',
        'PersonalVault', 'NetworkBandwidth'
    )
    'Updates' = @(
        'Update', 'WindowsUpdate', 'WUfB', 'QualityUpdate',
        'FeatureUpdate', 'DriverUpdate', 'DeliveryOptimization',
        'ActiveHoursStart', 'ActiveHoursEnd', 'DeferFeatureUpdates',
        'DeferQualityUpdates', 'PauseFeatureUpdates', 'PauseQualityUpdates',
        'BranchReadinessLevel', 'ScheduledInstall', 'AutoRestartRequired',
        'EngagedRestart', 'Telemetry', 'UpdateRing'
    )
    'Certificates' = @(
        'Certificate', 'SCEP', 'PKCS', 'RootCertificate', 'TrustedRoot',
        'ClientCertificate', 'CertificateStore', 'CertificateAuthority',
        'CredentialProvider', 'SmartCard', 'PIV'
    )
    'Proxy' = @(
        'Proxy', 'ProxyServer', 'ProxySettings', 'AutoConfigUrl',
        'PAC', 'WPAD', 'ProxySettingsPerUser', 'NetworkProxy'
    )
    'Encryption' = @(
        'Encryption', 'TLS', 'SSL', 'Cipher', 'SCHANNEL',
        'CryptographicProtocol', 'ClientAuthTrustMode'
    )
    'AppLocker' = @(
        'AppLocker', 'ApplicationControl', 'WDAC', 'CodeIntegrity',
        'SmartLocker', 'AllowedApps', 'BlockedApps', 'ManagedInstaller'
    )
}
#endregion

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

function Test-SettingMatchesFeature {
    param([string]$SettingPath, [string]$SettingName, [string]$PolicyName, [string[]]$Keywords)
    foreach ($kw in $Keywords) {
        if ($SettingPath -like "*$kw*" -or $SettingName -like "*$kw*" -or $PolicyName -like "*$kw*") {
            return $true
        }
    }
    return $false
}
#endregion

#region --- Authentication ---
Write-Section "AUTHENTICATION"
$requiredScopes = if ($Mode -eq 'Isolate') {
    @('DeviceManagementConfiguration.ReadWrite.All','DeviceManagementManagedDevices.Read.All','Device.Read.All','Directory.Read.All','Group.Read.All','GroupMember.Read.All')
} else {
    @('DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Device.Read.All','Directory.Read.All')
}
$context = Get-MgContext
if (-not $context) {
    Write-Status "Connecting to Microsoft Graph..." "White"
    Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"
#endregion

#region --- Resolve Device ---
Write-Section "RESOLVING DEVICE"
Write-Status "Searching for device: $DeviceName"
$devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$DeviceName'"
if ($devices.Count -eq 0) {
    Write-Host "  ERROR: Device '$DeviceName' not found." -ForegroundColor Red
    return
}
$device = $devices[0]
$managedDeviceId = $device.id

Write-Host ""
Write-Host "  Device Name      : $($device.deviceName)" -ForegroundColor White
Write-Host "  OS               : $($device.operatingSystem) $($device.osVersion)" -ForegroundColor Gray
Write-Host "  User             : $($device.userPrincipalName)" -ForegroundColor White
Write-Host "  Compliance       : $($device.complianceState)" -ForegroundColor $(if($device.complianceState -eq 'compliant'){'Green'}elseif($device.complianceState -eq 'conflict'){'Red'}else{'Yellow'})
Write-Host "  Last Sync        : $($device.lastSyncDateTime)" -ForegroundColor Gray
#endregion

if ($Mode -eq 'Analyze') {
    #region --- Analyze Mode ---
    Write-Section "MODE: ANALYZE (finding conflicts and errors)"

    Write-Status "Fetching device configuration policy states..."
    $configStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$managedDeviceId/deviceConfigurationStates"
    Write-Status "Found $($configStates.Count) configuration policy states"

    Write-Status "Fetching compliance policy states..."
    $complianceStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$managedDeviceId/deviceCompliancePolicyStates"
    Write-Status "Found $($complianceStates.Count) compliance policy states"

    Write-Status "Fetching tenant-level conflict summary..."
    $conflictSummary = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurationConflictSummary"

    # Combine
    $allStates = @()
    foreach ($cs in $configStates)    { $allStates += [PSCustomObject]@{ PolicyName=$cs.displayName; PolicyType='Device Configuration'; State=$cs.state; PolicyId=$cs.id } }
    foreach ($cs in $complianceStates) { $allStates += [PSCustomObject]@{ PolicyName=$cs.displayName; PolicyType='Compliance Policy'; State=$cs.state; PolicyId=$cs.id } }

    Write-Section "POLICY STATE OVERVIEW"
    Write-Host ""
    $stateGroups = $allStates | Group-Object State | Sort-Object Name
    foreach ($sg in $stateGroups) {
        $c = switch ($sg.Name) { 'compliant'{'Green'} 'conflict'{'Red'} 'error'{'Red'} 'notApplicable'{'DarkGray'} default{'Gray'} }
        Write-Host "  $($sg.Name) : $($sg.Count)" -ForegroundColor $c
    }

    # Drill into settings for all policies - find overlaps
    $settingReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $settingMap = @{}

    Write-Section "DRILLING INTO PER-SETTING STATES"
    Write-Host ""

    foreach ($cs in $configStates) {
        $settingStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$managedDeviceId/deviceConfigurationStates/$($cs.id)/settingStates"
        foreach ($ss in $settingStates) {
            $key = if ($ss.setting) { $ss.setting } elseif ($ss.settingName) { $ss.settingName } else { continue }
            if ($ss.state -ne 'notApplicable') {
                if (-not $settingMap.ContainsKey($key)) { $settingMap[$key] = @() }
                $settingMap[$key] += [PSCustomObject]@{ PolicyName=$cs.displayName; State=$ss.state; Value=$ss.currentValue }
            }
            if ($ss.state -notin @('compliant','notApplicable')) {
                Write-Host "  [$($ss.state.ToUpper())] $key" -ForegroundColor $(if($ss.state -eq 'conflict'){'Red'}elseif($ss.state -eq 'error'){'Magenta'}else{'Yellow'})
                Write-Host "    Policy : $($cs.displayName)" -ForegroundColor White
                if ($ss.currentValue) { Write-Host "    Value  : $($ss.currentValue)" -ForegroundColor DarkGray }
                if ($ss.sources) { foreach ($src in $ss.sources) { Write-Host "    Source : $($src.displayName) = $($src.value)" -ForegroundColor DarkYellow } }
                Write-Host ""
                $settingReport.Add([PSCustomObject]@{ DeviceName=$device.deviceName; PolicyName=$cs.displayName; SettingPath=$ss.setting; SettingName=$ss.settingName; State=$ss.state; Value=$ss.currentValue; Sources=if($ss.sources){($ss.sources|%{"$($_.displayName)=$($_.value)"})-join'; '}else{'-'} })
            }
        }
    }

    # Overlaps
    $overlaps = $settingMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 } | Sort-Object { $_.Value.Count } -Descending
    if ($overlaps.Count -gt 0) {
        Write-Section "SETTING OVERLAPS ($($overlaps.Count) settings touched by multiple policies)"
        Write-Host ""
        foreach ($ol in $overlaps) {
            $hasConflict = $ol.Value | Where-Object { $_.State -eq 'conflict' }
            $tag = if ($hasConflict) { '[CONFLICT]' } else { '[OVERLAP]' }
            Write-Host "  $($ol.Key) $tag" -ForegroundColor $(if($hasConflict){'Red'}else{'Yellow'})
            foreach ($e in $ol.Value) { Write-Host "    - $($e.PolicyName) [$($e.State)] = $($e.Value)" -ForegroundColor $(if($e.State -eq 'conflict'){'Red'}else{'White'}) }
            Write-Host ""
        }
    }

    Write-Section "ANALYSIS COMPLETE"
    Write-Host ""
    Write-Host "  Policies on device       : $($allStates.Count)" -ForegroundColor White
    Write-Host "  Settings in conflict     : $(($settingReport | Where-Object { $_.State -eq 'conflict' }).Count)" -ForegroundColor $(if(($settingReport|?{$_.State -eq 'conflict'}).Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Settings in error        : $(($settingReport | Where-Object { $_.State -eq 'error' }).Count)" -ForegroundColor $(if(($settingReport|?{$_.State -eq 'error'}).Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Settings with overlaps   : $($overlaps.Count)" -ForegroundColor $(if($overlaps.Count -gt 0){'Yellow'}else{'Green'})
    Write-Host ""
    if ($settingReport.Count -eq 0 -and $overlaps.Count -eq 0) {
        Write-Host "  No conflicts or errors found." -ForegroundColor Green
        Write-Host "  If a feature is broken without a reported conflict, the issue is" -ForegroundColor DarkGray
        Write-Host "  likely a hardening side effect. Try:" -ForegroundColor DarkGray
        Write-Host "    .\Find-IntunePolicyConflict.ps1 -DeviceName '$DeviceName' -Mode Investigate -Feature Hello" -ForegroundColor Cyan
        Write-Host ""
    }
    if ($settingReport.Count -gt 0) {
        $path = if($ExportPath){$ExportPath}else{Join-Path $env:TEMP "$($DeviceName -replace '[^\w\-]','_')_Conflicts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"}
        $settingReport | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Status "Exported to: $path" "Green"
    }
    #endregion

} elseif ($Mode -eq 'Investigate') {
    #region --- Investigate Mode ---
    if (-not $Feature) {
        Write-Host ""
        Write-Host "  -Feature is required for Investigate mode." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Built-in feature maps:" -ForegroundColor Yellow
        foreach ($f in ($featureMaps.Keys | Sort-Object)) {
            $kwCount = $featureMaps[$f].Count
            Write-Host "    $f ($kwCount keywords)" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  Or enter any custom keyword (e.g., -Feature 'Bluetooth')" -ForegroundColor DarkGray
        return
    }

    # Resolve keywords
    $keywords = if ($featureMaps.ContainsKey($Feature)) {
        $featureMaps[$Feature]
    } else {
        @($Feature)
    }

    $mapType = if ($featureMaps.ContainsKey($Feature)) { "built-in map ($($keywords.Count) keywords)" } else { "custom keyword" }

    Write-Section "MODE: INVESTIGATE - Full X-Ray for '$Feature'"
    Write-Host ""
    Write-Host "  This mode shows EVERY setting applied to the device that could" -ForegroundColor DarkGray
    Write-Host "  affect $Feature - INCLUDING settings that applied successfully." -ForegroundColor DarkGray
    Write-Host "  A 'compliant' setting can still break a feature as a side effect." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Feature     : $Feature ($mapType)" -ForegroundColor White
    if ($featureMaps.ContainsKey($Feature)) {
        Write-Host "  Keywords    : $($keywords[0..4] -join ', ')$(if($keywords.Count -gt 5){', ...'})" -ForegroundColor DarkGray
    }
    Write-Host ""

    Write-Status "Fetching all configuration policy states for device..."
    $configStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$managedDeviceId/deviceConfigurationStates"
    Write-Status "$($configStates.Count) policies on device"

    $featureSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $policiesWithMatchingSettings = @{}
    $totalSettingsScanned = 0

    Write-Status "Scanning all settings across all policies for $Feature-related entries..."
    $policyIndex = 0

    foreach ($cs in $configStates) {
        $policyIndex++
        Write-Progress -Activity "Scanning policies" -Status "$policyIndex of $($configStates.Count) - $($cs.displayName)" -PercentComplete (($policyIndex / $configStates.Count) * 100)

        $settingStates = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$managedDeviceId/deviceConfigurationStates/$($cs.id)/settingStates"
        $totalSettingsScanned += $settingStates.Count

        foreach ($ss in $settingStates) {
            $settingPath = if ($ss.setting) { $ss.setting } else { '' }
            $settingName = if ($ss.settingName) { $ss.settingName } else { '' }

            if (Test-SettingMatchesFeature -SettingPath $settingPath -SettingName $settingName -PolicyName $cs.displayName -Keywords $keywords) {

                if (-not $policiesWithMatchingSettings.ContainsKey($cs.displayName)) {
                    $policiesWithMatchingSettings[$cs.displayName] = 0
                }
                $policiesWithMatchingSettings[$cs.displayName]++

                $featureSettings.Add([PSCustomObject]@{
                    PolicyName     = $cs.displayName
                    PolicyState    = $cs.state
                    SettingPath    = $settingPath
                    SettingName    = $settingName
                    SettingState   = $ss.state
                    CurrentValue   = $ss.currentValue
                    Sources        = if ($ss.sources) { ($ss.sources | ForEach-Object { "$($_.displayName)=$($_.value)" }) -join '; ' } else { '-' }
                })
            }
        }
    }
    Write-Progress -Activity "Scanning policies" -Completed

    Write-Section "INVESTIGATION RESULTS FOR: $Feature"
    Write-Host ""
    Write-Host "  Total settings scanned     : $totalSettingsScanned" -ForegroundColor Gray
    Write-Host "  $Feature-related settings  : $($featureSettings.Count)" -ForegroundColor White
    Write-Host "  Policies touching $Feature : $($policiesWithMatchingSettings.Count)" -ForegroundColor White
    Write-Host ""

    if ($featureSettings.Count -eq 0) {
        Write-Host "  No settings matching '$Feature' found on this device." -ForegroundColor Yellow
        Write-Host "  Try a different keyword or check if the feature is controlled" -ForegroundColor DarkGray
        Write-Host "  by a setting not in the built-in map." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  You can also try: -Mode Isolate (binary search)" -ForegroundColor Cyan
        return
    }

    # Group by policy - show which policies are touching this feature area
    Write-Section "POLICIES AFFECTING $($Feature.ToUpper())"
    Write-Host ""

    $groupedByPolicy = $featureSettings | Group-Object PolicyName | Sort-Object { $_.Group.Count } -Descending
    foreach ($pg in $groupedByPolicy) {
        $policyState = $pg.Group[0].PolicyState
        $settingCount = $pg.Group.Count
        $hasIssues = $pg.Group | Where-Object { $_.SettingState -notin @('compliant','notApplicable') }
        $policyColor = if ($hasIssues) { 'Yellow' } else { 'White' }
        $stateTag = if ($policyState -eq 'conflict') { ' [CONFLICT]' } elseif ($policyState -eq 'error') { ' [ERROR]' } else { '' }

        Write-Host "  $($pg.Name)$stateTag ($settingCount settings)" -ForegroundColor $policyColor
    }
    Write-Host ""

    # Show all settings grouped by policy
    Write-Section "DETAILED SETTING VALUES"
    Write-Host ""
    Write-Host "  Legend: Settings marked [COMPLIANT] applied successfully but MAY" -ForegroundColor DarkGray
    Write-Host "  still cause side effects. Review the VALUES, not just the states." -ForegroundColor DarkGray
    Write-Host ""

    foreach ($pg in $groupedByPolicy) {
        Write-Host "  POLICY: $($pg.Name)" -ForegroundColor Yellow
        Write-Host "  $('-' * ($pg.Name.Length + 8))" -ForegroundColor DarkGray

        foreach ($s in ($pg.Group | Sort-Object SettingPath)) {
            $stateColor = switch ($s.SettingState) {
                'compliant'    { 'Green' }
                'conflict'     { 'Red' }
                'error'        { 'Magenta' }
                'notApplicable' { 'DarkGray' }
                default        { 'Yellow' }
            }
            $stateTag = "[$($s.SettingState.ToUpper())]"

            # Highlight potentially disruptive values
            $valueColor = 'DarkGray'
            $disruptiveFlag = ''
            if ($s.CurrentValue) {
                $val = $s.CurrentValue.ToString().ToLower()
                if ($val -in @('disabled','blocked','0','false','not allowed','not configured','deny','block')) {
                    $valueColor = 'DarkYellow'
                    $disruptiveFlag = ' <-- RESTRICTIVE'
                }
            }

            Write-Host "    $stateTag " -ForegroundColor $stateColor -NoNewline
            Write-Host "$($s.SettingPath)" -ForegroundColor White
            if ($s.SettingName -and $s.SettingName -ne $s.SettingPath) {
                Write-Host "      Name  : $($s.SettingName)" -ForegroundColor DarkCyan
            }
            Write-Host "      Value : $($s.CurrentValue)$disruptiveFlag" -ForegroundColor $valueColor
            if ($s.Sources -ne '-') {
                Write-Host "      Sources: $($s.Sources)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }

    # Flag potentially disruptive settings
    $restrictive = $featureSettings | Where-Object {
        $v = $_.CurrentValue
        $v -and ($v.ToString().ToLower() -in @('disabled','blocked','0','false','not allowed','deny','block'))
    }

    if ($restrictive.Count -gt 0) {
        Write-Section "POTENTIALLY DISRUPTIVE SETTINGS ($($restrictive.Count))"
        Write-Host ""
        Write-Host "  These settings have restrictive values (disabled/blocked/0/false)" -ForegroundColor Yellow
        Write-Host "  that could break $Feature even without a conflict:" -ForegroundColor Yellow
        Write-Host ""
        foreach ($r in $restrictive) {
            Write-Host "  $($r.SettingPath)" -ForegroundColor Red
            Write-Host "    Policy : $($r.PolicyName)" -ForegroundColor White
            Write-Host "    Value  : $($r.CurrentValue)" -ForegroundColor DarkYellow
            Write-Host ""
        }
    }

    # Summary
    Write-Section "INVESTIGATION SUMMARY"
    Write-Host ""
    Write-Host "  Feature investigated       : $Feature" -ForegroundColor White
    Write-Host "  Policies touching feature  : $($policiesWithMatchingSettings.Count)" -ForegroundColor White
    Write-Host "  Total related settings     : $($featureSettings.Count)" -ForegroundColor White
    Write-Host "  Restrictive values found   : $($restrictive.Count)" -ForegroundColor $(if($restrictive.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Settings in conflict/error : $(($featureSettings | Where-Object { $_.SettingState -in @('conflict','error') }).Count)" -ForegroundColor $(if(($featureSettings|?{$_.SettingState -in @('conflict','error')}).Count -gt 0){'Red'}else{'Green'})
    Write-Host ""

    if ($restrictive.Count -gt 0) {
        Write-Host "  NEXT STEP: Review the restrictive settings above. One of those" -ForegroundColor Cyan
        Write-Host "  policies is likely hardening a setting that $Feature depends on." -ForegroundColor Cyan
        Write-Host "  Try relaxing the value in a test policy to confirm." -ForegroundColor Cyan
    } else {
        Write-Host "  No obviously restrictive values found. The issue may be more subtle." -ForegroundColor DarkGray
        Write-Host "  Consider: -Mode Isolate for binary search." -ForegroundColor Cyan
    }

    # Export
    if ($featureSettings.Count -gt 0) {
        $safeFeature = $Feature -replace '[^\w\-]','_'
        $path = if($ExportPath){$ExportPath}else{Join-Path $env:TEMP "$($DeviceName -replace '[^\w\-]','_')_Investigate_$($safeFeature)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"}
        $featureSettings | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        Write-Status "Exported $($featureSettings.Count) settings to: $path" "Green"
    }
    #endregion

} elseif ($Mode -eq 'Isolate') {
    #region --- Isolate Mode (Binary Search) ---
    Write-Section "MODE: ISOLATE - Binary Search Policy Isolation"
    Write-Host ""
    Write-Host "  This mode will TEMPORARILY modify policy assignments to isolate" -ForegroundColor Yellow
    Write-Host "  the culprit policy. All changes are REVERTED at the end." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  How it works:" -ForegroundColor White
    Write-Host "    1. Collects all group-assigned config policies on this device" -ForegroundColor DarkGray
    Write-Host "    2. Temporarily removes HALF the policy assignments" -ForegroundColor DarkGray
    Write-Host "    3. You sync the device and test the broken feature" -ForegroundColor DarkGray
    Write-Host "    4. You report: Fixed (F) or Still Broken (B)" -ForegroundColor DarkGray
    Write-Host "    5. Narrows by half each round until 1 policy remains" -ForegroundColor DarkGray
    Write-Host "    6. ALL original assignments restored automatically" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "  Type YES to proceed (this will temporarily modify assignments)"
    if ($confirm -ne 'YES') {
        Write-Host "  Aborted." -ForegroundColor Yellow
        return
    }

    # Resolve device's Entra object
    $entraDeviceId = $device.azureADDeviceId
    $entraDevices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$entraDeviceId'&`$select=id"
    if ($entraDevices.Count -eq 0) {
        Write-Host "  ERROR: Cannot resolve Entra device." -ForegroundColor Red
        return
    }

    # Collect policies with group-based assignments
    Write-Status "Collecting policies with assignments..."
    $policyTypes = @(
        @{ Name='Device Configurations'; Uri='https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'; NameProp='displayName' }
        @{ Name='Settings Catalog';      Uri='https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'; NameProp='name' }
    )

    $candidatePolicies = @()
    foreach ($pt in $policyTypes) {
        $policies = Invoke-MgGraph-Safe -Uri "$($pt.Uri)?`$expand=Assignments"
        foreach ($p in $policies) {
            if (-not $p.assignments) { continue }
            foreach ($a in $p.assignments) {
                $target = $a.target
                if (-not $target) { continue }
                if ($target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $target.groupId) {
                    $pName = $p.($pt.NameProp); if (-not $pName) { $pName = $p.displayName }; if (-not $pName) { $pName = $p.name }
                    $candidatePolicies += [PSCustomObject]@{ PolicyName=$pName; PolicyId=$p.id; PolicyType=$pt.Name; BaseUri=$pt.Uri; GroupId=$target.groupId }
                }
            }
        }
    }
    $candidatePolicies = $candidatePolicies | Sort-Object PolicyId -Unique

    if ($candidatePolicies.Count -lt 2) {
        Write-Host "  Only $($candidatePolicies.Count) candidate(s) found. Need at least 2." -ForegroundColor Yellow
        return
    }

    Write-Status "$($candidatePolicies.Count) candidate policies" "Green"

    # Backup all assignments
    $originalAssignments = @{}
    foreach ($cp in $candidatePolicies) {
        $assignments = Invoke-MgGraph-Safe -Uri "$($cp.BaseUri)/$($cp.PolicyId)/assignments"
        $originalAssignments[$cp.PolicyId] = @{ BaseUri=$cp.BaseUri; PolicyName=$cp.PolicyName; Assignments=$assignments }
    }
    Write-Status "Backed up assignments for $($originalAssignments.Count) policies" "Green"

    $suspects = [System.Collections.ArrayList]::new($candidatePolicies)
    $round = 0
    $totalRoundsEstimate = [math]::Ceiling([math]::Log($suspects.Count, 2))

    try {
        while ($suspects.Count -gt 1) {
            $round++
            $mid = [math]::Ceiling($suspects.Count / 2)
            $removeGroup = $suspects[0..($mid-1)]
            $keepGroup = $suspects[$mid..($suspects.Count-1)]

            Write-Section "ROUND $round of ~$totalRoundsEstimate | $($suspects.Count) remaining"
            Write-Host ""
            Write-Host "  REMOVING ($($removeGroup.Count)):" -ForegroundColor Yellow
            $removeGroup | ForEach-Object { Write-Host "    - $($_.PolicyName)" -ForegroundColor DarkYellow }
            Write-Host "  KEEPING ($($keepGroup.Count)):" -ForegroundColor Green
            $keepGroup | ForEach-Object { Write-Host "    - $($_.PolicyName)" -ForegroundColor DarkGreen }
            Write-Host ""

            foreach ($rp in $removeGroup) {
                $cur = Invoke-MgGraph-Safe -Uri "$($rp.BaseUri)/$($rp.PolicyId)/assignments"
                $filtered = $cur | Where-Object { $_.target.groupId -ne $rp.GroupId }
                $body = @{ assignments = @($filtered | ForEach-Object { @{ target=$_.target } }) } | ConvertTo-Json -Depth 10
                try { Invoke-MgGraphRequest -Uri "$($rp.BaseUri)/$($rp.PolicyId)/assign" -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null }
                catch { Write-Host "    WARNING: $($rp.PolicyName): $_" -ForegroundColor Yellow }
            }

            Write-Host "  >>> Sync device and test the broken feature now." -ForegroundColor Cyan
            Write-Host ""
            $answer = Read-Host "  Result? (F = Fixed, B = Still Broken, Q = Quit)"

            # Restore removed policies before narrowing
            foreach ($rp in $removeGroup) {
                $orig = $originalAssignments[$rp.PolicyId]
                $body = @{ assignments = @($orig.Assignments | ForEach-Object { @{ target=$_.target } }) } | ConvertTo-Json -Depth 10
                try { Invoke-MgGraphRequest -Uri "$($rp.BaseUri)/$($rp.PolicyId)/assign" -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null } catch {}
            }

            switch ($answer.Trim().ToUpper()) {
                'F' { $suspects = [System.Collections.ArrayList]::new($removeGroup) }
                'B' { $suspects = [System.Collections.ArrayList]::new($keepGroup) }
                'Q' { throw "UserQuit" }
                default { Write-Host "  Invalid. Retrying round..." -ForegroundColor Red; continue }
            }
        }

        Write-Section "CULPRIT FOUND"
        Write-Host ""
        Write-Host "  The policy causing the issue:" -ForegroundColor Green
        Write-Host "    Name : $($suspects[0].PolicyName)" -ForegroundColor White
        Write-Host "    Type : $($suspects[0].PolicyType)" -ForegroundColor White
        Write-Host "    ID   : $($suspects[0].PolicyId)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Isolated in $round round(s) out of $($candidatePolicies.Count) policies." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next step: Use -Mode Investigate to see exactly which settings" -ForegroundColor Cyan
        Write-Host "  in this policy are causing the issue." -ForegroundColor Cyan

    } catch {
        if ($_.Exception.Message -ne 'UserQuit') { Write-Host "  ERROR: $_" -ForegroundColor Red }
    } finally {
        Write-Section "RESTORING ALL ORIGINAL ASSIGNMENTS"
        $restored = 0
        foreach ($pid in $originalAssignments.Keys) {
            $orig = $originalAssignments[$pid]
            $body = @{ assignments = @($orig.Assignments | ForEach-Object { @{ target=$_.target } }) } | ConvertTo-Json -Depth 10
            try { Invoke-MgGraphRequest -Uri "$($orig.BaseUri)/$pid/assign" -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null; $restored++ } catch { Write-Host "  FAILED: $($orig.PolicyName): $_" -ForegroundColor Red }
        }
        Write-Status "$restored of $($originalAssignments.Count) policies restored" "Green"
    }
    #endregion
}

Write-Host "`n$('='*60)" -ForegroundColor DarkGray


