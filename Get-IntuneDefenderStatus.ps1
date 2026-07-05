#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Microsoft Defender health status across all Intune managed Windows devices.
.DESCRIPTION
    Pulls Windows protection state from all managed devices and reports:
    signature age, real-time protection status, last scan dates, devices
    with active threats, devices with outdated signatures, and devices
    where Defender is disabled or unhealthy.
.PARAMETER SignatureAgeDays
    Flag devices with signatures older than this many days. Default: 3.
.PARAMETER ExportPath
    Optional. Export results to CSV.
.EXAMPLE
    .\Get-IntuneDefenderStatus.ps1
.EXAMPLE
    .\Get-IntuneDefenderStatus.ps1 -SignatureAgeDays 7
#>

[CmdletBinding()]
param(
    [Parameter()][int]$SignatureAgeDays = 3,
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
    Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "COLLECTING DEFENDER STATUS"
Write-Status "Fetching Windows managed devices..."

$devices = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,userPrincipalName,osVersion,complianceState,lastSyncDateTime"
Write-Status "Found $($devices.Count) Windows devices" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$healthyCount = 0; $unhealthyCount = 0; $outdatedSigCount = 0; $threatCount = 0; $rtpDisabledCount = 0; $noDataCount = 0

$deviceIndex = 0
foreach ($d in $devices) {
    $deviceIndex++
    if ($deviceIndex % 25 -eq 0) { Write-Progress -Activity "Fetching Defender status" -Status "$deviceIndex of $($devices.Count)" -PercentComplete (($deviceIndex/$devices.Count)*100) }

    $protState = $null
    try {
        $protState = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.id)/windowsProtectionState" -Method GET -ErrorAction Stop
    } catch { }

    if (-not $protState) {
        $noDataCount++
        $report.Add([PSCustomObject]@{
            DeviceName=$d.deviceName; User=$d.userPrincipalName; OSVersion=$d.osVersion
            RealTimeProtection='No data'; EngineVersion='-'; SignatureVersion='-'
            SignatureLastUpdated='-'; SignatureAgeDays=-1; LastQuickScan='-'; LastFullScan='-'
            MalwareProtection='No data'; NetworkInspection='No data'
            ActiveThreats=0; ThreatStatus='-'; ComplianceState=$d.complianceState
            HealthStatus='No Data'; LastSync=$d.lastSyncDateTime
        })
        continue
    }

    $rtpEnabled = $protState.realTimeProtectionEnabled
    $engineVer = $protState.engineVersion
    $sigVer = $protState.antiVirusSignatureVersion
    $sigUpdated = $protState.antiVirusSignatureLastUpdateDateTime
    $lastQuick = $protState.lastQuickScanDateTime
    $lastFull = $protState.lastFullScanDateTime
    $malwareProt = $protState.malwareProtectionEnabled
    $networkInsp = $protState.networkInspectionSystemEnabled
    $productStatus = $protState.productStatus
    $isVm = $protState.isVirtualMachine

    $sigAge = if ($sigUpdated) { [math]::Round(((Get-Date) - [datetime]$sigUpdated).TotalDays, 1) } else { 999 }
    $isSigOutdated = $sigAge -gt $SignatureAgeDays

    # Get detected threats
    $threats = @()
    try {
        $threats = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.id)/windowsProtectionState/detectedMalwareState"
    } catch { }
    $activeThreatCount = ($threats | Where-Object { $_.state -ne 'fullyStopped' -and $_.state -ne 'cleaned' }).Count

    # Determine health
    $healthStatus = 'Healthy'
    $issues = @()
    if (-not $rtpEnabled) { $issues += 'RTP disabled'; $rtpDisabledCount++ }
    if ($isSigOutdated) { $issues += "Signatures $([math]::Round($sigAge))d old"; $outdatedSigCount++ }
    if ($activeThreatCount -gt 0) { $issues += "$activeThreatCount active threat(s)"; $threatCount++ }
    if (-not $malwareProt) { $issues += 'Malware protection off' }

    if ($issues.Count -gt 0) { $healthStatus = 'Unhealthy'; $unhealthyCount++ } else { $healthyCount++ }

    $report.Add([PSCustomObject]@{
        DeviceName            = $d.deviceName
        User                  = $d.userPrincipalName
        OSVersion             = $d.osVersion
        RealTimeProtection    = $rtpEnabled
        EngineVersion         = $engineVer
        SignatureVersion      = $sigVer
        SignatureLastUpdated   = $sigUpdated
        SignatureAgeDays      = [math]::Round($sigAge, 1)
        LastQuickScan         = $lastQuick
        LastFullScan          = $lastFull
        MalwareProtection     = $malwareProt
        NetworkInspection     = $networkInsp
        ActiveThreats         = $activeThreatCount
        ThreatStatus          = if ($threats.Count -gt 0) { ($threats | ForEach-Object { "$($_.displayName):$($_.state)" }) -join '; ' } else { 'Clean' }
        ComplianceState       = $d.complianceState
        HealthStatus          = $healthStatus
        Issues                = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
        LastSync              = $d.lastSyncDateTime
    })
}
Write-Progress -Activity "Fetching Defender status" -Completed

Write-Section "DEFENDER HEALTH SUMMARY"
Write-Host ""
$totalReporting = $devices.Count - $noDataCount
Write-Host "  Total Windows devices    : $($devices.Count)" -ForegroundColor White
Write-Host "  Reporting Defender data  : $totalReporting" -ForegroundColor White
Write-Host "  No Defender data         : $noDataCount" -ForegroundColor $(if($noDataCount -gt 0){'Yellow'}else{'DarkGray'})
Write-Host ""
Write-Host "  Healthy                  : $healthyCount" -ForegroundColor Green
Write-Host "  Unhealthy                : $unhealthyCount" -ForegroundColor $(if($unhealthyCount -gt 0){'Red'}else{'Green'})
Write-Host "  RTP disabled             : $rtpDisabledCount" -ForegroundColor $(if($rtpDisabledCount -gt 0){'Red'}else{'Green'})
Write-Host "  Outdated signatures (>$SignatureAgeDays d): $outdatedSigCount" -ForegroundColor $(if($outdatedSigCount -gt 0){'Yellow'}else{'Green'})
Write-Host "  Active threats           : $threatCount device(s)" -ForegroundColor $(if($threatCount -gt 0){'Red'}else{'Green'})

if ($totalReporting -gt 0) {
    $healthPct = [math]::Round(($healthyCount / $totalReporting) * 100, 1)
    Write-Host ""
    Write-Host "  Defender health rate     : $healthPct%" -ForegroundColor $(if($healthPct -ge 95){'Green'}elseif($healthPct -ge 80){'Yellow'}else{'Red'})
}

# Show unhealthy devices
$unhealthy = $report | Where-Object { $_.HealthStatus -eq 'Unhealthy' } | Sort-Object { $_.ActiveThreats } -Descending
if ($unhealthy.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Unhealthy Devices ---" -ForegroundColor Red
    foreach ($u in ($unhealthy | Select-Object -First 20)) {
        Write-Host "    $($u.DeviceName) | $($u.Issues)" -ForegroundColor DarkYellow
    }
    if ($unhealthy.Count -gt 20) { Write-Host "    ... and $($unhealthy.Count - 20) more" -ForegroundColor DarkGray }
}

# Signature version distribution
$sigVersions = $report | Where-Object { $_.SignatureVersion -ne '-' } | Group-Object SignatureVersion | Sort-Object Count -Descending | Select-Object -First 5
if ($sigVersions.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Top Signature Versions ---" -ForegroundColor Yellow
    foreach ($sv in $sigVersions) {
        Write-Host "    $($sv.Name) : $($sv.Count) device(s)" -ForegroundColor White
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "DefenderStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


