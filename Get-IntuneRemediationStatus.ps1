#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Reports Proactive Remediation (Health Script) execution status.
.DESCRIPTION
    Shows detection pass/fail rates and remediation success rates for all
    Device Health Scripts. Identifies scripts with high failure rates and
    devices that consistently fail detection.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-IntuneRemediationStatus.ps1
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
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "PROACTIVE REMEDIATION STATUS"
$healthScripts = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$filter=publisher ne 'Microsoft'"
Write-Status "Found $($healthScripts.Count) custom health scripts (excluding Microsoft built-ins)" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($hs in $healthScripts) {
    $hsName = $hs.displayName
    Write-Status "Checking: $hsName..."

    # Get run summary
    try {
        $summary = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($hs.id)/runSummary" -Method GET -ErrorAction Stop
    } catch { $summary = $null }

    $detectionOk = 0; $detectionFail = 0; $remediationOk = 0; $remediationFail = 0
    $totalDevices = 0; $noIssueCount = 0; $issueFoundCount = 0

    if ($summary) {
        $detectionOk = if ($summary.noIssueDetectedDeviceCount) { $summary.noIssueDetectedDeviceCount } else { 0 }
        $detectionFail = if ($summary.issueDetectedDeviceCount) { $summary.issueDetectedDeviceCount } else { 0 }
        $remediationOk = if ($summary.issueRemediatedDeviceCount) { $summary.issueRemediatedDeviceCount } else { 0 }
        $remediationFail = if ($summary.issueRemediatedFailedDeviceCount) { $summary.issueRemediatedFailedDeviceCount } else { 0 }
        $noIssueCount = $detectionOk
        $issueFoundCount = $detectionFail
        $totalDevices = $detectionOk + $detectionFail
    }

    $detectionRate = if ($totalDevices -gt 0) { [math]::Round(($detectionOk / $totalDevices) * 100, 1) } else { 0 }
    $remediationRate = if ($issueFoundCount -gt 0) { [math]::Round(($remediationOk / $issueFoundCount) * 100, 1) } else { 0 }

    $hasProblems = $detectionFail -gt 0 -or $remediationFail -gt 0
    $nameColor = if ($remediationFail -gt 0) { 'Red' } elseif ($detectionFail -gt 0) { 'Yellow' } else { 'Green' }

    Write-Host "    $hsName" -ForegroundColor $nameColor
    Write-Host "      Devices: $totalDevices | Detection OK: $detectionOk | Issues found: $issueFoundCount | Remediated: $remediationOk | Rem failed: $remediationFail" -ForegroundColor $(if($hasProblems){'DarkYellow'}else{'DarkGray'})

    $report.Add([PSCustomObject]@{
        ScriptName         = $hsName
        Description        = $hs.description
        Publisher          = $hs.publisher
        RunAsAccount       = $hs.runAsAccount
        TotalDevices       = $totalDevices
        DetectionOK        = $detectionOk
        IssuesDetected     = $issueFoundCount
        Remediated         = $remediationOk
        RemediationFailed  = $remediationFail
        DetectionPassRate  = $detectionRate
        RemediationRate    = $remediationRate
        EnforceSignature   = $hs.enforceSignatureCheck
        RunAs32Bit         = $hs.runAs32Bit
        LastModified       = $hs.lastModifiedDateTime
    })
}

Write-Section "REMEDIATION SUMMARY"
Write-Host ""
Write-Host "  Total remediation scripts : $($healthScripts.Count)" -ForegroundColor White

$failingScripts = $report | Where-Object { $_.RemediationFailed -gt 0 }
$highDetection = $report | Where-Object { $_.IssuesDetected -gt ($_.TotalDevices * 0.5) -and $_.TotalDevices -gt 5 }

Write-Host "  Scripts with rem failures : $($failingScripts.Count)" -ForegroundColor $(if($failingScripts.Count -gt 0){'Red'}else{'Green'})
Write-Host "  Scripts >50% issue rate   : $($highDetection.Count)" -ForegroundColor $(if($highDetection.Count -gt 0){'Yellow'}else{'Green'})

if ($failingScripts.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Scripts with Remediation Failures ---" -ForegroundColor Red
    foreach ($fs in ($failingScripts | Sort-Object RemediationFailed -Descending)) {
        Write-Host "    $($fs.ScriptName) : $($fs.RemediationFailed) failed remediation(s)" -ForegroundColor DarkYellow
    }
}

if ($highDetection.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Scripts with High Issue Detection Rate ---" -ForegroundColor Yellow
    foreach ($hd in ($highDetection | Sort-Object DetectionPassRate)) {
        Write-Host "    $($hd.ScriptName) : $($hd.IssuesDetected)/$($hd.TotalDevices) devices have issues ($($hd.DetectionPassRate)% pass)" -ForegroundColor DarkYellow
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "RemediationStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
Write-Host ""


