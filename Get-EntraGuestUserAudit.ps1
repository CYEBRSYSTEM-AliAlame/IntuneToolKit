#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Audits external/guest users in Entra ID.
.DESCRIPTION
    Lists all guest users and flags: guests who never signed in, guests
    inactive for 90+ days, guest group memberships, and invitation status.
.PARAMETER InactiveDays
    Flag guests inactive for more than this many days. Default: 90.
.PARAMETER ExportPath
    Optional. Export to CSV.
.EXAMPLE
    .\Get-EntraGuestUserAudit.ps1
.EXAMPLE
    .\Get-EntraGuestUserAudit.ps1 -InactiveDays 60
#>

[CmdletBinding()]
param(
    [Parameter()][int]$InactiveDays = 90,
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
    Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','Directory.Read.All','GroupMember.Read.All' -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "GUEST USER INVENTORY"
$guests = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,userPrincipalName,displayName,mail,createdDateTime,externalUserState,externalUserStateChangeDateTime,accountEnabled,signInActivity"
Write-Status "$($guests.Count) guest users found" "Green"

if ($guests.Count -eq 0) {
    Write-Host "  No guest users in this tenant." -ForegroundColor Green
    return
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$neverSignedIn = 0; $staleCount = 0; $pendingInvite = 0; $disabledCount = 0

$now = Get-Date

foreach ($g in $guests) {
    $lastSignIn = $null; $daysSinceSignIn = 999
    if ($g.signInActivity -and $g.signInActivity.lastSignInDateTime) {
        $lastSignIn = [datetime]$g.signInActivity.lastSignInDateTime
        $daysSinceSignIn = [math]::Round(($now - $lastSignIn).TotalDays, 0)
    }

    $neverSignedInFlag = -not $lastSignIn
    $isStale = $daysSinceSignIn -gt $InactiveDays
    $isPending = $g.externalUserState -eq 'PendingAcceptance'
    $isDisabled = -not $g.accountEnabled

    if ($neverSignedInFlag) { $neverSignedIn++ }
    if ($isStale -and -not $neverSignedInFlag) { $staleCount++ }
    if ($isPending) { $pendingInvite++ }
    if ($isDisabled) { $disabledCount++ }

    # Get group memberships (sample - expensive for large tenants)
    $groupCount = 0
    $groupNames = '-'
    try {
        $memberOf = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$($g.id)/memberOf?`$select=id,displayName,@odata.type&`$top=50" -Method GET -ErrorAction Stop
        if ($memberOf.value) {
            $groups = $memberOf.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
            $groupCount = $groups.Count
            $groupNames = ($groups | ForEach-Object { $_.displayName }) -join '; '
        }
    } catch { }

    $issues = @()
    if ($neverSignedInFlag) { $issues += 'Never signed in' }
    elseif ($isStale) { $issues += "Inactive $daysSinceSignIn days" }
    if ($isPending) { $issues += 'Invitation pending' }
    if ($isDisabled) { $issues += 'Account disabled' }

    $report.Add([PSCustomObject]@{
        DisplayName       = $g.displayName
        Email             = $g.mail
        UserPrincipalName = $g.userPrincipalName
        AccountEnabled    = $g.accountEnabled
        InvitationState   = $g.externalUserState
        Created           = $g.createdDateTime
        LastSignIn        = $lastSignIn
        DaysSinceSignIn   = if ($neverSignedInFlag) { 'Never' } else { $daysSinceSignIn }
        GroupCount        = $groupCount
        Groups            = $groupNames
        IsStale           = $isStale
        NeverSignedIn     = $neverSignedInFlag
        Issues            = if ($issues.Count -gt 0) { $issues -join '; ' } else { '-' }
    })
}

Write-Section "GUEST USER AUDIT SUMMARY"
Write-Host ""
Write-Host "  Total guests           : $($guests.Count)" -ForegroundColor White
Write-Host "  Never signed in        : $neverSignedIn" -ForegroundColor $(if($neverSignedIn -gt 0){'Red'}else{'Green'})
Write-Host "  Inactive ($InactiveDays+ days)   : $staleCount" -ForegroundColor $(if($staleCount -gt 0){'Yellow'}else{'Green'})
Write-Host "  Pending invitation     : $pendingInvite" -ForegroundColor $(if($pendingInvite -gt 0){'DarkYellow'}else{'Green'})
Write-Host "  Disabled accounts      : $disabledCount" -ForegroundColor DarkGray

$issueGuests = $report | Where-Object { $_.Issues -ne '-' }
if ($issueGuests.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Guests with Issues ($($issueGuests.Count)) ---" -ForegroundColor Yellow
    foreach ($ig in ($issueGuests | Sort-Object { if ($_.NeverSignedIn) { 0 } else { 1 } } | Select-Object -First 20)) {
        Write-Host "    $($ig.Email) | $($ig.Issues) | Groups: $($ig.GroupCount)" -ForegroundColor DarkYellow
    }
    if ($issueGuests.Count -gt 20) { Write-Host "    ... and $($issueGuests.Count - 20) more" -ForegroundColor DarkGray }
}

# Guests with most group memberships
$topGroupGuests = $report | Where-Object { $_.GroupCount -gt 3 } | Sort-Object GroupCount -Descending | Select-Object -First 10
if ($topGroupGuests.Count -gt 0) {
    Write-Host ""
    Write-Host "  --- Guests with Most Group Memberships ---" -ForegroundColor Yellow
    foreach ($tg in $topGroupGuests) {
        Write-Host "    $($tg.Email) : $($tg.GroupCount) groups" -ForegroundColor White
    }
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "GuestAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""


