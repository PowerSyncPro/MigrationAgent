<#
.DESCRIPTION
    Cleans up remnants of a migration.
    Clears deny logon rights (preserves Guest in local deny), resets lock screen policy, clears legal notice.

    To be used in a situation where the PowerSyncPro Migration Agent doesn't clear out the locak screen, legal notice, or local GPO preventing user login.

    Login as a local administrator on the affected system and run this script.
 
.PARAMETERS
    -None

.NOTES
    Date            January/2026
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 2.0
    Updated: 18th Jan 2026 - Initial Release
#>

#Requires -RunAsAdministrator

# CompletionCleanup.ps1
# 

$ErrorActionPreference = 'Stop'

Write-Host "Starting CompletionCleanup operations..." -ForegroundColor Cyan

# 1. Process deny logon rights
Write-Host ""
Write-Host "1. Processing deny logon rights..."

$secedit   = Join-Path $env:SystemRoot 'System32\secedit.exe'
$temp      = [System.IO.Path]::GetTempPath()
$ts        = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportInf = Join-Path $temp "sec_export_$ts.inf"
$modInf    = Join-Path $temp "sec_mod_$ts.inf"
$verifyInf = Join-Path $temp "sec_verify_$ts.inf"
$logFile   = Join-Path $temp "sec_apply_$ts.log"

& $secedit /export /cfg $exportInf /areas USER_RIGHTS /quiet
if (-not (Test-Path $exportInf)) {
    Write-Host "  ERROR: secedit export failed" -ForegroundColor Red
    exit 1
}

$content = Get-Content $exportInf -Encoding Unicode -Raw

Write-Host "  Before changes:"
$rights = @(
    @{Name = 'SeDenyInteractiveLogonRight'; Display = 'Deny log on locally'},
    @{Name = 'SeDenyRemoteInteractiveLogonRight'; Display = 'Deny log on through Remote Desktop Services'}
)

foreach ($r in $rights) {
    if ($content -match "(?m)^$([regex]::Escape($r.Name))\s*=\s*(.*)") {
        $val = $Matches[1].Trim()
        if ($val -eq '*' -or $val -eq '') {
            Write-Host "    $($r.Display): empty"
        } else {
            $entries = $val -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            Write-Host "    $($r.Display): $($entries.Count) entries"
            foreach ($e in $entries) {
                Write-Host "      - $e"
            }
        }
    } else {
        Write-Host "    $($r.Display): not present"
    }
}

# Build modified content
$newContent = $content

# Preserve Guest in Deny log on locally
if ($newContent -match '(?m)^SeDenyInteractiveLogonRight\s*=\s*(.*)') {
    $oldVal = $Matches[1].Trim()
    $entries = if ($oldVal -eq '*' -or $oldVal -eq '') { @() } else { $oldVal -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
    $keep = $entries | Where-Object { $_ -eq 'Guest' -or $_ -like '*Guest*' }
    $newVal = if ($keep) { $keep -join ',' } else { '*' }
    $newContent = $newContent -replace '(?m)^(SeDenyInteractiveLogonRight\s*=\s*).*$', "`$1$newVal"
} else {
    $newContent += "`nSeDenyInteractiveLogonRight = Guest`r`n"
}

# Clear Deny RDP completely
$newContent = $newContent -replace '(?m)^(SeDenyRemoteInteractiveLogonRight\s*=\s*).*$', '$1*'

$newContent | Out-File $modInf -Encoding Unicode -Force

Write-Host "  Applying deny rights changes..."
& $secedit /configure /db "$env:windir\security\local.sdb" /cfg $modInf /areas USER_RIGHTS /log $logFile /quiet
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host "  secedit returned $exitCode - trying temp database..."
    $tempDb = Join-Path $temp "tempdb_$ts.sdb"
    & $secedit /configure /db $tempDb /cfg $modInf /areas USER_RIGHTS /overwrite /log $logFile /quiet
    $exitCode = $LASTEXITCODE
}

# Verify deny rights
& $secedit /export /cfg $verifyInf /areas USER_RIGHTS /quiet
if (Test-Path $verifyInf) {
    $vc = Get-Content $verifyInf -Encoding Unicode -Raw
    Write-Host "  After deny rights changes:"
    if ($vc -match 'SeDenyInteractiveLogonRight\s*=\s*Guest') {
        Write-Host "    Deny log on locally: Guest preserved" -ForegroundColor Green
    } elseif ($vc -match 'SeDenyInteractiveLogonRight\s*=\s*\*') {
        Write-Host "    Deny log on locally: empty (Guest not present)" -ForegroundColor Green
    }
    if ($vc -match 'SeDenyRemoteInteractiveLogonRight\s*=\s*\*') {
        Write-Host "    Deny log on through RDP: cleared" -ForegroundColor Green
    }
}

Remove-Item -Path $exportInf,$modInf,$verifyInf,$logFile -Force -EA SilentlyContinue

# 2. Reset lock screen (correct PersonalizationCSP path)
Write-Host ""
Write-Host "2. Resetting lock screen to default..."

$cspPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
$keysRemoved = $false

if (Test-Path $cspPath) {
    @("LockScreenImagePath", "LockScreenImageUrl", "LockScreenImageStatus") | ForEach-Object {
        if (Get-ItemProperty -Path $cspPath -Name $_ -EA SilentlyContinue) {
            Remove-ItemProperty -Path $cspPath -Name $_ -EA SilentlyContinue
            $keysRemoved = $true
        }
    }
    if ($keysRemoved) {
        Write-Host "  Removed lock screen CSP keys" -ForegroundColor Green
    } else {
        Write-Host "  No lock screen CSP keys found" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No PersonalizationCSP path found" -ForegroundColor Yellow
}

# 3. Clear legal notice (correct Winlogon path)
Write-Host ""
Write-Host "3. Clearing legal notice (pre-logon message)..."

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$noticeRemoved = $false

@("LegalNoticeCaption", "LegalNoticeText") | ForEach-Object {
    if (Get-ItemProperty -Path $winlogonPath -Name $_ -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $winlogonPath -Name $_ -ErrorAction SilentlyContinue
        $noticeRemoved = $true
    }
}

if ($noticeRemoved) {
    Write-Host "  Removed LegalNoticeCaption and LegalNoticeText from Winlogon" -ForegroundColor Green
} else {
    Write-Host "  No legal notice was configured in Winlogon" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "CompletionCleanup finished." -ForegroundColor Cyan
Write-Host " - Guest preserved in Deny log on locally (if it existed)"
Write-Host " - Other deny entries removed"
Write-Host " - Lock screen policy reset"
Write-Host " - Legal notice cleared"
Write-Host " - Log off/on or reboot recommended to apply all changes"
Write-Host " - If changes revert, check domain GPO with gpresult /h report.html"

Write-Host "Done." -ForegroundColor Green