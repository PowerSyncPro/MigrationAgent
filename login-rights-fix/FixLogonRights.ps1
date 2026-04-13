#requires -RunAsAdministrator

<#
.SYNOPSIS
    Fixes "Allow log on locally" rights to unblock Entra ID users on AD-to-Entra migrated machines.

.DESCRIPTION
    When machines are migrated from Active Directory to Entra ID (Azure AD join), the local
    security policy "Allow log on locally" (SeInteractiveLogonRight) may retain stale AD group
    entries that prevent Entra users from signing in interactively.

    This script:
      1. Exports the current local security policy via secedit.
      2. Replaces SeInteractiveLogonRight with the correct well-known SIDs
         (Administrators, Users, Backup Operators, Guest).
      3. Clears SeDenyInteractiveLogonRight to remove any explicit deny entries.
      4. Re-imports the modified policy scoped to USER_RIGHTS only.
      5. Re-exports and verifies the changes were applied successfully.
      6. Forces a computer group policy refresh.

    Log is written to C:\Temp\Fix-SeInteractiveLogonRight.log on each run (previous log cleared).
    A reboot is recommended after this script completes.

.NOTES
    Must be run as Administrator.
    Tested on Windows 10 / 11 Entra-joined machines.
    Run AFTER the machine has been Entra-joined and AD-removed.

.EXAMPLE
    .\FixLogonRights.ps1
#>

$ErrorActionPreference = 'Stop'

# ── Configuration ─────────────────────────────────────────────────────────────
$TempPath   = 'C:\Temp'
$ExportPath = Join-Path $TempPath 'secpol-export.inf'
$ImportPath = Join-Path $TempPath 'secpol-import.inf'
$VerifyPath = Join-Path $TempPath 'secpol-verify.inf'
$DbPath     = Join-Path $TempPath 'secedit.sdb'
$LogPath    = Join-Path $TempPath 'Fix-SeInteractiveLogonRight.log'

# Well-known local SIDs granted interactive logon:
#   S-1-5-32-544  Administrators
#   S-1-5-32-545  Users  (covers Entra-joined user accounts via local group membership)
#   S-1-5-32-551  Backup Operators
#   Guest         Local Guest account
$DesiredInteractiveLogonRight = 'Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551'

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}

# ── Main ──────────────────────────────────────────────────────────────────────
try {
    if (-not (Test-Path -Path $TempPath)) {
        New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
    }

    # Clear stale working files from any previous run
    foreach ($file in $ExportPath, $ImportPath, $VerifyPath, $DbPath, $LogPath) {
        if (Test-Path -Path $file) {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log 'Starting local security policy remediation.'

    # ── Export current policy ──────────────────────────────────────────────────
    Write-Log 'Exporting current local security policy...'
    secedit /export /cfg $ExportPath | Out-Null

    if (-not (Test-Path -Path $ExportPath)) {
        throw 'Security policy export failed. Export file was not created.'
    }

    $content = Get-Content -Path $ExportPath -Encoding Unicode

    # ── Patch the relevant rights ──────────────────────────────────────────────
    $foundInteractive = $false
    $foundDeny        = $false

    $updatedContent = foreach ($line in $content) {
        if ($line -match '^SeInteractiveLogonRight\s*=') {
            $foundInteractive = $true
            Write-Log ('Replacing SeInteractiveLogonRight. Was: {0}' -f $line.Trim())
            'SeInteractiveLogonRight = ' + $DesiredInteractiveLogonRight
        }
        elseif ($line -match '^SeDenyInteractiveLogonRight\s*=') {
            $foundDeny = $true
            Write-Log ('Clearing SeDenyInteractiveLogonRight. Was: {0}' -f $line.Trim())
            'SeDenyInteractiveLogonRight ='
        }
        else {
            $line
        }
    }

    if (-not $foundInteractive) {
        Write-Log 'SeInteractiveLogonRight was not present in export. Adding it.' 'WARN'
        $updatedContent += 'SeInteractiveLogonRight = ' + $DesiredInteractiveLogonRight
    }

    if (-not $foundDeny) {
        Write-Log 'SeDenyInteractiveLogonRight was not present. Nothing to clear.'
    }

    # ── Re-import scoped to USER_RIGHTS only ──────────────────────────────────
    Write-Log 'Writing modified policy file...'
    Set-Content -Path $ImportPath -Value $updatedContent -Encoding Unicode

    Write-Log 'Importing updated USER_RIGHTS policy...'
    secedit /configure /db $DbPath /cfg $ImportPath /areas USER_RIGHTS | Out-Null

    # ── Verify the changes took effect ────────────────────────────────────────
    Write-Log 'Verifying applied policy...'
    secedit /export /cfg $VerifyPath | Out-Null

    if (-not (Test-Path -Path $VerifyPath)) {
        Write-Log 'Verification export failed. Please confirm policy manually in secpol.msc.' 'WARN'
    }
    else {
        $verifyContent = Get-Content -Path $VerifyPath -Encoding Unicode

        $interactiveLine = $verifyContent | Where-Object { $_ -match '^SeInteractiveLogonRight\s*=' }
        $denyLine        = $verifyContent | Where-Object { $_ -match '^SeDenyInteractiveLogonRight\s*=' }

        if ($interactiveLine) {
            $interactiveValue = ($interactiveLine -split '=', 2)[1].Trim()
            if ($interactiveValue -eq $DesiredInteractiveLogonRight) {
                Write-Log 'SeInteractiveLogonRight verified successfully.'
            }
            else {
                Write-Log ('SeInteractiveLogonRight mismatch after import. Expected: [{0}] Got: [{1}]' -f $DesiredInteractiveLogonRight, $interactiveValue) 'WARN'
            }
        }
        else {
            Write-Log 'SeInteractiveLogonRight not found in verification export.' 'WARN'
        }

        if ($denyLine) {
            $denyValue = ($denyLine -split '=', 2)[1].Trim()
            if ([string]::IsNullOrWhiteSpace($denyValue)) {
                Write-Log 'SeDenyInteractiveLogonRight verified as empty.'
            }
            else {
                Write-Log ('SeDenyInteractiveLogonRight still contains entries after import: [{0}]' -f $denyValue) 'WARN'
            }
        }
        else {
            Write-Log 'SeDenyInteractiveLogonRight not present in verification export (treated as clear).'
        }
    }

    # ── Force computer policy refresh ─────────────────────────────────────────
    Write-Log 'Refreshing computer group policy...'
    $gpOutput = & gpupdate /target:computer /force 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log ('gpupdate exited with code {0}. Output: {1}' -f $LASTEXITCODE, ($gpOutput -join ' ')) 'WARN'
    }
    else {
        Write-Log 'Group policy refresh completed successfully.'
    }

    Write-Log 'Done. A reboot is recommended before testing Entra user sign-in.'
}
catch {
    Write-Log ('FATAL: {0}' -f $_.Exception.Message) 'ERROR'
    Write-Error $_.Exception.Message
    exit 1
}
