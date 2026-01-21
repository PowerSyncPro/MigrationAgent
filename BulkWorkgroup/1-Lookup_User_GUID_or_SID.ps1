<#
.SYNOPSIS
    Populate target_identity in a migration CSV from Entra (Graph) or AD.

.DESCRIPTION
    This script helps an admin populate the initial migration CSV.

    CSV schema (required headers):
      computer_name, local_username, target_upn, target_identity

    Modes:
      -TargetType Entra
         Uses Microsoft Graph to resolve target_upn to the user's ObjectId (GUID),
         writes that GUID to target_identity.

      -TargetType AD
         Uses Active Directory to resolve target_upn (or samAccountName) to the
         user's SID, writes that SID string to target_identity.

    Behavior:
      - By default, the script FAILS (exit 1) and does not update the CSV if any
        target_upn cannot be resolved.
      - Use -AllowPartial to write what can be resolved and leave unresolved rows as-is.

.NOTES
    PowerShell 5.1 compatible. ASCII-only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file")]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Entra","AD")]
    [string]$TargetType,

    # If set, the script will update rows it can resolve and will not abort on missing identities.
    [switch]$AllowPartial,

    # Optional: for AD mode, force a specific domain controller.
    [string]$DomainController
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[INFO ] " + $Message)
}

function Write-Warn {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Warning $Message
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$FriendlyName
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw ($FriendlyName + " does not exist: " + $Path)
    }
}

function Assert-CsvSchema {
    param(
        [Parameter(Mandatory=$true)][object[]]$CsvData
    )

    if ($null -eq $CsvData -or $CsvData.Count -eq 0) {
        throw "CSV is empty."
    }

    $requiredHeaders = @("computer_name","local_username","target_upn","target_identity")
    $headers = $CsvData[0].PSObject.Properties.Name

    $missing = @()
    foreach ($h in $requiredHeaders) {
        if ($headers -notcontains $h) { $missing += $h }
    }

    if ($missing.Count -gt 0) {
        throw ("CSV is missing required headers: " + ($missing -join ", ") + ". Expected: " + ($requiredHeaders -join ", "))
    }
}

function Connect-EntraGraph {
    # Loads Graph Users module and connects with minimum required scope.
    Import-Module Microsoft.Graph.Users -ErrorAction Stop

    try {
        Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop | Out-Null
        Write-Info "Connected to Microsoft Graph."
    } catch {
        throw ("Failed to connect to Microsoft Graph: " + $_.Exception.Message)
    }
}

function Disconnect-EntraGraph {
    try {
        Disconnect-MgGraph | Out-Null
        Write-Info "Disconnected from Microsoft Graph."
    } catch {
        # Non-fatal
        Write-Warn "Disconnect-MgGraph failed or was not needed."
    }
}

function Resolve-EntraObjectIdFromUpn {
    param([Parameter(Mandatory=$true)][string]$Upn)

    # Get-MgUser -UserId accepts UPN.
    $user = Get-MgUser -UserId $Upn -ErrorAction Stop
    return $user.Id
}

function Ensure-ActiveDirectoryModule {
    # RSAT AD module is required for AD mode.
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Resolve-AdSidFromUpnOrSam {
    param(
        [Parameter(Mandatory=$true)][string]$Identity,
        [string]$DomainController
    )

    # Try UPN first, then fall back to samAccountName if needed.
    # Using -Identity will work for many forms. If it fails, try a filter.
    try {
        if ([string]::IsNullOrWhiteSpace($DomainController)) {
            $u = Get-ADUser -Identity $Identity -Properties ObjectSID -ErrorAction Stop
        } else {
            $u = Get-ADUser -Server $DomainController -Identity $Identity -Properties ObjectSID -ErrorAction Stop
        }
        return $u.ObjectSID.Value
    } catch {
        # Fallback: if Identity is an email/UPN and -Identity did not work in a given AD,
        # attempt filter by userPrincipalName.
        try {
            $escaped = $Identity.Replace("'", "''")
            $filter = "userPrincipalName -eq '$escaped'"

            if ([string]::IsNullOrWhiteSpace($DomainController)) {
                $u2 = Get-ADUser -Filter $filter -Properties ObjectSID -ErrorAction Stop
            } else {
                $u2 = Get-ADUser -Server $DomainController -Filter $filter -Properties ObjectSID -ErrorAction Stop
            }

            if ($null -eq $u2) { throw "No match." }
            if (@($u2).Count -gt 1) { throw "Multiple matches." }

            return $u2.ObjectSID.Value
        } catch {
            throw ("AD user not found for identity '" + $Identity + "'.")
        }
    }
}

# -----------------------
# MAIN
# -----------------------
$missing = @()

try {
    Assert-FileExists -Path $CsvPath -FriendlyName "CSV file"

    Write-Info ("Loading CSV: " + $CsvPath)
    $csvData = Import-Csv -LiteralPath $CsvPath
    Assert-CsvSchema -CsvData $csvData

    Write-Info ("TargetType: " + $TargetType)
    if ($AllowPartial) {
        Write-Info "AllowPartial: enabled (will write what can be resolved)."
    } else {
        Write-Info "AllowPartial: disabled (will abort if any identity cannot be resolved)."
    }

    # Connect to the appropriate directory based on mode
    if ($TargetType -eq "Entra") {
        Connect-EntraGraph
    } else {
        Ensure-ActiveDirectoryModule
        if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
            Write-Info ("Using DomainController: " + $DomainController)
        }
    }

    # Iterate rows and resolve target_identity from target_upn
    foreach ($row in $csvData) {
        $upn = $row.target_upn

        if ([string]::IsNullOrWhiteSpace($upn)) {
            Write-Warn ("Empty target_upn in row with computer_name: " + $row.computer_name)
            $missing += ("<blank target_upn> (computer_name=" + $row.computer_name + ")")
            continue
        }

        try {
            if ($TargetType -eq "Entra") {
                $id = Resolve-EntraObjectIdFromUpn -Upn $upn
                $row.target_identity = $id
                Write-Info ("Entra: " + $upn + " -> " + $id)
            } else {
                $sid = Resolve-AdSidFromUpnOrSam -Identity $upn -DomainController $DomainController
                $row.target_identity = $sid
                Write-Info ("AD: " + $upn + " -> " + $sid)
            }
        } catch {
            Write-Warn $_.Exception.Message
            $missing += $upn
        }
    }

    # If strict mode, abort without writing if anything was unresolved
    if (-not $AllowPartial -and $missing.Count -gt 0) {
        throw ("Unresolved identities found: " + ($missing -join ", ") + ". CSV was not updated.")
    }

    # Write results back to CSV
    Write-Info ("Writing updated CSV: " + $CsvPath)
    $csvData | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Force

    if ($missing.Count -gt 0) {
        Write-Warn ("Completed with unresolved identities (AllowPartial enabled). Missing: " + ($missing -join ", "))
        exit 2
    }

    Write-Info "CSV successfully updated."
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    if ($TargetType -eq "Entra") {
        Disconnect-EntraGraph
    }
}
