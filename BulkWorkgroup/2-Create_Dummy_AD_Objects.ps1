<#
.SYNOPSIS
    Creates dummy AD computer objects from a CSV into Computers container by default, or an OU if specified.

.DESCRIPTION
    Reads computer_name values from a CSV and creates computer objects in Active Directory.

    Target location:
      - If -TargetOU is NOT specified, objects are created in:
          CN=Computers,<domainDN>

      - If -TargetOU IS specified, objects are created in that OU:
          OU=...,DC=...
        If -CreateOuPath is set, missing OUs in the path are created.

.PARAMETER CsvPath
    Path to CSV containing a computer_name column.

.PARAMETER TargetOU
    Optional distinguished name of the target OU. Example:
      "OU=Workgroup Staging,OU=Computers,DC=contoso,DC=com"

.PARAMETER CreateOuPath
    If set and -TargetOU is used, create the OU path if it does not exist.

.PARAMETER DomainController
    Optional domain controller to use for all AD operations.

.NOTES
    PowerShell 5.1 compatible. ASCII-only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file")]
    [string]$CsvPath,

    [Parameter(Mandatory = $false, HelpMessage = "Optional OU DN. If omitted, uses default CN=Computers container.")]
    [string]$TargetOU,

    [Parameter(Mandatory = $false)]
    [switch]$CreateOuPath,

    [Parameter(Mandatory = $false)]
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

function Get-DomainDistinguishedName {
    param([string]$DomainController)

    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        return (Get-ADDomain).DistinguishedName
    } else {
        return (Get-ADDomain -Server $DomainController).DistinguishedName
    }
}

function Get-DefaultComputersContainerDn {
    param([string]$DomainController)

    $domainDn = Get-DomainDistinguishedName -DomainController $DomainController
    return ("CN=Computers," + $domainDn)
}

function Test-AdObjectExistsByDn {
    param(
        [Parameter(Mandatory=$true)][string]$DistinguishedName,
        [string]$DomainController
    )

    try {
        if ([string]::IsNullOrWhiteSpace($DomainController)) {
            $null = Get-ADObject -Identity $DistinguishedName -ErrorAction Stop
        } else {
            $null = Get-ADObject -Server $DomainController -Identity $DistinguishedName -ErrorAction Stop
        }
        return $true
    } catch {
        return $false
    }
}

function Ensure-OrganizationalUnitPath {
    param(
        [Parameter(Mandatory=$true)][string]$OuDistinguishedName,
        [Parameter(Mandatory=$true)][bool]$Create,
        [string]$DomainController
    )

    if (Test-AdObjectExistsByDn -DistinguishedName $OuDistinguishedName -DomainController $DomainController) {
        Write-Info ("OU exists: " + $OuDistinguishedName)
        return
    }

    if (-not $Create) {
        throw ("Target OU does not exist: " + $OuDistinguishedName + ". Use -CreateOuPath to create it.")
    }

    $domainDn = Get-DomainDistinguishedName -DomainController $DomainController

    $parts = $OuDistinguishedName -split ","
    $ouParts = @()
    foreach ($p in $parts) {
        if ($p -like "OU=*") { $ouParts += $p }
    }

    if ($ouParts.Count -eq 0) {
        throw ("TargetOU does not appear to be an OU DN: " + $OuDistinguishedName)
    }

    # Create from top-most OU down to leaf OU
    [array]::Reverse($ouParts)

    $parentPath = $domainDn
    foreach ($ouRdn in $ouParts) {
        $ouName = $ouRdn.Substring(3)  # strip "OU="
        $currentDn = ("OU=" + $ouName + "," + $parentPath)

        if (-not (Test-AdObjectExistsByDn -DistinguishedName $currentDn -DomainController $DomainController)) {
            Write-Info ("Creating OU: " + $currentDn)
            if ([string]::IsNullOrWhiteSpace($DomainController)) {
                New-ADOrganizationalUnit -Name $ouName -Path $parentPath -ErrorAction Stop | Out-Null
            } else {
                New-ADOrganizationalUnit -Server $DomainController -Name $ouName -Path $parentPath -ErrorAction Stop | Out-Null
            }
        } else {
            Write-Info ("OU already present: " + $currentDn)
        }

        $parentPath = $currentDn
    }

    if (-not (Test-AdObjectExistsByDn -DistinguishedName $OuDistinguishedName -DomainController $DomainController)) {
        throw ("Failed to create/verify target OU: " + $OuDistinguishedName)
    }
}

function Import-ComputerNamesFromCsv {
    param([Parameter(Mandatory=$true)][string]$CsvPath)

    $data = Import-Csv -LiteralPath $CsvPath
    if ($null -eq $data -or $data.Count -eq 0) {
        throw ("CSV is empty: " + $CsvPath)
    }

    $headers = $data[0].PSObject.Properties.Name
    if ($headers -notcontains "computer_name") {
        throw "CSV is missing required header: computer_name"
    }

    $names = @()
    foreach ($row in $data) {
        $n = $row.computer_name
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $names += $n.Trim()
    }

    return $names
}

function New-DummyComputerIfMissing {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][string]$TargetPathDn,
        [string]$DomainController
    )

    $escaped = $ComputerName.Replace("'","''")
    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        $existing = Get-ADComputer -Filter ("Name -eq '" + $escaped + "'") -ErrorAction SilentlyContinue
    } else {
        $existing = Get-ADComputer -Server $DomainController -Filter ("Name -eq '" + $escaped + "'") -ErrorAction SilentlyContinue
    }

    if ($null -ne $existing) {
        if (@($existing).Count -gt 1) {
            Write-Warn ("Computer '" + $ComputerName + "' already exists multiple times. First DN: " + @($existing)[0].DistinguishedName)
        } else {
            Write-Warn ("Computer '" + $ComputerName + "' already exists. DN: " + $existing.DistinguishedName)
        }
        return $false
    }

    Write-Info ("Creating computer '" + $ComputerName + "' in '" + $TargetPathDn + "'")
    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        New-ADComputer -Name $ComputerName -Path $TargetPathDn -Enabled $true -ErrorAction Stop | Out-Null
    } else {
        New-ADComputer -Server $DomainController -Name $ComputerName -Path $TargetPathDn -Enabled $true -ErrorAction Stop | Out-Null
    }

    return $true
}

# -----------------------
# MAIN
# -----------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop

    Assert-FileExists -Path $CsvPath -FriendlyName "CSV file"

    # Determine the target path DN.
    # Default: CN=Computers,<domainDN>
    # If TargetOU provided: use OU DN (optionally create it).
    $targetPathDn = $null

    if ([string]::IsNullOrWhiteSpace($TargetOU)) {
        $targetPathDn = Get-DefaultComputersContainerDn -DomainController $DomainController

        if (-not (Test-AdObjectExistsByDn -DistinguishedName $targetPathDn -DomainController $DomainController)) {
            throw ("Default Computers container was not found: " + $targetPathDn)
        }

        Write-Info ("Target path (default Computers container): " + $targetPathDn)
    } else {
        Ensure-OrganizationalUnitPath -OuDistinguishedName $TargetOU -Create ([bool]$CreateOuPath) -DomainController $DomainController
        $targetPathDn = $TargetOU
        Write-Info ("Target path (OU): " + $targetPathDn)
    }

    $computerNames = Import-ComputerNamesFromCsv -CsvPath $CsvPath
    if ($computerNames.Count -eq 0) {
        throw "No computer_name values found in CSV."
    }

    $created = 0
    $skipped = 0

    foreach ($name in $computerNames) {
        if ($name.Length -gt 15) {
            Write-Warn ("Computer name longer than 15 characters: " + $name)
        }

        $didCreate = New-DummyComputerIfMissing -ComputerName $name -TargetPathDn $targetPathDn -DomainController $DomainController
        if ($didCreate) { $created++ } else { $skipped++ }
    }

    Write-Info ("Completed. Created: " + $created + ", Skipped (already existed): " + $skipped)
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
