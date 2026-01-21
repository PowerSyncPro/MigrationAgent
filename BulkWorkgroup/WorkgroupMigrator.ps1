#Requires -RunAsAdministrator
<#
.DESCRIPTION
    PowerSyncPro Workgroup Kickoff Script (1:1 user migration)

    - Designed for WORKGROUP machines only (not domain-joined).
    - Supports a single 1-to-1 mapping: one local workgroup user to one target user.
    - Creates a SID translation table file and places it in each Runbook folder.
    - Stamps required registry values and restarts the Migration Agent service
      to force a refresh of runbook data.

    Execution model
    - Intended to be run by an RMM as SYSTEM or elevated admin.
    - The RMM typically pushes:
        * This script
        * The migration CSV (mig_db.csv)
        * The PowerSyncPro Migration Agent MSI
      into the same directory (BasePath) and runs the script once.

    CSV requirements
    Required headers:
      computer_name, local_username, target_upn, target_identity

    Interpretation of target_identity depends on TargetIdentityType:
      - Entra: target_identity must be a GUID ObjectId (converted to SID)
      - AD:    target_identity must be a SID string (used directly)

.NOTES
    Date        January/2026
    Disclaimer  This script is provided 'AS IS'. No warranty is provided either expressed or implied.
                Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version     0.1
    Updated     Initial Release - JRR
    Copyright   (c) 2026 Declaration Software
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------
# CONFIGURATION
# -----------------------

# Base working directory.
# The RMM is expected to drop:
#   - mig_db.csv
#   - PSPMigrationAgentInstaller.msi
#   - this .ps1
# into this folder prior to execution.
$BasePath     = "C:\Temp"
$CsvName      = "mig_db_entra.csv"
$PspMsiName   = "PSPMigrationAgentInstaller.msi"

# DomainName is written to the agent registry key as part of kickoff.
# For workgroup migrations, this value is likely the dummy domain which contains an AD object for the workstation
$DomainName   = "dummy.local"

# RunbookGUIDs represent one or more runbook folders under:
#   C:\ProgramData\Declaration Software\Migration Agent\<GUID>\
# The translation table is copied into each GUID folder.  See KB to determine how to retrieve this from the web interface.
$RunbookGUIDs = @("d73976d7-d004-425f-8163-08de576995ae")

# Windows service name (not display name) for the PowerSyncPro Migration Agent.
$ServiceName  = "PowerSyncPro Migration Agent"

# Server URL and PSK are used only if the agent must be installed.
$PspServerUrl = "<PSP Server URL> (inc. /Agent)"
$PspPsk       = "<PSK from Server>"

# Target identity type:
#   - Entra: target_identity in CSV is a GUID ObjectId; script converts it to an S-1-12-1-* SID
#   - AD:    target_identity in CSV is already a SID string; script validates it and uses it directly
$TargetIdentityType = "Entra"  # Entra | AD

# Transcript logging output location.
$TranscriptName = "Migration_Kickoff_Log"
$TranscriptPath = Join-Path -Path $BasePath -ChildPath ($TranscriptName + ".log")

# Fixed locations used by the agent.
$RegKey           = "HKLM:\SOFTWARE\Declaration Software\Migration Agent"
$MaDataDirectory  = "C:\ProgramData\Declaration Software\Migration Agent"
$RunbooksFileName = "Runbooks.json"

# Translation table file created by this script.
$TranslationFileName = "TranslationTable.json"
$TranslationJsonPath = Join-Path -Path $BasePath -ChildPath $TranslationFileName

# MSI install log (only written if installation occurs).
$MsiInstallLogPath = Join-Path -Path $BasePath -ChildPath "PSPAgent_Install.log"

# ASCII logo shown at runtime for quick operator confirmation.
$asciiLogo=@"
 ____                        ____                   ____
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/
                                   |___/
"@

# -----------------------
# HELPER FUNCTIONS
# -----------------------

function Write-Info {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[INFO] " + $Message)
}

function Write-Warn {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Warning $Message
}

function Assert-FileExists {
<#
.SYNOPSIS
    Validates that a file exists at a given path.

.DESCRIPTION
    Throws a terminating error if the path does not exist.
    This is used as a "fail fast" check before operations that require the file.

.PARAMETER Path
    The full file path to validate.

.PARAMETER FriendlyName
    Friendly description of the file for error messages (example: "Migration CSV").

.EXAMPLE
    Assert-FileExists -Path "C:\Temp\mig_db.csv" -FriendlyName "Migration CSV"
#>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$FriendlyName
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw ($FriendlyName + " was not found: " + $Path)
    }
}

function Assert-WorkgroupOnly {
<#
.SYNOPSIS
    Hard guardrail: ensures the machine is not domain joined.

.DESCRIPTION
    This script is intended exclusively for workgroup machines. If the machine is
    domain-joined, the script throws and stops immediately.

    Uses Win32_ComputerSystem.PartOfDomain for determination.

.NOTES
    - This is a business/process requirement (not a technical limitation).
    - If you ever need to support domain-joined, remove/modify this function.
#>
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        throw ("This script is for WORKGROUP machines only. This machine is domain-joined (Domain: " + $cs.Domain + "). Aborting.")
    }
}

function Get-MigrationRowFromCsv {
<#
.SYNOPSIS
    Loads mig_db.csv and returns the row matching the current computer name.

.DESCRIPTION
    - Imports the CSV.
    - Validates required headers exist:
        computer_name, local_username, target_upn, target_identity
    - Performs a case-insensitive match against computer_name.
    - If multiple rows match, warns and uses the first.

.PARAMETER CsvPath
    Path to the CSV file.

.PARAMETER ComputerName
    The local hostname to match against the computer_name column.

.OUTPUTS
    PSCustomObject representing a single CSV row.

.NOTES
    - Throws if CSV is empty, missing headers, or no matching row is found.
#>
    param(
        [Parameter(Mandatory=$true)][string]$CsvPath,
        [Parameter(Mandatory=$true)][string]$ComputerName
    )

    $data = Import-Csv -LiteralPath $CsvPath
    if ($null -eq $data -or $data.Count -eq 0) {
        throw ("CSV is empty: " + $CsvPath)
    }

    # Required schema.
    # target_upn is required even if not used directly by this script.
    # Some support tooling uses UPN to resolve the Entra ObjectId through Graph.
    $requiredHeaders = @("computer_name","local_username","target_upn","target_identity")
    $headers = $data[0].PSObject.Properties.Name

    $missing = @()
    foreach ($h in $requiredHeaders) {
        if ($headers -notcontains $h) { $missing += $h }
    }
    if ($missing.Count -gt 0) {
        throw ("CSV is missing required headers: " + ($missing -join ", ") + ". Expected: " + ($requiredHeaders -join ", "))
    }

    # Match the current device row by hostname.
    $matches = @($data | Where-Object { $_.computer_name -ieq $ComputerName })

    if ($matches.Count -eq 0) {
        throw ("This computer '" + $ComputerName + "' was not found in CSV '" + $CsvPath + "'. Aborting.")
    }

    if ($matches.Count -gt 1) {
        Write-Warn ("Multiple rows matched computer_name '" + $ComputerName + "'. Using the first match.")
    }

    return $matches[0]
}

function Get-LocalUserSid {
<#
.SYNOPSIS
    Returns the SID for a local (workgroup) user account by username.

.DESCRIPTION
    Uses Win32_UserAccount with a filter:
      LocalAccount=True AND Name='<username>'

    This avoids partial matches and avoids returning domain accounts.

.PARAMETER LocalUserName
    The local username to look up (example: "bob").

.OUTPUTS
    String SID (example: "S-1-5-21-...").

.NOTES
    - Throws if the local account is not found.
    - Warns and returns the first result if multiple results are found (unexpected).
#>
    param([Parameter(Mandatory=$true)][string]$LocalUserName)

    # Escape single quotes so the WMI filter string remains valid.
    $escaped = $LocalUserName.Replace("'", "''")
    $acct = Get-CimInstance Win32_UserAccount -Filter ("LocalAccount=True AND Name='" + $escaped + "'")

    if ($null -eq $acct) {
        throw ("Local workgroup account '" + $LocalUserName + "' not found (LocalAccount=True). Aborting.")
    }

    if (@($acct).Count -gt 1) {
        Write-Warn ("Multiple local accounts matched '" + $LocalUserName + "'. Using the first.")
        $acct = @($acct)[0]
    }

    return $acct.SID
}

function Assert-SidFormat {
<#
.SYNOPSIS
    Validates that a string is a valid Windows SID.

.DESCRIPTION
    Attempts to construct a System.Security.Principal.SecurityIdentifier.
    If construction fails, the SID string is invalid and the function throws.

.PARAMETER Sid
    SID string to validate (example: "S-1-5-21-...").

.NOTES
    - This validates format and basic SID correctness.
    - It does not validate that the SID exists on the system.
#>
    param([Parameter(Mandatory=$true)][string]$Sid)
    try {
        $null = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    } catch {
        throw ("Invalid SID format: '" + $Sid + "'")
    }
}

function Convert-EntraObjectIdToSid {
<#
.SYNOPSIS
    Converts an Entra ID objectId (GUID) into its corresponding SID format.

.DESCRIPTION
    Entra object IDs are GUIDs. Windows represents these cloud identities as
    SIDs in the form:

      S-1-12-1-<UInt32>-<UInt32>-<UInt32>-<UInt32>

    This function:
      - Validates the input is a GUID
      - Converts GUID -> byte array
      - Interprets bytes as four UInt32 values
      - Constructs the S-1-12-1-* SID string

.PARAMETER ObjectId
    Entra user objectId as a GUID string.

.OUTPUTS
    String SID in the S-1-12-1-* form.

.NOTES
    - Throws if ObjectId is not a valid GUID.
#>
    param([Parameter(Mandatory=$true)][string]$ObjectId)

    if ([string]::IsNullOrWhiteSpace($ObjectId)) {
        throw "target_identity is blank. In Entra mode, target_identity must contain the user's GUID ObjectId."
    }

    $s = $ObjectId.Trim()

    # Optional: also accept 32-hex "N" format just in case
    if ($s -match '^[0-9a-fA-F]{32}$') {
        $s = $s.Substring(0,8)  + "-" +
             $s.Substring(8,4)  + "-" +
             $s.Substring(12,4) + "-" +
             $s.Substring(16,4) + "-" +
             $s.Substring(20,12)
    }

    # IMPORTANT: PS 5.1 requires the out/ref target to be a Guid, not $null
    $guid = [Guid]::Empty

    if (-not [Guid]::TryParse($s, [ref]$guid)) {
        throw ("target_identity is not a valid GUID ObjectId: '" + $ObjectId + "'")
    }

    $guidBytes = $guid.ToByteArray()
    $uintArray = New-Object 'UInt32[]' 4
    [Buffer]::BlockCopy($guidBytes, 0, $uintArray, 0, 16)

    return ("S-1-12-1-" + $uintArray[0] + "-" + $uintArray[1] + "-" + $uintArray[2] + "-" + $uintArray[3])
}


function Write-Utf8NoBomFile {
<#
.SYNOPSIS
    Writes text content to disk using UTF-8 encoding without a BOM.

.DESCRIPTION
    Uses .NET APIs to write the file as UTF-8 without a Byte Order Mark (BOM).
    This is often more compatible with parsers that treat a BOM as file content.

.PARAMETER Path
    Destination file path.

.PARAMETER Content
    Text content to write.

.NOTES
    - Overwrites the file if it exists.
    - UTF-8 without BOM is used intentionally.
#>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Ensure-PspAgentInstalled {
<#
.SYNOPSIS
    Ensures the PowerSyncPro Migration Agent service exists, installing if necessary.

.DESCRIPTION
    - Checks for the existence of the service by name.
    - If missing:
        * Validates MSI exists
        * Runs msiexec with PSK and URL parameters
        * Logs install output to a file
        * Treats exit code 0 as success and 3010 as success (reboot required)
        * Waits up to 60 seconds for the service to appear after install

.PARAMETER ServiceName
    The Windows service name to check.

.PARAMETER MsiPath
    Full path to the MSI installer.

.PARAMETER PspServerUrl
    Agent endpoint URL passed to MSI.

.PARAMETER PspPsk
    PSK passed to MSI.

.PARAMETER InstallLogPath
    MSI log file path.

.NOTES
    - This function does not verify the service is "Running"; only that it exists.
    - Throwing here indicates install failure or missing service after install.
#>
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][string]$MsiPath,
        [Parameter(Mandatory=$true)][string]$PspServerUrl,
        [Parameter(Mandatory=$true)][string]$PspPsk,
        [Parameter(Mandatory=$true)][string]$InstallLogPath
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        Write-Info ("Service '" + $ServiceName + "' exists. Status: " + $svc.Status)
        return
    }

    Write-Info ("Service '" + $ServiceName + "' not found. Installing PSP Migration Agent...")
    Assert-FileExists -Path $MsiPath -FriendlyName "PSP MSI"

    $args = @(
        "/i", ('"' + $MsiPath + '"'),
        ("PSK=" + $PspPsk),
        ("URL=" + $PspServerUrl),
        "/qn",
        "/l*v", ('"' + $InstallLogPath + '"')
    )

    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    Write-Info ("MSI install exit code: " + $p.ExitCode)

    # 3010 is a common MSI success code indicating a reboot is required to complete.
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw ("PSP Migration Agent install failed (msiexec exit code " + $p.ExitCode + "). See " + $InstallLogPath)
    }

    # MSI completion does not always mean the service is registered instantly.
    # Poll for the service for up to 60 seconds to avoid race conditions.
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } while ($null -eq $svc -and (Get-Date) -lt $deadline)

    if ($null -eq $svc) {
        throw ("Service '" + $ServiceName + "' still not present after installation. Verify MSI install.")
    }

    Write-Info ("Service '" + $ServiceName + "' is present. Status: " + $svc.Status)
}

function Apply-TranslationAndRestartAgent {
<#
.SYNOPSIS
    Applies translation/registry settings and restarts the agent to force a refresh.

.DESCRIPTION
    This function performs the "kickoff" steps expected by the Migration Agent:

    1) Validate translation file exists.
    2) Stop the Migration Agent service.
    3) Ensure the agent registry key exists.
    4) Write DomainName and ComputerName into the agent registry key.
    5) Copy TranslationTable.json into each runbook GUID folder.
    6) Remove Runbooks.json to force the agent to rebuild/refresh on next start.
    7) Start the service and wait until it is Running.

.PARAMETER ServiceName
    Migration Agent Windows service name.

.PARAMETER RegKey
    Registry key path where agent settings are stored.

.PARAMETER DomainName
    Value written to the agent registry key.

.PARAMETER ComputerName
    Value written to the agent registry key.

.PARAMETER MaDataDirectory
    Agent data directory (ProgramData path).

.PARAMETER RunbookGUIDs
    List of runbook GUIDs to copy translation table into.

.PARAMETER TranslationJsonPath
    Full path to TranslationTable.json.

.PARAMETER RunbooksFileName
    Filename under MaDataDirectory to remove (Runbooks.json).

.NOTES
    - Stopping the service avoids races where the agent reads files while they are being updated.
    - Removing Runbooks.json is an intentional "force refresh" behavior.
#>
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][string]$RegKey,
        [Parameter(Mandatory=$true)][string]$DomainName,
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][string]$MaDataDirectory,
        [Parameter(Mandatory=$true)][string[]]$RunbookGUIDs,
        [Parameter(Mandatory=$true)][string]$TranslationJsonPath,
        [Parameter(Mandatory=$true)][string]$RunbooksFileName
    )

    Assert-FileExists -Path $TranslationJsonPath -FriendlyName "Translation table JSON"

    Write-Info ("Stopping service '" + $ServiceName + "'...")
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { throw ("Service '" + $ServiceName + "' not found.") }

    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus("Stopped","00:00:30")
    }

    # Ensure registry key exists before writing values.
    if (-not (Test-Path -LiteralPath $RegKey)) {
        Write-Info ("Registry key not found, creating: " + $RegKey)
        New-Item -Path $RegKey -Force | Out-Null
    }

    # Stamp values used by the agent to understand current device context.
    Write-Info ("Setting registry values DomainName='" + $DomainName + "', ComputerName='" + $ComputerName + "'")
    Set-ItemProperty -Path $RegKey -Name "DomainName"   -Value $DomainName
    Set-ItemProperty -Path $RegKey -Name "ComputerName" -Value $ComputerName

    # Copy translation table into each Runbook GUID folder.
    # The agent reads these files when processing the runbook.
    foreach ($guid in $RunbookGUIDs) {
        $targetFolder = Join-Path -Path $MaDataDirectory -ChildPath $guid

        if (-not (Test-Path -LiteralPath $targetFolder)) {
            Write-Info ("Creating runbook folder: " + $targetFolder)
            New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        }

        $dest = Join-Path -Path $targetFolder -ChildPath ([IO.Path]::GetFileName($TranslationJsonPath))
        Write-Info ("Copying translation table to: " + $dest)
        Copy-Item -LiteralPath $TranslationJsonPath -Destination $dest -Force
    }

    # Removing Runbooks.json forces the agent to refresh runbook state on startup.
    $runbookFilePath = Join-Path -Path $MaDataDirectory -ChildPath $RunbooksFileName
    if (Test-Path -LiteralPath $runbookFilePath) {
        Write-Info ("Removing: " + $runbookFilePath)
        Remove-Item -LiteralPath $runbookFilePath -Force
    } else {
        Write-Info ("Runbooks file not present (ok): " + $runbookFilePath)
    }

    # Restart the service and confirm it transitions to Running.
    Write-Info ("Starting service '" + $ServiceName + "'...")
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus("Running","00:00:30")
    Write-Info "Service is running."
}

# -----------------------
# MAIN
# -----------------------
# Main execution is intentionally linear and "fail-fast":
#   1) Ensure required folders/files exist.
#   2) Confirm this is a workgroup machine.
#   3) Load migration inputs from CSV for THIS computer.
#   4) Resolve local user SID and target SID (AD or Entra).
#   5) Write translation table JSON to BasePath.
#   6) Ensure agent is installed (install from MSI if missing).
#   7) Apply translation file + registry settings and restart agent.

try {
    # Ensure BasePath exists.
    # Some RMM tools create it automatically, but do not rely on that.
    if (-not (Test-Path -LiteralPath $BasePath)) {
        New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
    }

    # Start transcript early so any failures are captured in the log file.
    Start-Transcript -Append -LiteralPath $TranscriptPath | Out-Null
    Write-Info ("Transcript: " + $TranscriptPath)

    # Guardrail: do not allow execution on domain-joined machines.
    # This is a strict requirement for this workflow.
    Assert-WorkgroupOnly

    # Display the ASCII logo so it is obvious in RMM output what script ran.
    Write-Host $asciiLogo

    # Identify the local computer and announce configuration mode.
    $computerName = $env:COMPUTERNAME
    Write-Info ("ComputerName: " + $computerName)
    Write-Info ("TargetIdentityType: " + $TargetIdentityType)

    # Build and validate the CSV path.
    # The CSV is the "database" that maps this computer to a local user and target identity.
    $csvPath = Join-Path -Path $BasePath -ChildPath $CsvName
    Assert-FileExists -Path $csvPath -FriendlyName "Migration CSV"

    # Build MSI path (used only if agent installation is needed).
    $msiPath = Join-Path -Path $BasePath -ChildPath $PspMsiName

    # Load the matching row for THIS computer name from the CSV.
    # The CSV entry defines:
    #   - local_username: the local workgroup user currently on the machine
    #   - target_upn:     required support field (used by other tooling)
    #   - target_identity: SID or Entra ObjectId depending on TargetIdentityType
    $row = Get-MigrationRowFromCsv -CsvPath $csvPath -ComputerName $computerName

    # Extract local username (source identity on the workgroup PC).
    $localUserName = $row.local_username
    if ([string]::IsNullOrWhiteSpace($localUserName)) {
        throw ("CSV local_username is blank for computer '" + $computerName + "'.")
    }

    # target_upn is required by schema even if this script does not use it directly.
    # This preserves compatibility with support tooling that resolves Entra identities via Graph.
    $targetUpn = $row.target_upn
    if ([string]::IsNullOrWhiteSpace($targetUpn)) {
        throw ("CSV target_upn is blank for computer '" + $computerName + "'.")
    }
    Write-Info ("Target UPN: " + $targetUpn)

    # target_identity is the key value this script uses to build a translation.
    # For Entra mode, it is expected to be a GUID ObjectId.
    # For AD mode, it is expected to be a SID string.
    $targetIdentity = $row.target_identity
    if ([string]::IsNullOrWhiteSpace($targetIdentity)) {
        throw ("CSV target_identity is blank for computer '" + $computerName + "'.")
    }

    # Resolve the source SID for the local workgroup account.
    # This SID is the "from" side of the translation mapping.
    $localSid = Get-LocalUserSid -LocalUserName $localUserName
    Assert-SidFormat -Sid $localSid
    Write-Info ("Local user '" + $localUserName + "' SID: " + $localSid)

    # Resolve the target SID depending on mode selection.
    # This SID is the "to" side of the translation mapping.
    $targetSid = $null
    if ($TargetIdentityType -eq "Entra") {
        # Convert the Entra ObjectId GUID into an S-1-12-1-* SID representation.
        $targetSid = Convert-EntraObjectIdToSid -ObjectId $targetIdentity
        Assert-SidFormat -Sid $targetSid
        Write-Info ("Entra ObjectId '" + $targetIdentity + "' converted to target SID: " + $targetSid)
    }
    elseif ($TargetIdentityType -eq "AD") {
        # CSV already contains a SID string for AD targets; validate and use directly.
        $targetSid = $targetIdentity
        Assert-SidFormat -Sid $targetSid
        Write-Info ("AD target SID: " + $targetSid)
    }
    else {
        # Defensive: only Entra and AD are valid values for TargetIdentityType.
        throw ("Invalid TargetIdentityType value: '" + $TargetIdentityType + "'. Use 'Entra' or 'AD'.")
    }

    # Create the translation table JSON expected by the agent.
    # Format: {"<sourceSid>":"<targetSid>"}
    $translationJson = '{"' + $localSid + '":"' + $targetSid + '"}'

    # Write the translation table to a deterministic location (BasePath).
    # This avoids working-directory differences under various RMM execution contexts.
    Write-Utf8NoBomFile -Path $TranslationJsonPath -Content $translationJson
    Write-Info ("Translation table written: " + $TranslationJsonPath)
    Write-Info ("Translation JSON: " + $translationJson)

    # Ensure the agent exists.
    # If the service does not exist, install the MSI using the configured URL and PSK.
    Ensure-PspAgentInstalled `
        -ServiceName $ServiceName `
        -MsiPath $msiPath `
        -PspServerUrl $PspServerUrl `
        -PspPsk $PspPsk `
        -InstallLogPath $MsiInstallLogPath

    # Apply translation/registry values and restart the agent.
    # This forces the agent to refresh runbook state and pick up the new translation file.
    Apply-TranslationAndRestartAgent `
        -ServiceName $ServiceName `
        -RegKey $RegKey `
        -DomainName $DomainName `
        -ComputerName $computerName `
        -MaDataDirectory $MaDataDirectory `
        -RunbookGUIDs $RunbookGUIDs `
        -TranslationJsonPath $TranslationJsonPath `
        -RunbooksFileName $RunbooksFileName

    Write-Info "Migration kickoff completed successfully."
    exit 0
}
catch {
    # Any uncaught error results in a non-zero exit code for the RMM.
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    # Stop transcript if it was started. Ignore errors to avoid masking root causes.
    try { Stop-Transcript | Out-Null } catch { }
}
