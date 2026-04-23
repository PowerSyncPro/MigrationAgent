<#
.SYNOPSIS
    Creates a PowerSyncPro Entra ID app registration with the appropriate permissions
    for your deployment scenario.

.DESCRIPTION
    This script automates the creation of a Microsoft Entra ID (Azure AD) app
    registration for use with PowerSyncPro. It supports four permission profiles
    covering Migration Agent and Directory Synchronisation scenarios for both source
    and target tenants.

    The script will:
      - Verify and install the required Microsoft.Graph PowerShell module
      - Authenticate to the target tenant via interactive browser login
      - Create the app registration with the correct API permissions
      - Grant admin consent for all application roles
      - Add the bulk enrolment (BPRT) delegated permission where required
      - Generate a client secret and apply a service principal lock
      - Output the Tenant ID, Application ID, and Client Secret

    Run this script once per tenant. Keep the output confidential - the client
    secret cannot be retrieved again after the session ends.

.PARAMETER TenantID
    The GUID of the tenant to create the app registration in.
    If not provided, the script will prompt for it.

.PARAMETER RedirectURI
    Redirect URL for PowerSyncPro authentication.
    Defaults to http://localhost:5000/redirect.
    Only change this if you are administering PSP from outside the local server.

.PARAMETER CloudEnvironment
    The Microsoft cloud environment the tenant belongs to.
    Valid values: Commercial, GCCHigh, DoD
    Defaults to Commercial. Specify GCCHigh or DoD for US Government tenants.

.PARAMETER PermissionSet
    The permission set to apply to the app registration.
    Valid values: MigrationAgentSource, MigrationAgentTarget, DirSyncRO, DirSyncHP
    If not provided, the script will interview you to determine the correct set.
    When provided, the script runs without prompts (headless mode).

    MigrationAgentSource - Read-only permissions for the source tenant during workstation migration.
    MigrationAgentTarget - Read-only permissions for the target tenant during workstation migration.
                           Includes delegated self_service_device_delete (BPRT).
    DirSyncRO            - Read-only permissions for directory sync (e.g. standard source tenant).
                           Includes Exchange.ManageAsApp.
    DirSyncHP            - Read/write permissions for directory sync (e.g. target tenant or
                           bidirectional source). Includes Exchange.ManageAsApp and BPRT.

.NOTES
    Date:       November 2024
    Disclaimer: This script is provided 'AS IS'. No warranty is provided either
                expressed or implied. Declaration Software Ltd cannot be held
                responsible for any misuse of the script.
    Version:    3.0
    Updated:    17th Feb 2025  - Added check for federated account.
    Updated:    19th May 2025  - Added Graph permission check to ensure correct
                                 placement in 'Configured permissions'.
    Updated:    19th June 2025 - Added ServicePrincipalLockConfiguration.
    Updated:    29th Sept 2025 - Updated BPRT language.
    Updated:    30th Sept 2025 - Fixed SyncFabric checks; added warning about
                                 not sharing tenant credentials with Support.
    Updated:    8th Oct 2025   - Fixed Graph module version check logic;
                                 added RedirectURI parameter handling.
    Updated:    March 2026     - Auth improvements (explicit ClientId, device code
                                 flow); fixed disconnect/reconnect logic; fixed
                                 permission scope check; removed PSGallery query
                                 on every run; lazy module loading; duplicate app
                                 check; messaging and UX cleanup; permission sets
                                 replaced with four granular sets: MigrationSource,
                                 MigrationTarget, DirSyncSource, DirSyncTarget.
    Updated:    April 2026     - Renamed MigrationSource/Target to
                                 MigrationAgentSource/Target; interactive interview
                                 replaces numbered menu; dynamic Graph role ID
                                 resolution; DRS permission included at app creation;
                                 Intune Enrollment SP check added alongside SyncFabric;
                                 homepage URL added to app registration;
                                 Grant-AppRoleConsent refactored as reusable function;
                                 headless mode when -PermissionSet flag is supplied;
                                 DirSyncSource/Target renamed to DirSyncRO/DirSyncHP;
                                 source tenants can now select DirSyncHP for
                                 bidirectional sync scenarios.
                                 DirSyncRO now includes Exchange.ManageAsApp;
                                 interview questions coloured with separators for clarity;
                                 BPRT requirements and role list moved to final output;
                                 logo upload hardened with delay and graceful failure handling.
    Updated:    13th April 2026 - Removed Directory.Read.All from DirSyncRO and DirSyncHP
                                  profiles; not required by default.
    Updated:    15th April 2026 - Added -CloudEnvironment parameter for GCC High and DoD
                                  support; REST-based device code flow for all environments
                                  to bypass Azure.Identity token caching regression in
                                  Microsoft.Graph module 2.36.x.
    Updated:    16th April 2026 - Improved error handling: post-auth connection validation
                                  added; Graph API calls in federation check,
                                  Ensure-ServicePrincipalExists, and Get-GraphAppRoleMap now
                                  fail fast with clear messages instead of cascading nulls.
    Updated:    20th April 2026 - Switched from device code flow to interactive browser
                                  authentication; removed REST-based device code workaround.
    Updated:    23rd April 2026 - Added Device.Read.All to DirSyncHP permission profile.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$TenantID,

    [Parameter(Mandatory = $false)]
    [string]$RedirectURI = "http://localhost:5000/redirect",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Commercial", "GCCHigh", "DoD")]
    [string]$CloudEnvironment = "Commercial",

    [Parameter(Mandatory = $false)]
    [ValidateSet("MigrationAgentSource", "MigrationAgentTarget", "DirSyncRO", "DirSyncHP")]
    [string]$PermissionSet
)

# ---------------------------------------------------------------------------
# Branding
# Displayed immediately so the user sees output while modules load.
# ---------------------------------------------------------------------------

$asciiLogo = @"

 ____                        ____                   ____
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/
                                   |___/

"@

Write-Host $asciiLogo
Write-Host "Use this script to create the PowerSyncPro app registration in your tenant."
Write-Host "Do not close this window until you have saved the app secret shown at the end."
Write-Host ""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Info { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan   }
function Ok   { param($Message) Write-Host "[+] $Message" -ForegroundColor Green  }
function Warn { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err  { param($Message) Write-Host "[-] $Message" -ForegroundColor Red    }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# App registration logo - base64-encoded PNG (215x215px, max 100KB).
$appLogoBase64 = 'iVBORw0KGgoAAAANSUhEUgAAASwAAAEsCAIAAAD2HxkiAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAEv2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLyc+CjxyZGY6UkRGIHhtbG5zOnJkZj0naHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyc+CgogPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9JycKICB4bWxuczpBdHRyaWI9J2h0dHA6Ly9ucy5hdHRyaWJ1dGlvbi5jb20vYWRzLzEuMC8nPgogIDxBdHRyaWI6QWRzPgogICA8cmRmOlNlcT4KICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0nUmVzb3VyY2UnPgogICAgIDxBdHRyaWI6Q3JlYXRlZD4yMDI1LTEwLTI0PC9BdHRyaWI6Q3JlYXRlZD4KICAgICA8QXR0cmliOkV4dElkPjNhMDBiZDVjLWUyYWMtNGE2YS05OWQzLWIzYjQ0OWVhYzZlOTwvQXR0cmliOkV4dElkPgogICAgIDxBdHRyaWI6RmJJZD41MjUyNjU5MTQxNzk1ODA8L0F0dHJpYjpGYklkPgogICAgIDxBdHRyaWI6VG91Y2hUeXBlPjI8L0F0dHJpYjpUb3VjaFR5cGU+CiAgICA8L3JkZjpsaT4KICAgPC9yZGY6U2VxPgogIDwvQXR0cmliOkFkcz4KIDwvcmRmOkRlc2NyaXB0aW9uPgoKIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PScnCiAgeG1sbnM6ZGM9J2h0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvJz4KICA8ZGM6dGl0bGU+CiAgIDxyZGY6QWx0PgogICAgPHJkZjpsaSB4bWw6bGFuZz0neC1kZWZhdWx0Jz5VbnRpdGxlZCBkZXNpZ24gLSAxPC9yZGY6bGk+CiAgIDwvcmRmOkFsdD4KICA8L2RjOnRpdGxlPgogPC9yZGY6RGVzY3JpcHRpb24+CgogPHJkZjpEZXNjcmlwdGlv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'

$termsOfServiceUrl   = "https://downloads.powersyncpro.com/current/Declaration-Software-End-User-License-Agreement.pdf"
$homepageUrl         = "https://powersyncpro.com/"
$privacyStatementUrl = "https://powersyncpro.com/privacy-policy/"
$supportUrl          = "https://kb.powersyncpro.com"

# Delegated scopes required to run this setup script
$requiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Organization.Read.All",
    "User.Read"
)

# Microsoft Graph Command Line Tools - well-known public client app used for
# interactive delegated auth. Explicitly specified to avoid reliance on the
# implicit default, which is deprecated in newer SDK versions.
$graphCliClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Resource app IDs
$graphAppId            = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
$exchangeAppId         = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online
$drsAppId              = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"  # Azure Device Registration Service
$syncFabricAppId       = "00000014-0000-0000-c000-000000000000"  # Microsoft.Azure.SyncFabric
$intuneEnrollmentAppId = "d4ebce55-015a-49b5-a083-c84d1797ae8c"  # Microsoft Intune Enrollment

# Non-Graph permission IDs (hardcoded - not resolvable via Graph SP app roles)
$exchangeManageAsAppRoleId      = "dc50a0fb-09a3-484d-be87-e023b12c6440"  # Exchange.ManageAsApp
$selfServiceDeviceDeleteScopeId = "086327cd-9afe-4777-8341-b136a1866bb3"  # self_service_device_delete (BPRT)

# ---------------------------------------------------------------------------
# Permission Sets
# Each entry defines a named configuration selectable via -PermissionSet or
# the interactive interview.
#
#   DisplayName      - Name used for the app registration in Entra
#   Description      - Shown in the interview summary
#   GraphPermissions - Application permission names resolved dynamically from Graph
#   NeedsExchange    - Whether to add Exchange.ManageAsApp
#   IncludeBprt      - Whether to add the bulk enrolment (BPRT) delegated permission
# ---------------------------------------------------------------------------

$permissionSets = @{

    # Source tenant during workstation migration. Read-only. No BPRT required.
    "MigrationAgentSource" = @{
        DisplayName      = "PowerSyncPro - Migration Agent Source (Read Only)"
        Description      = "Read-only source tenant permissions for workstation migration"
        GraphPermissions = @(
            "Device.Read.All",
            "Domain.Read.All",
            "User.Read.All"
        )
        NeedsExchange    = $false
        IncludeBprt      = $false
    }

    # Target tenant during workstation migration. Read-only. Includes BPRT for device enrolment.
    "MigrationAgentTarget" = @{
        DisplayName      = "PowerSyncPro - Migration Agent Target (Read Only)"
        Description      = "Read-only target tenant permissions for workstation migration"
        GraphPermissions = @(
            "Domain.Read.All",
            "User.Read.All"
        )
        NeedsExchange    = $false
        IncludeBprt      = $true
    }

    # Read-only DirSync registration. Suitable for standard source tenants.
    "DirSyncRO" = @{
        DisplayName      = "PowerSyncPro - DirSync (Read Only)"
        Description      = "Read-only permissions for directory sync"
        GraphPermissions = @(
            "Device.Read.All",
            "Domain.Read.All",
            "Group.Read.All",
            "GroupMember.Read.All",
            "User.Read.All"
        )
        NeedsExchange    = $true
        IncludeBprt      = $false
    }

    # Highly privileged DirSync registration. Required for target tenants and bidirectional source tenants.
    "DirSyncHP" = @{
        DisplayName      = "PowerSyncPro - DirSync (Highly Privileged)"
        Description      = "Read/write permissions for directory sync"
        GraphPermissions = @(
            "Domain.Read.All",
            "Device.Read.All",
            "Group.Create",
            "Group.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "User.Invite.All",
            "User.ReadWrite.All"
        )
        NeedsExchange    = $true
        IncludeBprt      = $true
    }

}

# ---------------------------------------------------------------------------
# Module Check
# ---------------------------------------------------------------------------

function Test-MicrosoftGraphModule {
    [CmdletBinding()]
    param(
        [version]$MinimumVersion = [version]"2.28.0",
        [ValidateSet("AllUsers", "CurrentUser")]
        [string]$Scope = "AllUsers"
    )

    Info "Checking Microsoft.Graph module (minimum required: $MinimumVersion)..."

    try {
        $installed = Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue
    } catch {
        $installed = $null
    }

    if (-not $installed) {
        Warn "Microsoft.Graph is not installed. Installing now..."
        Install-Module -Name Microsoft.Graph -Scope $Scope -Force -AllowClobber -MinimumVersion $MinimumVersion
        Write-Host ""
        Warn "Installation complete. Please restart this PowerShell session and re-run the script."
        exit 0
    }

    if ($installed.Version -lt $MinimumVersion) {
        Warn "Installed version ($($installed.Version)) is below the minimum required ($MinimumVersion). Updating..."
        Uninstall-Module -Name Microsoft.Graph -AllVersions -Force
        Install-Module -Name Microsoft.Graph -Scope $Scope -Force -AllowClobber -MinimumVersion $MinimumVersion
        Write-Host ""
        Warn "Update complete. Please restart this PowerShell session and re-run the script."
        exit 0
    }

    Ok "Microsoft.Graph $($installed.Version) is installed."
}

# ---------------------------------------------------------------------------
# Dynamic Graph Role Resolution
# Resolves permission names (e.g. "User.Read.All") to their role GUIDs by
# querying the live Microsoft Graph service principal in the tenant.
# ---------------------------------------------------------------------------

function Get-GraphAppRoleMap {
    Info "Loading Microsoft Graph application roles..."
    try {
        $graphSp = Get-MgServicePrincipal -Filter "AppId eq '$graphAppId'" -ErrorAction Stop
    } catch {
        throw "Failed to query Microsoft Graph service principal: $($_.Exception.Message)"
    }

    if (-not $graphSp) {
        throw "Could not find Microsoft Graph service principal in this tenant."
    }

    $roleMap = @{}
    foreach ($role in $graphSp.AppRoles) {
        if ($role.AllowedMemberTypes -contains "Application") {
            $roleMap[$role.Value] = $role.Id
        }
    }

    return $roleMap
}

function Resolve-GraphResourceAccess {
    param(
        [hashtable] $RoleMap,
        [string[]]  $PermissionNames
    )

    $resourceAccess = @()
    foreach ($name in ($PermissionNames | Sort-Object -Unique)) {
        if (-not $RoleMap.ContainsKey($name)) {
            throw "Could not resolve Microsoft Graph permission '$name'."
        }
        $resourceAccess += @{ Id = $RoleMap[$name]; Type = "Role" }
    }
    return $resourceAccess
}

# ---------------------------------------------------------------------------
# Service Principal Helpers
# ---------------------------------------------------------------------------

function Ensure-ServicePrincipalExists {
    param(
        [Parameter(Mandatory = $true)]  [string] $AppId,
        [Parameter(Mandatory = $false)] [string] $DisplayName
    )

    $label = if ($DisplayName) { $DisplayName } else { $AppId }

    try {
        $existing = Get-MgServicePrincipal -All -ErrorAction Stop | Where-Object { $_.AppId -eq $AppId }
    } catch {
        Err "Failed to query service principals: $($_.Exception.Message)"
        exit 1
    }

    if (-not $existing) {
        Info "Creating service principal: $label..."
        try {
            New-MgServicePrincipal -AppId $AppId -ErrorAction Stop | Out-Null
            Ok "$label created."
        } catch {
            Err "Failed to create service principal '$label': $($_.Exception.Message)"
            exit 1
        }
    } else {
        Ok "$label already present."
    }
}

function Ensure-WorkstationMigrationServicePrincipals {
    Info "Verifying workstation migration service principals..."
    Ensure-ServicePrincipalExists -AppId $syncFabricAppId       -DisplayName "Microsoft.Azure.SyncFabric"
    Ensure-ServicePrincipalExists -AppId $intuneEnrollmentAppId -DisplayName "Microsoft Intune Enrollment"
}

# ---------------------------------------------------------------------------
# Admin Consent
# ---------------------------------------------------------------------------

function Grant-AppRoleConsent {
    param(
        [Parameter(Mandatory = $true)] [string]   $ServicePrincipalId,
        [Parameter(Mandatory = $true)] [string]   $ResourceAppId,
        [Parameter(Mandatory = $true)] [string[]] $RoleIds
    )

    $resourceSp = Get-MgServicePrincipal -Filter "AppId eq '$ResourceAppId'"
    if (-not $resourceSp) {
        throw "Could not find service principal for resource app '$ResourceAppId'."
    }

    foreach ($roleId in $RoleIds) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $ServicePrincipalId `
            -PrincipalId        $ServicePrincipalId `
            -ResourceId         $resourceSp.Id `
            -AppRoleId          $roleId `
            -ErrorAction Stop | Out-Null
    }
}


# ---------------------------------------------------------------------------
# Interactive Interview
# Asks two questions to determine the correct permission set.
# Not called when -PermissionSet is provided.
# ---------------------------------------------------------------------------

function Invoke-PermissionSetInterview {

    $separator = "  " + ("-" * 60)

    Write-Host ""
    Write-Host "Answer the following questions to select the correct permission set." -ForegroundColor Cyan
    Write-Host ""

    # Q1: Source or Target?
    Write-Host "  [1] SOURCE tenant  (PSP reads FROM this tenant)"
    Write-Host "  [2] TARGET tenant  (PSP writes/migrates INTO this tenant)"
    Write-Host ""
    do {
        Write-Host "Is this a source or target tenant? [1/2]: " -ForegroundColor Yellow -NoNewline
        $raw = Read-Host
        $q1  = $raw -as [int]
    } while ($q1 -ne 1 -and $q1 -ne 2)

    Write-Host ""
    Write-Host $separator -ForegroundColor DarkGray
    Write-Host ""

    # Q2: DirSync or Workstation Migration?
    Write-Host "  [1] Directory Sync  (use this if DirSync is in use - includes MigrationAgent permissions)"
    Write-Host "  [2] Workstation Migration only  (MigrationAgent permissions only, no DirSync)"
    Write-Host ""
    do {
        Write-Host "What is PSP being used for in this tenant? [1/2]: " -ForegroundColor Yellow -NoNewline
        $raw = Read-Host
        $q2  = $raw -as [int]
    } while ($q2 -ne 1 -and $q2 -ne 2)

    # Q3 (Source + DirSync only): does this source need write permissions?
    if ($q1 -eq 1 -and $q2 -eq 1) {
        Write-Host ""
        Write-Host $separator -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [1] Read-only  (standard; PSP reads from this tenant only)"
        Write-Host "  [2] Read/write  (bidirectional sync; this source tenant also receives changes)"
        Write-Host ""
        do {
            Write-Host "Does this source tenant require write permissions? [1/2]: " -ForegroundColor Yellow -NoNewline
            $raw = Read-Host
            $q3  = $raw -as [int]
        } while ($q3 -ne 1 -and $q3 -ne 2)

        if ($q3 -eq 1) { return "DirSyncRO" }
        else           { return "DirSyncHP" }
    }

    if     ($q1 -eq 1 -and $q2 -eq 2) { return "MigrationAgentSource" }
    elseif ($q1 -eq 2 -and $q2 -eq 1) { return "DirSyncHP"            }
    else                               { return "MigrationAgentTarget" }
}

# ---------------------------------------------------------------------------
# Configuration Summary  (interactive mode only)
# Shows what will be created and requires the user to type CREATE to proceed.
# ---------------------------------------------------------------------------

function Show-ConfigurationSummary {
    param(
        [hashtable] $Set,
        [string]    $SetName,
        [string]    $Tenant,
        [string]    $Redirect
    )

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Yellow
    Write-Host "  Configuration Summary" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Yellow
    Write-Host "  Permission Set : $SetName"
    Write-Host "  App Name       : $($Set.DisplayName)"
    Write-Host "  Tenant ID      : $Tenant"
    Write-Host "  Redirect URI   : $Redirect"
    Write-Host ""
    Write-Host "  Graph Permissions:"
    foreach ($p in ($Set.GraphPermissions | Sort-Object)) {
        Write-Host "    - $p"
    }
    if ($Set.NeedsExchange) {
        Write-Host ""
        Write-Host "  Exchange Online:"
        Write-Host "    - Exchange.ManageAsApp (full_access_as_app)"
    }
    if ($Set.IncludeBprt) {
        Write-Host ""
        Write-Host "  Device Registration Service:"
        Write-Host "    - self_service_device_delete (BPRT)"
    }
    Write-Host ("=" * 60) -ForegroundColor Yellow
    Write-Host ""

    $confirm = (Read-Host "Type CREATE to proceed, or anything else to cancel").Trim()
    if ($confirm -ne "CREATE") {
        Info "Cancelled."
        exit 0
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Module Check + Import
# ---------------------------------------------------------------------------

Test-MicrosoftGraphModule -MinimumVersion "2.28.0"

Info "Loading required modules..."
@(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement"
) | Where-Object { -not (Get-Module -Name $_) } | ForEach-Object {
    Import-Module $_
}

# ---------------------------------------------------------------------------
# Tenant ID
# ---------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($TenantID)) {
    Write-Host ""
    Write-Host "Enter the Tenant ID you wish to create the app registration in:" -ForegroundColor Cyan
    Write-Host "  e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ForegroundColor DarkGray
    $TenantID = Read-Host
}

# ---------------------------------------------------------------------------
# Permission Set Resolution
# If -PermissionSet was supplied: headless mode, no interview, no summary prompt.
# If not supplied: interview the user, then show summary and require CREATE.
# ---------------------------------------------------------------------------

$headless = -not [string]::IsNullOrWhiteSpace($PermissionSet)

if (-not $headless) {
    $PermissionSet = Invoke-PermissionSetInterview
}

$selectedSet     = $permissionSets[$PermissionSet]
$resolvedAppName = $selectedSet.DisplayName

Info "Permission set: $PermissionSet - $($selectedSet.Description)"

if (-not $headless) {
    Show-ConfigurationSummary `
        -Set      $selectedSet `
        -SetName  $PermissionSet `
        -Tenant   $TenantID `
        -Redirect $RedirectURI
}

# ---------------------------------------------------------------------------
# Graph Connection
# ---------------------------------------------------------------------------

$currentContext = Get-MgContext

if ($currentContext -and $currentContext.TenantId -ne $TenantID) {
    Warn "An active Graph session exists for a different tenant. Disconnecting..."
    Disconnect-MgGraph -InformationAction SilentlyContinue | Out-Null
    $currentContext = $null
}

if (-not $currentContext) {
    $mgEnvironment = switch ($CloudEnvironment) {
        "GCCHigh" { "USGov"    }
        "DoD"     { "USGovDoD" }
        default   { "Global"   }
    }

    Info "Connecting to tenant '$TenantID' ($CloudEnvironment)..."
    Info "A browser window will open for authentication. Sign in with a Global Administrator account."
    Write-Host ""

    Connect-MgGraph -ClientId    $graphCliClientId `
                    -TenantId    $TenantID `
                    -Scopes      $requiredScopes `
                    -Environment $mgEnvironment `
                    -NoWelcome
}

$context = Get-MgContext

# For government clouds authenticated via access token, scopes come back as the
# full resource URI (e.g. "https://graph.microsoft.us/User.Read").  Normalise to
# short names so the check below works the same way for all environments.
$contextScopes = $context.Scopes | ForEach-Object { ($_ -split "/")[-1] }

$missingScopes = $requiredScopes | Where-Object { $_ -notin $contextScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host ""
    Err "The following required permissions were not granted:"
    $missingScopes | ForEach-Object { Err "  - $_" }
    Write-Host ""
    Err "Please disconnect any existing Graph sessions and re-run the script."
    exit 1
}

Write-Host ""
Ok "Connected as $($context.Account)"

# ---------------------------------------------------------------------------
# Connection Validation
# Verify the session can actually reach the tenant before proceeding.
# ---------------------------------------------------------------------------

try {
    $null = Get-MgOrganization -ErrorAction Stop
} catch {
    Err "Connected but unable to query the tenant. The tenant ID may be incorrect,"
    Err "or the account may not have access."
    Err $_.Exception.Message
    exit 1
}

# ---------------------------------------------------------------------------
# BPRT Federation Check
# Only relevant for permission sets that include the BPRT permission.
# ---------------------------------------------------------------------------

$isFederated = $false
if ($selectedSet.IncludeBprt) {
    if ([string]::IsNullOrWhiteSpace($context.Account)) {
        Warn "Could not determine the signed-in account. Skipping federation check."
    } else {
        try {
            $user       = Get-MgUser -UserId $context.Account -ErrorAction Stop
            $domain     = $user.UserPrincipalName.Split("@")[1]
            $domainInfo = Get-MgDomain -DomainId $domain -ErrorAction Stop

            if ($domainInfo.AuthenticationType -eq "Federated") {
                $isFederated = $true
                Warn "This account is federated."
                Warn "The app registration will be created successfully, but if you plan to"
                Warn "create a Bulk Enrolment Token (BPRT) later, you will need to use a"
                Warn "non-federated Global Admin account at that point."
            } else {
                Ok "This account is not federated."
            }
        } catch {
            Warn "Federation check failed: $($_.Exception.Message)"
            Warn "Proceeding without federation status."
        }
    }
}

# ---------------------------------------------------------------------------
# Workstation Migration Service Principals
# SyncFabric and Intune Enrollment must exist for BPRT-enabled permission sets.
# ---------------------------------------------------------------------------

if ($selectedSet.IncludeBprt) {
    Ensure-WorkstationMigrationServicePrincipals
}

# ---------------------------------------------------------------------------
# Duplicate App Check
# ---------------------------------------------------------------------------

$existingApp = Get-MgApplication -Filter "displayName eq '$resolvedAppName'" -ErrorAction SilentlyContinue
if ($existingApp) {
    Write-Host ""
    Warn "An app registration named '$resolvedAppName' already exists in this tenant."
    Warn "Application ID: $($existingApp.AppId)"
    Write-Host ""
    $choice = Read-Host "Do you want to continue and create a second registration? (y/n)"
    if ($choice -ne 'y') {
        Info "Exiting."
        exit 0
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Resolve Graph Role IDs and Build Resource Access
# ---------------------------------------------------------------------------

$graphRoleMap        = Get-GraphAppRoleMap
$graphResourceAccess = Resolve-GraphResourceAccess `
    -RoleMap         $graphRoleMap `
    -PermissionNames $selectedSet.GraphPermissions

$requiredResourceAccess = @(
    @{ ResourceAppId = $graphAppId; ResourceAccess = $graphResourceAccess }
)

if ($selectedSet.NeedsExchange) {
    $requiredResourceAccess += @{
        ResourceAppId  = $exchangeAppId
        ResourceAccess = @(@{ Id = $exchangeManageAsAppRoleId; Type = "Role" })
    }
}

if ($selectedSet.IncludeBprt) {
    $requiredResourceAccess += @{
        ResourceAppId  = $drsAppId
        ResourceAccess = @(@{ Id = $selfServiceDeviceDeleteScopeId; Type = "Scope" })
    }
}

# ---------------------------------------------------------------------------
# Create App Registration
# ---------------------------------------------------------------------------

Info "Creating app registration '$resolvedAppName'..."
$app = New-MgApplication -DisplayName $resolvedAppName `
    -Spa @{ RedirectUris = @($RedirectURI) } `
    -Web @{ HomePageUrl = $homepageUrl } `
    -Info @{
        PrivacyStatementUrl = $privacyStatementUrl
        SupportUrl          = $supportUrl
        TermsOfServiceUrl   = $termsOfServiceUrl
    } `
    -RequiredResourceAccess $requiredResourceAccess
Ok "App registration created."

if (-not [string]::IsNullOrWhiteSpace($appLogoBase64)) {
    Info "Setting app registration logo..."
    $logoBytes = [Convert]::FromBase64String($appLogoBase64)
    $logoTemp  = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "psp-logo.png")
    [System.IO.File]::WriteAllBytes($logoTemp, $logoBytes)
    Start-Sleep -Seconds 3
    try {
        Set-MgApplicationLogo -ApplicationId $app.Id -InFile $logoTemp -ContentType "image/png" -ErrorAction Stop
        Ok "Logo set."
    } catch {
        Write-Host "[!] Logo could not be set (the app was created successfully). You can set it manually in the Entra portal." -ForegroundColor Yellow
    } finally {
        Remove-Item $logoTemp -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Service Principal + Admin Consent
# ---------------------------------------------------------------------------

Info "Creating service principal..."
$sp = New-MgServicePrincipal -AppId $app.AppId
Ok "Service principal created."

Info "Granting admin consent for Microsoft Graph roles..."
Grant-AppRoleConsent `
    -ServicePrincipalId $sp.Id `
    -ResourceAppId      $graphAppId `
    -RoleIds            @($graphResourceAccess | ForEach-Object { $_.Id })
Ok "Microsoft Graph admin consent granted."

if ($selectedSet.NeedsExchange) {
    Info "Granting admin consent for Exchange Online roles..."
    Grant-AppRoleConsent `
        -ServicePrincipalId $sp.Id `
        -ResourceAppId      $exchangeAppId `
        -RoleIds            @($exchangeManageAsAppRoleId)
    Ok "Exchange Online admin consent granted."
}

# ---------------------------------------------------------------------------
# Secret and Lock
# ---------------------------------------------------------------------------

Info "Generating client secret..."
$secret = Add-MgApplicationPassword -ApplicationId $app.Id
Ok "Client secret generated."

Info "Applying service principal lock configuration..."
Update-MgApplication -ApplicationId $app.Id -ServicePrincipalLockConfiguration @{
    IsEnabled                  = $true
    AllProperties              = $true
    CredentialsWithUsageSign   = $true
    CredentialsWithUsageVerify = $true
    TokenEncryptionKeyId       = $true
}
Ok "Service principal lock applied."

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$tenantId     = (Get-MgOrganization).Id
$clientId     = $app.AppId
$clientSecret = $secret.SecretText
$baseUrl      = $RedirectURI -replace '(https?://[^/]+).*', '$1/'

Write-Host ""
Write-Host ("-" * 80)
Write-Host ""
Write-Host "  App registration created successfully." -ForegroundColor Green
Write-Host ""
Write-Host "  IMPORTANT: Copy the information below before closing this window." -ForegroundColor Yellow
Write-Host "  The client secret cannot be retrieved again after this session ends." -ForegroundColor Yellow
Write-Host "  *** Do not share this information with anyone, including PowerSyncPro Support. ***" -ForegroundColor Red
Write-Host ""
Write-Host "  Application Name : $resolvedAppName"
Write-Host "  Permission Set   : $PermissionSet"
Write-Host "  Cloud Environment: $CloudEnvironment"
Write-Host "  Tenant ID        : $tenantId"
Write-Host "  Application ID   : $clientId"
Write-Host "  Client Secret    : $clientSecret"
Write-Host "  Redirect URI     : $RedirectURI"

if ($selectedSet.IncludeBprt) {
    Write-Host ""
    Write-Host "  If creating a BPRT within PowerSyncPro, you must access the application from"
    Write-Host "  $baseUrl or you will receive an error when attempting to generate the BPRT."
    if ($RedirectURI -eq "http://localhost:5000/redirect") {
        Write-Host "  Do not use a vanity name."
    }
    Write-Host ""
    Write-Host "  When creating a BPRT, the account used to generate the token must meet the" -ForegroundColor Cyan
    Write-Host "  following Microsoft requirements:" -ForegroundColor Cyan
    Write-Host ""
    $federatedNote = if ($isFederated) { "($($context.Account) IS federated)" } else { "($($context.Account) is not federated)" }
    $federatedColor = if ($isFederated) { "Yellow" } else { "Green" }
    Write-Host "    Account restrictions:"
    Write-Host "      - Must not be federated " -NoNewline; Write-Host $federatedNote -ForegroundColor $federatedColor
    Write-Host "      - Must not be passwordless or use a Temporary Access Pass (TAP)"
    Write-Host "      - Must be permitted to join devices to Entra AND included in the"
    Write-Host "        Intune MDM user scope for automatic enrollment"
    Write-Host ""
    Write-Host "    Required role (one or more of the following):"
    Write-Host "      - Cloud Device Administrator"
    Write-Host "      - Intune Administrator"
    Write-Host "      - Password Administrator"
    Write-Host "      - Global Administrator"
}

Write-Host ""
Write-Host ("-" * 80)
Write-Host ""
Read-Host "Press Enter to exit"
