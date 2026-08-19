<#
.SYNOPSIS
    Automated installer for PowerSyncPro on Windows Server: all prerequisites, the
    IIS reverse proxy, TLS hardening and an HTTPS certificate.

.DESCRIPTION
    Installs PowerSyncPro end to end on a Windows Server: the .NET 8 Hosting Bundle,
    VC++ Redistributables, SQL Server Express (or an existing local / external SQL
    Server), SQL Server Management Studio, IIS with URL Rewrite and Application
    Request Routing configured as a reverse proxy in front of the Kestrel backend,
    the PowerSyncPro MSI itself, maintenance scripts, firewall rules, SCHANNEL/TLS
    hardening, and an HTTPS certificate - LetsEncrypt (ACME), a supplied PFX (BYOC),
    self-signed, or a certificate already installed on the server.

    A normal run is interactive and downloads content from Microsoft, PowerSyncPro,
    and the PowerSyncPro GitHub. Switch parameters select alternative modes: a
    prerequisite-only first half (-PreReqOnly), a reverse-proxy-only second half
    against a PowerSyncPro installed by hand (-ReverseProxyOnly), a standalone
    reverse proxy in front of PowerSyncPro on another server (-ReverseProxyOnly
    with -PSPBackendUrl), and a fully air-gapped install from a prepared offline
    bundle (-PrepareOffline / -InstallOffline). See the parameter documentation
    and examples below.

.NOTES
    Date            August/2026
    Disclaimer:     This script is community driven and provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 1.0
    Updated : 9th January, 2026 - Added logic to handle installing with existing SQL instances on system, SQL Express 2025, fixed a bug where VC++ install would cause script failure. JRR
    Updated : 20th January, 2026 - Added logic to split the script in half and allow for PreReqOnly and Completion only modes.
    Updated : 3rd February, 2026 - Added logic to handle a headless flag.  Internal use only. - JRR
    Updated : 23rd February, 2026 - Fixed issues in completion only mode with SQL selection. - JRR
    Updated : 10th March, 2026 - Added -KestrelHttpPort / -KestrelHttpsPort flags for custom Kestrel ports. - JRR
    Updated : 18th May, 2026 - URL Rewrite MSI now selected based on OS UI locale so non-English IIS installations receive the correct localized package; falls back to en-US for unsupported locales. Removed /ENU=True from SQL Express install args - SSEI bootstrapper already downloads locale-correct media and this flag caused silent install failure on non-English servers. - JRR
    Updated : 26th May, 2026 - Server Core / remote PS session support: SQL installer now runs via SYSTEM scheduled task to avoid DPAPI double-hop failure; -Verb RunAs and /QS suppressed in non-interactive sessions; SQL update check disabled during install to prevent SEARCHUPDATES access denied error; SSMS skipped on headless servers; completion message updated for remote context; Import-Module WebAdministration errors suppressed from transcript in pre-install checks; non-interactive session detected and reported at startup. - JRR
    Updated : 1st July, 2026 - Fixed silent SSMS install: aka.ms/ssmsfullsetup now serves the SSMS 21+ Visual Studio bootstrapper (vs_ssms.exe), which ignored the old slash switches. Install-SSMS now detects the installer type by OriginalFilename and uses the correct flags (--quiet --norestart --wait for the bootstrapper, /install /quiet /norestart /log for the old standalone), confirms success by locating ssms.exe (new ...Studio nn\Release\Common7\IDE layout) rather than the unreliable bootstrapper exit code, and Test-SSMS now falls back to a filesystem check so the VS-based install is not reinstalled on every run. - JRR
    Updated : 1st July, 2026 - Added offline / air-gapped support: -PrepareOffline builds a SHA256-manifested bundle of every payload, -InstallOffline verifies and installs from it with no internet access. - JRR
    Updated : 24th July, 2026 - Added -IISOnly to deploy just the IIS reverse-proxy stack against a remote PSP backend (-PSPBackendUrl). The admin site is locked down by default; -NoLockAdmin opts out. - Trevor
    Updated : 13th August, 2026 - Merged the offline and IIS-only branches. Added -ReverseProxyOnly, which rebuilds the proxy layer against an existing PSP install and reads the Kestrel port from appsettings.json; -IISOnly and -CompletionOnly are now aliases for it. - JRR
    Updated : 13th August, 2026 - Added an Existing certificate type that binds a certificate already in the LocalMachine store, defaulting to the one bound to 443. Consolidated the four certificate-apply paths into Set-PspCertificate. - JRR
    Updated : 17th August, 2026 - Fixed offline installs from bundles built without -IncludeSSMS: the missing optional SSMS asset killed the install after SQL instead of being skipped. - JRR
    Updated : 17th August, 2026 - All downloads now carry timeouts (PS 5.1 defaults to waiting forever, hanging the installer when a URL such as GitHub is firewalled). Hosts file update hardened: direct .NET I/O, retries on every failure, read-only attribute cleared. - JRR
    Copyright (c) 2026 Declaration Software

.PARAMETER PSPUrl
    URL the PowerSyncPro MSI is downloaded from. Also accepts a local file path
    (e.g. C:\Temp\PowerSyncProInstaller.msi) to install a specific version. In
    offline mode a local path is honored and a URL falls back to the bundled MSI.

.PARAMETER PSPServiceUser
    Optional service account the PowerSyncPro service runs as, e.g. DOMAIN\User or
    .\LocalUser. When omitted the service runs as LocalSystem. Must be supplied
    together with -PSPServicePassword.

.PARAMETER PSPServicePassword
    Password for -PSPServiceUser. Passed to the MSI in plain text - run in a
    secure context.

.PARAMETER PreReqOnly
    Advanced split install, first half: install the prerequisites (including SQL
    and IIS) and stop before the PowerSyncPro MSI. Install the MSI by hand, then
    finish with -ReverseProxyOnly.

.PARAMETER CompletionOnly
    Deprecated alias for -ReverseProxyOnly, retained so existing command lines
    keep working.

.PARAMETER Headless
    Reduce prompting for automation. Only valid together with -PreReqOnly; assumes
    the default SQL instance. Internal use only.

.PARAMETER KestrelHttpPort
    Kestrel HTTP backend port the PowerSyncPro MSI and reverse proxy are
    configured with. Default 5000.

.PARAMETER KestrelHttpsPort
    Kestrel HTTPS backend port. Default 5001.

.PARAMETER PrepareOffline
    Build an offline bundle instead of installing anything: on an internet-connected
    machine, download every required payload into -OfflinePath along with a SHA256
    manifest, then exit. Runs without elevation, so a workstation can build the
    bundle. Cannot be combined with any install-mode flag.

.PARAMETER InstallOffline
    Install from a bundle previously built with -PrepareOffline. The bundle is
    integrity-checked against its manifest before anything is installed and no
    internet access is used. LetsEncrypt is not offered offline.

.PARAMETER OfflinePath
    Location of the offline bundle: the output directory for -PrepareOffline and
    the source directory for -InstallOffline. Default .\PSP_Offline.

.PARAMETER IncludeSSMS
    With -PrepareOffline, also download the SQL Server Management Studio offline
    layout into the bundle (large, multi-GB). Omit to exclude SSMS. Prepare-only.

.PARAMETER ReverseProxyOnly
    Configure ONLY the IIS reverse-proxy layer: IIS with Web-IP-Security, URL
    Rewrite, ARR, server hardening, certificate with HTTPS binding, and firewall
    rules. Installs no SQL, VC++, .NET Hosting Bundle, PSP MSI, service account,
    or SSMS. Two shapes, chosen by whether -PSPBackendUrl is supplied:

    WITHOUT -PSPBackendUrl, PowerSyncPro is installed on THIS server (typically by
    hand, or by an older installer). The Kestrel backend port is read from
    appsettings.json rather than assumed, and the admin site keeps its localhost
    allow.

    WITH -PSPBackendUrl, this server is a standalone, usually internet-facing
    proxy in front of PowerSyncPro on ANOTHER server. The admin site is locked
    down by default (see -NoLockAdmin).

    Requires an interactive session, because the certificate menu prompts.

.PARAMETER IISOnly
    Deprecated alias for -ReverseProxyOnly, retained so existing command lines
    keep working.

.PARAMETER PSPBackendUrl
    Full URL of the REMOTE PowerSyncPro backend the reverse proxy should forward
    to, e.g. https://psp.corp.local:5001. Must be a well-formed absolute http or
    https URL. Its presence is what distinguishes a standalone proxy from one
    sitting in front of a local install. Only valid with -ReverseProxyOnly.

.PARAMETER NoLockAdmin
    Opt out of the standalone-proxy admin lockdown. Only meaningful in
    reverse-proxy mode with a REMOTE backend (-PSPBackendUrl), where the PSP admin
    site is locked down by default: root ipSecurity becomes a full default-deny
    returning 403 for every source including localhost, and only /Agent (plus
    /.well-known for ACME) stays published. Passing -NoLockAdmin retains the
    localhost-allowed behaviour instead. A proxy in front of a LOCAL PowerSyncPro
    is never locked down, so this has no effect there.

.EXAMPLE
    .\PSP_AutoInstall.ps1

    Standard interactive installation: prerequisites, PowerSyncPro, reverse proxy,
    hardening and certificate in a single run.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -PSPServiceUser "DOMAIN\pspsvc" -PSPServicePassword "P@ssw0rd"

    Full installation with the PowerSyncPro service running under a service
    account instead of LocalSystem.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -PreReqOnly

    First half of a split install: prerequisites only. Install the PowerSyncPro
    MSI by hand afterwards, then run -ReverseProxyOnly to finish.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -ReverseProxyOnly

    Configure the reverse proxy, hardening and certificate for a PowerSyncPro
    already installed on this server. The Kestrel port is discovered from
    appsettings.json.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -ReverseProxyOnly -PSPBackendUrl https://psp.corp.local:5001

    Build a standalone reverse proxy on this server in front of PowerSyncPro
    running on another server. The admin site is locked down by default; add
    -NoLockAdmin to keep the localhost allow.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -PrepareOffline -OfflinePath C:\PSP_Offline -IncludeSSMS

    On an internet-connected machine (a workstation is fine, no elevation needed),
    build an offline bundle containing every payload plus a SHA256 manifest.

.EXAMPLE
    .\PSP_AutoInstall.ps1 -InstallOffline -OfflinePath C:\PSP_Offline

    On an air-gapped server, install everything from a prepared bundle with no
    internet access. LetsEncrypt is unavailable offline; the certificate menu
    offers BYOC, self-signed and existing certificates.
#>

# NOTE: administrator rights are enforced at runtime (see the admin check after
# the offline-mode dispatch) rather than with '#Requires -RunAsAdministrator'.
# This lets -PrepareOffline run on a non-elevated workstation to build a bundle,
# while all install modes still require elevation.
# Full parameter documentation lives in the .PARAMETER blocks of the header above
# (Get-Help .\PSP_AutoInstall.ps1 -Detailed). Comments here are one-line signposts.
param (
    # PSP MSI download URL, or a local .msi path to pin a version.
    [string]$PSPUrl = "https://downloads.powersyncpro.com/current/PowerSyncProInstaller.msi",

    # Optional service account (DOMAIN\User or .\LocalUser); LocalSystem when omitted.
    [string]$PSPServiceUser = $null,

    # Password for -PSPServiceUser (plain text, for MSI use).
    [string]$PSPServicePassword = $null,

    # Split install, first half: prerequisites only, stop before the PSP MSI.
    [switch]$PreReqOnly = $false,

    # Deprecated alias for -ReverseProxyOnly.
    [switch]$CompletionOnly = $false,

    # Automation lane for -PreReqOnly: no prompts, default SQL instance. Internal use only.
    [switch]$Headless = $false,

    # Kestrel HTTP backend port (default 5000).
    [int]$KestrelHttpPort = 5000,

    # Kestrel HTTPS backend port (default 5001).
    [int]$KestrelHttpsPort = 5001,

    # Build an offline bundle at -OfflinePath, then exit. Installs nothing; runs unelevated.
    [switch]$PrepareOffline = $false,

    # Install from a prepared offline bundle at -OfflinePath; no internet access used.
    [switch]$InstallOffline = $false,

    # Bundle directory: output for -PrepareOffline, source for -InstallOffline.
    [string]$OfflinePath = ".\PSP_Offline",

    # With -PrepareOffline, also bundle the (multi-GB) SSMS offline layout.
    [switch]$IncludeSSMS = $false,

    # Configure only the IIS reverse-proxy layer; local or remote backend (see -PSPBackendUrl).
    [switch]$ReverseProxyOnly = $false,

    # Deprecated alias for -ReverseProxyOnly.
    [switch]$IISOnly = $false,

    # Remote PowerSyncPro backend URL for a standalone proxy; absolute http/https only.
    [ValidateScript({
        $parsed = $null
        if ([uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$parsed) -and
            ($parsed.Scheme -eq 'http' -or $parsed.Scheme -eq 'https')) {
            $true
        }
        else {
            throw "PSPBackendUrl must be a well-formed absolute URL including scheme, e.g. https://psp.corp.local:5001"
        }
    })]
    [string]$PSPBackendUrl,

    # Opt out of the standalone-proxy admin lockdown (remote backend only).
    [switch]$NoLockAdmin = $false
)

Set-StrictMode -Version Latest

# General Variables
$scriptVer = "v1.0"

$tempDir = "C:\Temp" # Temporary Directory for Downloads, etc.
$LogPath = "C:\Temp\PSP_AutoInstall.txt" # Logging Location

# Web request timeouts. PowerShell 5.1's Invoke-WebRequest / Invoke-RestMethod default
# to -TimeoutSec 0, which waits FOREVER - so a URL blackholed by a corporate firewall
# (e.g. GitHub blocked) hangs the installer indefinitely instead of failing. Reported
# from the field. Every download in this script carries one of these bounds.
$WebTimeoutSec      = 120   # metadata and small script fetches
$DownloadTimeoutSec = 1800  # large payloads (hosting bundle, MSIs) on slow corporate links

# .Net 8 Hosting Platform Variables
# Meta Data URL, link to the latest .net releases in JSON
$metadataUrl = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"

# VC Redistributable Variables
$vcDownloadURL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# SQL 2025 Bootstrapper / Downloader
$SQLBootstrapperUrl = "https://download.microsoft.com/download/7ab8f535-7eb8-4b16-82eb-eca0fa2d38f3/SQL2025-SSEI-Expr.exe"
# SQL Suite Management Studio
$SsmsUrl = "https://aka.ms/ssmsfullsetup"
# Intermediate code-signing cert required to verify the SSMS 22 offline layout on
# air-gapped machines. It is NOT shipped in the layout's certificates folder (that
# only has the standard 2010/2011 roots), and offline boxes cannot auto-fetch it,
# so -PrepareOffline downloads it into the bundle and -InstallOffline imports it.
# Ref: https://learn.microsoft.com/en-us/ssms/install/install-certificates
$SsmsCodeSigningCertUrl  = "https://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt"
$SsmsCodeSigningCertName = "Microsoft_Windows_Code_Signing_PCA_2024.crt"

# IIS URL Rewrite - base download path; locale-specific MSI is selected at install time
$RewriteUrlBase = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592"
# IIS Advanced Request Routing URL
$ArrUrl = "https://download.microsoft.com/download/e/9/8/e9849d6a-020e-47e4-9fd0-a023e99b54eb/requestRouter_amd64.msi"

# Target Folder for Maintenance Scripts (PoshACME Cert Puller, WebConfig Editor)
$ScriptFolder = "C:\Scripts"

# Scripts to Drop (Github Links)
# Certificate Puller Script, used to pull certificates via LetsEncrypt / ACME
$CertPullerScriptName = "Cert-Puller_PoshACME.ps1"
$CertPullerURL = "https://raw.githubusercontent.com/PowerSyncPro/MigrationAgent/refs/heads/main/AutoInstall_Script/Cert-Puller_PoshACME.ps1"
# Certificate Renewer Script, used to manually replace a certificate on a PSP install
$CertRenewerScriptName = "Cert-Renewer.ps1"
$CertRenewerURL = "https://raw.githubusercontent.com/PowerSyncPro/MigrationAgent/refs/heads/main/AutoInstall_Script/Cert-Renewer.ps1"
# WebConfig Editor - Used to update reverse proxy allowed IPs and proxy rewrite URL.
$WebConfigScriptName = "WebConfig_Editor.ps1"
$WebConfigScriptURL = "https://raw.githubusercontent.com/PowerSyncPro/MigrationAgent/refs/heads/main/AutoInstall_Script/WebConfig_Editor.ps1"

# Web.Config Information
$WebConfigName = "web.config"
$WebConfigFolder = "C:\inetpub\wwwroot"

# PowerSyncPro application configuration. Read to discover the Kestrel backend port on a
# server where PowerSyncPro was installed by hand or upgraded, and updated with the
# certificate subject once one is bound.
$PspAppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"

# Install Checks
# .Net Version
$DotNetVer = @("8")
# VC++ Redistributable Version
$vcVer = "14.44.35211"

$asciiLogo=@"
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"@

# ------------------ Functions ------------------
# ------------------ Logging Functions ------------------
# NOTE: these accept ONLY a positional $Message. A number of callers still pass
# "-ForegroundColor Green/Red" - those extra args bind to nothing and are silently
# ignored (the color is fixed per level here). Harmless, but do not rely on them.
function Info  { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Ok    { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Warn  { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err   { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }

# ==================================================================================
# OFFLINE / AIR-GAPPED SUPPORT (scaffolding)
# ----------------------------------------------------------------------------------
# These globals and helpers underpin -PrepareOffline (download everything into a
# bundle on an internet-connected box) and -InstallOffline (install from that bundle
# on an air-gapped box). They are inert unless one of those modes is selected;
# $OfflineMode defaults to 'None' so the existing online flow is unchanged.
# ==================================================================================

# Current offline mode: 'None' | 'Prepare' | 'Install'
$script:OfflineMode = 'None'

# Manifest schema version - bump when the manifest structure changes.
$script:OfflineSchemaVersion = 1

# Bundle paths (populated by Initialize-OfflinePaths once a mode is selected).
$script:BundleDir   = $null   # root of the bundle
$script:PayloadDir  = $null   # <bundle>\payloads   - installers / media
$script:ScriptsDir  = $null   # <bundle>\scripts    - helper .ps1 files
$script:ManifestPath = $null  # <bundle>\manifest.json

function Initialize-OfflinePaths {
    <#
        Resolves and (in Prepare mode) creates the bundle directory layout,
        setting the $script:BundleDir / PayloadDir / ScriptsDir / ManifestPath
        globals. Called from the mode-dispatch block once OfflineMode is set.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Create
    )

    # Resolve to an absolute path so later copies/hashes are unambiguous.
    if ($Create) {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    }
    $script:BundleDir    = (Resolve-Path $Path -ErrorAction SilentlyContinue).Path
    if (-not $script:BundleDir) { $script:BundleDir = $Path }

    $script:PayloadDir   = Join-Path $script:BundleDir "payloads"
    $script:ScriptsDir   = Join-Path $script:BundleDir "scripts"
    $script:ManifestPath = Join-Path $script:BundleDir "manifest.json"

    if ($Create) {
        foreach ($d in @($script:PayloadDir, $script:ScriptsDir)) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
    }
}

function Get-OfflineAssetTable {
    <#
        Single source of truth for every downloadable payload. Both -PrepareOffline
        and -InstallOffline iterate this list so they can never drift apart.

        Each asset:
          Key         - stable identifier used by Resolve-OfflineAsset
          FileName    - name inside the bundle (payloads\ unless SubDir overrides)
          SubDir      - bundle subfolder ('payloads' or 'scripts')
          SourceUrl   - static download URL, or $null when Dynamic
          Dynamic     - URL/filename resolved at prepare time (e.g. latest .NET)
          Special     - handled by bespoke prepare logic (SQL media, SSMS layout)
          Optional    - not required for a valid bundle (e.g. SSMS)
          Description - human-readable label for logs / manifest
    #>
    @(
        [PSCustomObject]@{ Key='dotnet-hosting'; FileName=$null;                        SubDir='payloads'; SourceUrl=$null;               Dynamic=$true;  Special=$false; Optional=$false; Description='.NET 8 ASP.NET Core Hosting Bundle' }
        [PSCustomObject]@{ Key='vcredist';       FileName='vc_redist.x64.exe';          SubDir='payloads'; SourceUrl=$vcDownloadURL;      Dynamic=$false; Special=$false; Optional=$false; Description='Visual C++ 2015-2022 Redistributable (x64)' }
        [PSCustomObject]@{ Key='urlrewrite';     FileName='rewrite_amd64_en-US.msi';    SubDir='payloads'; SourceUrl="$RewriteUrlBase/rewrite_amd64_en-US.msi"; Dynamic=$false; Special=$false; Optional=$false; Description='IIS URL Rewrite Module (en-US)' }
        [PSCustomObject]@{ Key='arr';            FileName='requestRouter_amd64.msi';    SubDir='payloads'; SourceUrl=$ArrUrl;             Dynamic=$false; Special=$false; Optional=$false; Description='IIS Application Request Routing' }
        [PSCustomObject]@{ Key='psp';            FileName='PowerSyncProInstaller.msi';  SubDir='payloads'; SourceUrl=$PSPUrl;             Dynamic=$false; Special=$false; Optional=$false; Description='PowerSyncPro Installer (MSI)' }
        [PSCustomObject]@{ Key='sql-media';      FileName='SQL';                        SubDir='payloads'; SourceUrl=$SQLBootstrapperUrl; Dynamic=$false; Special=$true;  Optional=$false; Description='SQL Server Express install media' }
        [PSCustomObject]@{ Key='ssms';           FileName='SSMS';                       SubDir='payloads'; SourceUrl=$SsmsUrl;            Dynamic=$false; Special=$true;  Optional=$true;  Description='SQL Server Management Studio (offline layout)' }
        # Cert-Puller (PoshACME) is intentionally excluded: it is only used for the
        # LetsEncrypt cert flow, which is unavailable offline.
        [PSCustomObject]@{ Key='cert-renewer';   FileName=$CertRenewerScriptName;       SubDir='scripts';  SourceUrl=$CertRenewerURL;     Dynamic=$false; Special=$false; Optional=$false; Description='Cert-Renewer maintenance script' }
        [PSCustomObject]@{ Key='webconfig';      FileName=$WebConfigScriptName;         SubDir='scripts';  SourceUrl=$WebConfigScriptURL; Dynamic=$false; Special=$false; Optional=$false; Description='WebConfig editor maintenance script' }
    )
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Write-OfflineManifest {
    <#
        Writes manifest.json from a list of asset records. Each record should have:
        Key, FileName, RelativePath, Sha256, SizeBytes, SourceUrl, Version, Description.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Assets,
        [string]$PreparedOn
    )

    $manifest = [PSCustomObject]@{
        schemaVersion = $script:OfflineSchemaVersion
        scriptVersion = $scriptVer
        preparedOn    = $PreparedOn
        preparedOS    = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        preparedLocale = (Get-UICulture).Name
        assets        = $Assets
    }

    $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $script:ManifestPath -Encoding ascii -Force
    Ok "Wrote manifest: $script:ManifestPath"
}

function Read-OfflineManifest {
    if (-not (Test-Path $script:ManifestPath)) {
        throw "Offline manifest not found at $script:ManifestPath. Is -OfflinePath pointing at a valid bundle?"
    }
    return (Get-Content -Path $script:ManifestPath -Raw | ConvertFrom-Json)
}

function Test-BundleIntegrity {
    <#
        Verifies every required asset in the manifest exists in the bundle and its
        SHA256 matches. Returns $true only if all required assets pass. Optional
        assets are reported but do not fail the check.
    #>
    param([Parameter(Mandatory)]$Manifest)

    $allOk = $true
    foreach ($a in $Manifest.assets) {
        $full = Join-Path $script:BundleDir $a.RelativePath
        if (-not (Test-Path $full)) {
            if ($a.Optional) { Warn "Optional asset missing (skipping): $($a.Description)" }
            else { Err "Missing required asset: $($a.Description) [$($a.RelativePath)]"; $allOk = $false }
            continue
        }
        # Directory assets (SQL media / SSMS layout) are hashed as $null; presence is enough.
        if ($a.Sha256) {
            $actual = Get-Sha256 -Path $full
            if ($actual -ne $a.Sha256) {
                Err "Hash mismatch: $($a.Description) [$($a.RelativePath)]"
                $allOk = $false
            }
        }
    }
    return $allOk
}

function Resolve-OfflineAsset {
    <#
        Returns the full local path to a bundled asset by Key (used by the
        Install-* functions when running in offline mode). Returns $null if the
        asset is OPTIONAL and was skipped at prepare time (absent from the
        manifest) or if the file is absent on disk - the caller decides what a
        missing optional asset means. Throws only for keys the asset table does
        not know at all, which is a programmer error, not a thin bundle.
    #>
    param([Parameter(Mandatory)][string]$Key)

    $manifest = Read-OfflineManifest
    $asset = $manifest.assets | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    if (-not $asset) {
        # A bundle prepared without an optional payload (e.g. no -IncludeSSMS) has
        # no manifest row for it. That is a valid bundle, not an error.
        $known = Get-OfflineAssetTable | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
        if ($known -and $known.Optional) { return $null }
        throw "Asset '$Key' is not present in the offline manifest."
    }

    $full = Join-Path $script:BundleDir $asset.RelativePath
    if (-not (Test-Path $full)) { return $null }
    return $full
}

function Get-DownloadToFile {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile
    )
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
}

function Resolve-DotNetHostingAsset {
    <#
        Resolves the latest stable .NET 8 Hosting Bundle download URL / version /
        filename from the release metadata (same logic Install-dotNet8Hosting uses).
    #>
    param([Parameter(Mandatory)][string]$MetadataUrl)

    $releases = Invoke-RestMethod $MetadataUrl -TimeoutSec $WebTimeoutSec
    $stable = $releases.releases | Where-Object { $_.'release-version' -notmatch '-' }
    $latest = $stable | Sort-Object { [version]($_.'release-version') } -Descending | Select-Object -First 1
    $version = $latest.'release-version'
    $asset = $latest.'aspnetcore-runtime'.files | Where-Object { $_.name -eq 'dotnet-hosting-win.exe' } | Select-Object -First 1
    if (-not $asset) { throw "No .NET Hosting Bundle found in release metadata." }

    return [PSCustomObject]@{
        Url      = $asset.url
        Version  = $version
        FileName = "dotnet-hosting-$version-win.exe"
    }
}

function New-AssetRecord {
    <#
        Builds a manifest asset record from a downloaded file or directory:
        computes SHA256 (files only), size, and the bundle-relative path.
    #>
    param(
        [Parameter(Mandatory)]$Asset,
        [Parameter(Mandatory)][string]$FullPath,
        [string]$SourceUrl,
        [string]$Version,
        [switch]$IsDirectory
    )

    $rel = $FullPath.Substring($script:BundleDir.Length).TrimStart('\','/')

    if ($IsDirectory) {
        $size = (Get-ChildItem -Path $FullPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $hash = $null
        $name = $Asset.FileName
    }
    else {
        $size = (Get-Item $FullPath).Length
        $hash = Get-Sha256 -Path $FullPath
        $name = Split-Path $FullPath -Leaf
    }

    return [PSCustomObject]@{
        Key          = $Asset.Key
        FileName     = $name
        RelativePath = $rel
        Sha256       = $hash
        SizeBytes    = $size
        SourceUrl    = $SourceUrl
        Version      = $Version
        Description  = $Asset.Description
        Optional     = $Asset.Optional
    }
}

function Write-OfflineReadme {
    param([string]$PreparedOn)

    $readme = @"
PowerSyncPro Offline Installation Bundle
========================================
Prepared : $PreparedOn
Script   : $scriptVer

This bundle contains every payload required to install PowerSyncPro on an
air-gapped server with no internet access.

Contents:
  manifest.json         - inventory + SHA256 hashes of every payload
  PSP_AutoInstall.ps1   - the installer (offline-capable)
  payloads\             - installers and media (.NET, VC++, IIS modules, SQL, PSP)
  scripts\              - certificate / web.config maintenance scripts

To install on the air-gapped server:
  1. Copy this entire folder to the target server.
  2. Open an elevated PowerShell prompt in this folder.
  3. Run:
         .\PSP_AutoInstall.ps1 -InstallOffline -OfflinePath .

Notes:
  - LetsEncrypt is not available offline. You will be prompted for a PFX
    (bring-your-own certificate) or a self-signed certificate.
  - If this bundle was prepared without -IncludeSSMS, SQL Server Management
    Studio is not included and will be skipped.
"@

    $readme | Out-File -FilePath (Join-Path $script:BundleDir "README.txt") -Encoding ascii -Force
}

function Invoke-PrepareOffline {
    <#
        Downloads every payload in the asset table into the bundle, computes
        hashes, copies the installer script + README, and writes manifest.json.
        Fresh each run (payload/scripts folders are wiped first) and stops on the
        first failure ($ErrorActionPreference = Stop).
    #>
    param(
        [Parameter(Mandatory)][string]$MetadataUrl,
        [switch]$IncludeSSMS
    )

    $ErrorActionPreference = 'Stop'
    $preparedOn = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $records = @()

    # Always start fresh: wipe payload + scripts folders.
    foreach ($d in @($script:PayloadDir, $script:ScriptsDir)) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force }
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    foreach ($a in Get-OfflineAssetTable) {

        if ($a.Key -eq 'ssms' -and -not $IncludeSSMS) {
            Info "Skipping SSMS (use -IncludeSSMS to include it in the bundle)."
            continue
        }

        $subDirPath = Join-Path $script:BundleDir $a.SubDir

        switch ($a.Key) {

            'dotnet-hosting' {
                Info "Resolving latest .NET 8 Hosting Bundle..."
                $dn = Resolve-DotNetHostingAsset -MetadataUrl $MetadataUrl
                $out = Join-Path $subDirPath $dn.FileName
                Info ("Downloading {0} {1}..." -f $a.Description, $dn.Version)
                Get-DownloadToFile -Url $dn.Url -OutFile $out
                $records += New-AssetRecord -Asset $a -FullPath $out -SourceUrl $dn.Url -Version $dn.Version
            }

            'sql-media' {
                Info "Downloading $($a.Description) (large; this can take several minutes)..."
                $sqlRoot  = Join-Path $script:PayloadDir "SQL"
                $mediaDir = Join-Path $sqlRoot "Media"
                New-Item -ItemType Directory -Path $mediaDir -Force | Out-Null
                $boot = Join-Path $sqlRoot "SQL-SSEI-Expr.exe"
                Get-DownloadToFile -Url $a.SourceUrl -OutFile $boot
                # The SSEI downloader attaches to the current console and would clobber
                # the prepare status output. Run it in a separate window (same pattern
                # the interactive install uses) so this window stays readable.
                Info "Launching SQL media download in a separate window; please wait..."
                $bootstrapperCmd = "`"$boot`" /ACTION=Download /MEDIAPATH=`"$mediaDir`" /QUIET"
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$bootstrapperCmd -Verb RunAs -Wait
                $setup = Get-ChildItem -Path $mediaDir -Recurse -Filter "SQLEXPR*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $setup) { throw "SQL media download did not produce a SQLEXPR setup executable in $mediaDir" }
                $records += New-AssetRecord -Asset $a -FullPath $mediaDir -SourceUrl $a.SourceUrl -IsDirectory
            }

            'ssms' {
                Info "Building SSMS offline layout (large; this can take several minutes)..."
                $ssmsRoot  = Join-Path $script:PayloadDir "SSMS"
                $layoutDir = Join-Path $ssmsRoot "layout"
                New-Item -ItemType Directory -Path $layoutDir -Force | Out-Null
                $boot = Join-Path $ssmsRoot "vs_SSMS.exe"
                Get-DownloadToFile -Url $a.SourceUrl -OutFile $boot
                # Create an offline install layout per the MS "create-offline" guide.
                # Run in a separate window so the layout build progress does not clobber
                # the prepare status output.
                Info "Building SSMS layout in a separate window; please wait..."
                $ssmsLayoutCmd = "`"$boot`" --layout `"$layoutDir`" --lang en-US --quiet"
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$ssmsLayoutCmd -Verb RunAs -Wait

                # SSMS 22 packages are signed by the "Microsoft Windows Code Signing
                # PCA 2024" intermediate cert, which is NOT included in the layout's
                # certificates folder and cannot be fetched on an air-gapped box.
                # Download it into the layout so -InstallOffline can import it and the
                # OPC signature verification succeeds offline.
                $certTarget = Join-Path $layoutDir "certificates"
                if (-not (Test-Path $certTarget)) { New-Item -ItemType Directory -Path $certTarget -Force | Out-Null }
                Info "Downloading SSMS code-signing intermediate certificate..."
                Get-DownloadToFile -Url $SsmsCodeSigningCertUrl -OutFile (Join-Path $certTarget $SsmsCodeSigningCertName)

                $records += New-AssetRecord -Asset $a -FullPath $layoutDir -SourceUrl $a.SourceUrl -IsDirectory
            }

            default {
                # Standard single-file asset (payloads\ or scripts\).
                $out = Join-Path $subDirPath $a.FileName
                Info "Downloading $($a.Description)..."
                Get-DownloadToFile -Url $a.SourceUrl -OutFile $out
                $records += New-AssetRecord -Asset $a -FullPath $out -SourceUrl $a.SourceUrl
            }
        }
    }

    # Copy the installer script itself into the bundle root as PSP_AutoInstall.ps1.
    $scriptDest = Join-Path $script:BundleDir "PSP_AutoInstall.ps1"
    Copy-Item -Path $PSCommandPath -Destination $scriptDest -Force
    Ok "Copied installer script to $scriptDest"

    Write-OfflineReadme -PreparedOn $preparedOn
    Write-OfflineManifest -Assets $records -PreparedOn $preparedOn

    Ok "Offline bundle prepared successfully at: $script:BundleDir"
    Info "Move the entire folder to the air-gapped server and run:"
    Info "  .\PSP_AutoInstall.ps1 -InstallOffline -OfflinePath ."
}

# ------------------ Installation and Requirements Checks ------------------
function Install-dotNet8Hosting {
# -----------------------
# Download and install the latest stable .NET 8 Hosting Bundle (Windows)
# -----------------------
  param(
    [string]$metadataUrl,
    [string]$tempDir,
    # Offline: full path to a pre-downloaded dotnet-hosting-*-win.exe. When set,
    # the online metadata lookup and download are skipped.
    [string]$LocalPath
    )

  Info "Installing latest stable .NET 8 Hosting Bundle...."

  if ($LocalPath) {
      if (-not (Test-Path $LocalPath)) { throw "Hosting Bundle not found at offline path: $LocalPath" }
      $installerPath = $LocalPath
      Info "Using offline Hosting Bundle: $installerPath"
  }
  else {
      Info "Fetching release metadata from $metadataUrl ..."
      $releases = Invoke-RestMethod $metadataUrl -TimeoutSec $WebTimeoutSec

      # Filter out prerelease versions like "8.0.0-rc.2"
      $stableReleases = $releases.releases |
          Where-Object { ($_.'release-version' -notmatch '-') }

      # Sort as real [version] objects
      $latestRelease = $stableReleases |
          Sort-Object { [version]($_.'release-version') } -Descending |
          Select-Object -First 1

      $version = $latestRelease.'release-version'
      Info "Latest stable .NET 8 release: $version"

      # Look for the hosting bundle in aspnetcore-runtime.files
      $asset = $latestRelease.'aspnetcore-runtime'.files |
          Where-Object { $_.name -eq "dotnet-hosting-win.exe" } |
          Select-Object -First 1

      if (-not $asset) {
          throw "No Hosting Bundle found in aspnetcore-runtime.files!"
      }

      $downloadUrl = $asset.url
      $installerPath = "$tempDir\dotnet-hosting-$version-win.exe"

      Info "Downloading Hosting Bundle from $downloadUrl ..."
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -TimeoutSec $DownloadTimeoutSec
  }

  Info "Running Hosting Bundle installer silently..."
  Start-Process $installerPath -ArgumentList "/quiet /norestart" -Wait

  Ok ".Net 8 Hosting Bundle installation complete!"
}
function Test-dotNet8Hosting {
    param(
        [string[]]$RequiredVersions = @("8")
    )

    Info "Checking for .NET ASP.NET Core Runtimes..."
    try {
        $runtimes = & dotnet --list-runtimes
    }
    catch {
        Warn "Failed to execute 'dotnet' command. Assuming no versions installed."
        return $false
    }

    if (-not $runtimes) {
        Warn "No .NET runtimes found at all."
        return $false
    }

    try {
        $installedRuntimes = $runtimes |
            Where-Object { $_ -match "^Microsoft\.AspNetCore\.App\s+([0-9]+\.[0-9]+\.[0-9]+)" } |
            ForEach-Object {
                [PSCustomObject]@{
                    Full    = $_.Trim()
                    Version = $Matches[1]
                    Major   = $Matches[1].Split('.')[0]
                }
            }

        # Force array behavior (important when only one match)
        $installedRuntimes = @($installedRuntimes)
    }
    catch {
        Warn "Failed to parse installed runtimes: $($_.Exception.Message)"
        return $false
    }

    if (-not $installedRuntimes -or $installedRuntimes.Length -eq 0) {
        Warn "No Microsoft.AspNetCore.App runtimes found."
        return $false
    }

    Ok "Installed .NET ASP.NET Core Runtimes:"
    foreach ($r in $installedRuntimes) {
        Write-Host "$($r.Full) (Installed)"
    }

    $allFound = $true
    foreach ($version in $RequiredVersions) {
        if ($installedRuntimes.Major -contains $version) {
            Ok "ASP.NET Core Runtime version $version is installed."
        }
        else {
            Warn "ASP.NET Core Runtime version $version is not installed."
            $allFound = $false
        }
    }

    return $allFound
}
function Install-VCRedistributable {
  # -----------------------
  # Download / Install Automated VC++ 2022 Redistributable (x64)
  # -----------------------
  param(
    [string]$DownloadURL,
    [string]$TempDir,
    # Offline: full path to a pre-downloaded vc_redist.x64.exe. When set, the
    # download is skipped and this file is used directly.
    [string]$LocalPath
  )

  $ErrorActionPreference = "Stop"

  Info "Installing Microsoft Visual C++ Redistributables (x64)..."

  if ($LocalPath) {
      if (-not (Test-Path $LocalPath)) { throw "VC++ Redistributable not found at offline path: $LocalPath" }
      $installer = $LocalPath
      Info "Using offline VC++ Redistributable: $installer"
  }
  else {
      # Ensure download directory exists
      if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

      $installer = Join-Path $TempDir "vc_redist.x64.exe"

      Info "Downloading VC++ Redistributable (x64) from $DownloadURL ..."
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -Uri $DownloadURL -OutFile $installer -TimeoutSec $DownloadTimeoutSec

      Info "Downloaded vc_redist.x64.exe to $installer"
  }

  # Step 1: Run silent install (elevated)
  Info "Installing VC++ Redistributable silently..."
  $proc = Start-Process -FilePath $installer `
      -ArgumentList "/quiet", "/norestart" `
      -Verb RunAs -Wait -PassThru

  Info "VC++ Redistributable install finished with exit code $($proc.ExitCode)"
  if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010 -and $proc.ExitCode -ne 1641) {
      throw "VC++ Redistributable install failed with exit code $($proc.ExitCode)"
  }

  # Step 2: Verify install (basic check via registry)
  $vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
  $installed = Test-Path $vcKey

  if ($installed) {
      Ok "VC++ Redistributable (x64) installed successfully."
  } else {
      Warn "VC++ Redistributable verification failed. Check logs or rerun installer."
  }

}
function Test-VCRedistributable {
    param(
        [string]$RequiredVersion = "14.44.35211"  # minimum required version
    )

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $installedSoftware = foreach ($path in $registryPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
            Get-ItemProperty |
            Where-Object {
                $_.PSObject.Properties.Name -contains 'DisplayName' -and
                $_.DisplayName -like "*Visual C++*Redistributable* (x64)*"
            } |
            Select-Object DisplayName, DisplayVersion
    }

    if (-not $installedSoftware) {
        Warn "No Microsoft Visual C++ Redistributables (x64) installed."
        return $false
    }

    Ok "Found Microsoft Visual C++ Redistributables (x64):"
    $installedSoftware | ForEach-Object {
        Write-Host " - $($_.DisplayName) (Version $($_.DisplayVersion))"
    }

    $required = [version]$RequiredVersion
    $valid = $false

    foreach ($item in $installedSoftware) {
        try {
            $ver = [version]($item.DisplayVersion.Trim())
            if ($ver -ge $required) {
                $valid = $true
                break
            }
        }
        catch {
            # ignore if version parsing fails
        }
    }

    if ($valid) {
        Ok "A Visual C++ Redistributable x64 version $RequiredVersion or newer is installed."
        return $true
    }
    else {
        Warn "No Visual C++ Redistributable x64 version $RequiredVersion or newer is installed."
        return $false
    }
}
function Install-SQLExpress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BootstrapperUrl,

        [Parameter(Mandatory = $true)]
        [string]$tempDir,

        [Parameter(Mandatory = $true)]
        [string]$InstanceName,

        [Parameter(Mandatory = $false)]
        [string]$SQLAdminsGroup = $null,

        # Offline: path to pre-downloaded SQL Express install media (the folder
        # produced by the SSEI bootstrapper's /ACTION=Download). When set, the
        # bootstrapper download and media download are skipped.
        [string]$LocalMediaPath
    )

    <#
        Automated SQL Server Express Install
        -----------------------------------------
        - Downloads and extracts SQL Express setup media
        - Performs unattended install
        - Grants sysadmin to either:
            - The provided $SQLAdminsGroup, or
            - BUILTIN\Administrators (default)
        - Verifies SQL service health
    #>

    $ErrorActionPreference = "Stop"

    # If instance already exists, skip install
    $existingSvc = Test-SqlInstanceService -InstanceName $InstanceName
    if ($existingSvc) {
        Warn ("SQL instance '{0}' already exists. Skipping SQL Express installation." -f $InstanceName)

        if ($existingSvc.Status -ne 'Running') {
            if (Confirm-YesNo -Message ("Service is {0}. Start it now" -f $existingSvc.Status)) {
                Start-Service -Name $existingSvc.Name -ErrorAction Stop
                $existingSvc.WaitForStatus('Running','00:00:20')
            }
        }
        return
    }

    $DownloadDir = Join-Path $tempDir "SQL"
    $MediaDir    = Join-Path $DownloadDir "Media"

    Info ("Installing SQL Server Express instance '{0}'..." -f $InstanceName)

    if ($LocalMediaPath) {
        # Offline: use the pre-downloaded media folder from the bundle.
        if (-not (Test-Path $LocalMediaPath)) { throw ("SQL media not found at offline path: {0}" -f $LocalMediaPath) }
        $MediaDir = (Resolve-Path $LocalMediaPath).Path
        Info ("Using offline SQL Server Express media: {0}" -f $MediaDir)
    }
    else {
        foreach ($d in @($DownloadDir, $MediaDir)) {
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }

        # Download bootstrapper
        $bootstrapperExe = Join-Path $DownloadDir "SQL-SSEI-Expr.exe"
        Info ("Downloading SQL Server Express bootstrapper from {0} ..." -f $BootstrapperUrl)
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $BootstrapperUrl -OutFile $bootstrapperExe -TimeoutSec $DownloadTimeoutSec
        Info ("Downloaded bootstrapper to {0}" -f $bootstrapperExe)

        # Download full install media
        Info "Fetching installation media..."
        # -Verb RunAs (ShellExecute) is used in interactive desktop sessions so the download
        # progress window is visible to the user. In remote PS sessions and Server Core the
        # window station is non-interactive, causing ShellExecute to fail silently, so we
        # invoke the bootstrapper directly instead (the script is already running as admin).
        if ([Environment]::UserInteractive) {
            $bootstrapperCmd = "`"$bootstrapperExe`" /ACTION=Download /MEDIAPATH=`"$MediaDir`" /QUIET"
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$bootstrapperCmd -Verb RunAs -Wait
        } else {
            Start-Process -FilePath $bootstrapperExe -ArgumentList "/ACTION=Download","/MEDIAPATH=`"$MediaDir`"","/QUIET" -Wait
        }
    }

    # Locate setup executable
    $setupExe = Get-ChildItem -Path $MediaDir -Recurse -Filter "SQLEXPR*.exe" | Select-Object -First 1
    if (-not $setupExe) { throw ("Could not find SQL Server Express setup executable in {0}" -f $MediaDir) }
    Info ("Found setup executable: {0}" -f $setupExe.FullName)

    # Build sysadmin accounts string
    if (-not [string]::IsNullOrWhiteSpace($SQLAdminsGroup)) {
        $sysAdminsArg = "/SQLSYSADMINACCOUNTS=`"$SQLAdminsGroup`""
    }
    else {
        $sysAdminsArg = '/SQLSYSADMINACCOUNTS="BUILTIN\Administrators"'
    }

    Info ("Installing SQL Server Express with sysadmin accounts: {0}" -f $sysAdminsArg)

    # Build installer arguments
    # /QS shows a simple progress UI in interactive desktop sessions; /Q is fully silent
    # and required for remote PS sessions / Server Core where there is no window station.
    $quietFlag = if ([Environment]::UserInteractive) { "/QS" } else { "/Q" }

    $SqlArgs = @(
        "/ROLE=AllFeatures_WithDefaults",
        "/ACTION=Install",
        "/FEATURES=SQLENGINE,REPLICATION",
        # Disable update search during install. The SEARCHUPDATES workflow calls the
        # Windows Update COM interface which is inaccessible in remote PS sessions and
        # causes an Access Denied failure. SQL can be patched post-install via WU/WSUS.
        "/UpdateEnabled=False",
        "/USEMICROSOFTUPDATE=False",
        ("/INSTANCENAME={0}" -f $InstanceName),
        $sysAdminsArg,
        "/TCPENABLED=1",
        "/IACCEPTSQLSERVERLICENSETERMS",
        $quietFlag
    )

    if ([Environment]::UserInteractive) {
        # Interactive desktop session: use -Verb RunAs so the installer attaches to the
        # desktop and the progress UI is visible to the user.
        $sqlProc = Start-Process -FilePath $setupExe.FullName -ArgumentList $SqlArgs -Verb RunAs -Wait -PassThru
        $sqlExitCode = $sqlProc.ExitCode
    } else {
        # Remote PS / Server Core: running the installer directly here fails because SQL
        # setup calls DPAPI (ProtectedData.Protect) to serialize service credentials, and
        # DPAPI with CurrentUser scope requires an interactive logon session to load the
        # user master key. A WinRM session uses a network logon - no master key, Access
        # Denied. Fix: run the installer via a scheduled task as SYSTEM. SYSTEM uses the
        # machine DPAPI key which is always available regardless of session type.
        $taskName  = "PSP_SQLInstall"
        $argString = $SqlArgs -join " "
        $action    = New-ScheduledTaskAction -Execute $setupExe.FullName -Argument $argString
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Info "SQL installer running via SYSTEM scheduled task. Waiting for completion..."
        do {
            Start-Sleep -Seconds 10
            $taskState = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
        } while ($taskState -eq "Running")
        $sqlExitCode = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
    }
    Info ("SQL installer exited with code: {0}" -f $sqlExitCode)

    # Verify SQL service exists and is running
    $serviceName = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if (-not $service) {
        Err "SQL Server Express service not found. Installation may have failed."
        exit 1
    }

    if ($service.Status -ne 'Running') {
        Warn "SQL Server Express service is installed but not running. Attempting to start..."
        try {
            Start-Service -Name $serviceName -ErrorAction Stop
            $service.WaitForStatus('Running','00:00:20')
            Ok "SQL Server Express service started successfully."
        }
        catch {
            Err ("Failed to start SQL Server Express service. Error: {0}" -f $_)
            exit 1
        }
    }
    else {
        Ok "SQL Server Express service is running."
        Ok "SQL Server Express installed successfully."
    }
}
function Find-SsmsExe {
  <#
  .SYNOPSIS
      Locates ssms.exe for any installed SSMS version (old or new layout).
  .OUTPUTS
      [string] Full path to ssms.exe, or $null if not found.
  #>
  $candidates = @()
  foreach ($base in @("C:\Program Files", "C:\Program Files (x86)")) {
      $dirs = Get-ChildItem -Path $base -Directory -Filter "Microsoft SQL Server Management Studio *" -ErrorAction SilentlyContinue
      foreach ($d in $dirs) {
          # New (SSMS 21/22): ...\<ver>\Release\Common7\IDE\ssms.exe
          $candidates += (Join-Path $d.FullName "Release\Common7\IDE\ssms.exe")
          # Old (SSMS 18/19/20): ...\<ver>\Common7\IDE\ssms.exe
          $candidates += (Join-Path $d.FullName "Common7\IDE\ssms.exe")
      }
  }
  $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Install-SSMS {
  param(
  [string]$SsmsUrl,
  [string]$tempDir
  )
  # -----------------------
  # Download / Install SQL Server Management Studio
  #
  # aka.ms/ssmsfullsetup now serves the SSMS 21+ Visual Studio bootstrapper
  # (vs_ssms.exe), which uses double-dash switches ("--quiet --norestart
  # --wait") instead of the old standalone installer's slash switches. Both
  # block until the install completes when launched with Start-Process -Wait,
  # so we detect the installer type by its OriginalFilename and pick the right
  # flags. Success is confirmed by locating ssms.exe, not by the exit code
  # (the bootstrapper's early-return codes are not reliable).
  # -----------------------

  $DownloadDir = "$tempDir\SSMS"

  $ErrorActionPreference = "Stop"

  Info "Installing SQL Server Management Studio (SSMS)..."

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  $ssmsInstaller = Join-Path $DownloadDir "SSMS-Setup-ENU.exe"

  Info "Downloading SSMS installer from $SsmsUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $SsmsUrl -OutFile $ssmsInstaller -TimeoutSec $DownloadTimeoutSec

  Info "Downloaded SSMS installer to $ssmsInstaller"

  # Step 1: Detect installer type and choose the correct silent-install flags.
  $info = (Get-Item $ssmsInstaller).VersionInfo
  $isBootstrapper = ($info.OriginalFilename -like "vs_ssms*")

  if ($isBootstrapper) {
      Info "Detected SSMS 21+ Visual Studio bootstrapper (version $($info.ProductVersion))."
      $ssmsArgs = @("--quiet", "--norestart", "--wait")
  } else {
      Info "Detected SSMS 20 or older standalone installer (version $($info.ProductVersion))."
      $ssmsArgs = @("/install", "/quiet", "/norestart", "/log", "$DownloadDir\SSMS-Install.log")
  }

  # Step 2: Run SSMS silent install (elevated), blocking until it completes.
  Info "Installing SSMS silently; this can take several minutes..."
  $proc = Start-Process -FilePath $ssmsInstaller -ArgumentList $ssmsArgs -Verb RunAs -Wait -PassThru
  Info "SSMS installer returned exit code $($proc.ExitCode)."

  # For the old standalone installer the exit code is authoritative
  # (0 = success, 3010 = success/reboot required). The bootstrapper's codes
  # are less reliable, so for it we rely on the ssms.exe check below.
  if (-not $isBootstrapper -and ($proc.ExitCode -notin 0, 3010)) {
      throw "SSMS install failed with exit code $($proc.ExitCode). See log at $DownloadDir\SSMS-Install.log"
  }

  # Step 3: Verify SSMS installation (short poll as a safety net in case the
  # elevated installer handle returned before the files were fully in place).
  $verifyBy = (Get-Date).AddMinutes(3)
  $ssmsExe = $null
  do {
      $ssmsExe = Find-SsmsExe
      if (-not $ssmsExe) { Start-Sleep -Seconds 5 }
  } while (-not $ssmsExe -and (Get-Date) -lt $verifyBy)

  if (-not $ssmsExe) {
      Warn "SSMS executable not found after install. Check VS Installer logs at %TEMP%\dd_*.log or the log at $DownloadDir\SSMS-Install.log"
      return
  }

  Ok "SSMS installed successfully at: $ssmsExe"
}
function Test-SSMS {
    <#
    .SYNOPSIS
        Checks if SQL Server Management Studio (SSMS) is installed.
    .OUTPUTS
        [bool] True if SSMS is installed, False otherwise.
    #>
    [CmdletBinding()]
    param()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $ssms = foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object {
                    $_.PSObject.Properties.Name -contains 'DisplayName' -and
                    $_.DisplayName -like "SQL Server Management Studio*"
                } |
                Select-Object DisplayName, DisplayVersion
        }
    }

    if ($ssms) {
        Ok "SQL Server Management Studio (SSMS) is installed:" -ForegroundColor Green
        $ssms | ForEach-Object {
            Ok " - $($_.DisplayName) (Version $($_.DisplayVersion))"
        }
        return $true
    }

    # Fallback: the SSMS 21+ VS-based installer may register under a different
    # DisplayName, so also check the filesystem for ssms.exe directly.
    $ssmsExe = Find-SsmsExe
    if ($ssmsExe) {
        Ok "SQL Server Management Studio (SSMS) is installed: $ssmsExe"
        return $true
    }

    Warn "SQL Server Management Studio (SSMS) is not installed." -ForegroundColor Red
    return $false
}
function Install-IIS {
    <#
    .SYNOPSIS
        Installs IIS and/or Web-IP-Security if missing.
    .PARAMETER IISInstalled
        Boolean indicating if IIS is already installed.
    .PARAMETER WebIPInstalled
        Boolean indicating if Web-IP-Security is already installed.
    #>
    [CmdletBinding()]
    param(
        [bool]$IISInstalled,
        [bool]$WebIPInstalled
    )

    Import-Module ServerManager

    if (-not $IISInstalled) {
        Info "Installing IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools
        Ok "IIS Sucessfully Installed on this Server."
    }
    else {
        Ok "IIS is already installed."
    }

    if (-not $WebIPInstalled) {
        Info "Installing Web-IP-Security..."
        Add-WindowsFeature Web-IP-Security
        Ok "IIS Web IP Security Installed..."
    }
    else {
        Ok "Web-IP-Security is already installed."
    }
}
function Test-IISFeatures {
    <#
    .SYNOPSIS
        Checks if IIS (Web-Server) and Web-IP-Security are installed.
    .OUTPUTS
        [PSCustomObject] with IISInstalled and WebIPInstalled properties.
    #>
    [CmdletBinding()]
    param()

    Import-Module ServerManager

    $iis   = Get-WindowsFeature -Name Web-Server
    $webip = Get-WindowsFeature -Name Web-IP-Security

    return [PSCustomObject]@{
        IISInstalled   = $iis.Installed
        WebIPInstalled = $webip.Installed
    }
}
function Install-URLRewrite {
  param(
    [string]$RewriteUrlBase,
    [string]$tempDir,
    # Offline: full path to a pre-downloaded URL Rewrite MSI (en-US in the bundle).
    # When set, locale resolution and download are skipped.
    [string]$LocalPath
  )
  # -----------------------
  # Install URL Rewrite
  # -----------------------

  Info "Installing IIS URL Rewrite Functionality..."
  $DownloadDir = "$tempDir\URLRewrite"

  # Ensure download / logging directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  if ($LocalPath) {
      if (-not (Test-Path $LocalPath)) { throw "URL Rewrite MSI not found at offline path: $LocalPath" }
      $installer = $LocalPath
      Info "Using offline URL Rewrite MSI: $installer"
  }
  else {
      # Select the localized MSI that matches the OS UI language so it integrates
      # correctly with a non-English IIS installation.
      $knownLocales = @('en-US','fr-FR','de-DE','ja-JP','zh-CN','zh-TW','ko-KR','es-ES','pt-BR','it-IT','ru-RU','cs-CZ','pl-PL','tr-TR','hu-HU')
      $osLocale = (Get-UICulture).Name

      if ($knownLocales -contains $osLocale) {
          $rewriteLocale = $osLocale
      } else {
          $langCode = $osLocale.Split('-')[0]
          $match = $knownLocales | Where-Object { $_.StartsWith("$langCode-") } | Select-Object -First 1
          if ($match) {
              $rewriteLocale = $match
              Warn "URL Rewrite: no exact match for '$osLocale', using '$rewriteLocale'."
          } else {
              $rewriteLocale = 'en-US'
              Warn "URL Rewrite: no localized package found for '$osLocale', falling back to en-US."
          }
      }

      $RewriteUrl = "$RewriteUrlBase/rewrite_amd64_$rewriteLocale.msi"
      $installer = Join-Path $DownloadDir "rewrite_amd64_$rewriteLocale.msi"

      Info "Downloading IIS URL Rewrite MSI ($rewriteLocale) from $RewriteUrl ..."
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -Uri $RewriteUrl -OutFile $installer -TimeoutSec $DownloadTimeoutSec

      Info "Downloaded to $installer"
  }

  # Step 1: Run silent install (elevated)
  Info "Installing IIS URL Rewrite silently..."
  $proc = Start-Process -FilePath "msiexec.exe" `
      -ArgumentList "/i", "`"$installer`"", "/quiet", "/norestart", "/log", "$DownloadDir\URLRewrite-Install.log" `
      -Verb RunAs -Wait -PassThru

  if ($proc.ExitCode -ne 0) {
      throw "URL Rewrite install failed with exit code $($proc.ExitCode). See log: $DownloadDir\URLRewrite-Install.log"
  }

  # Step 2: Verify installation
  $regKey = "HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite"
  if (Test-Path $regKey) {
      Ok "IIS URL Rewrite installed successfully." -ForegroundColor Green
  } else {
      Warn "IIS URL Rewrite registry key not found. Check log: $DownloadDir\URLRewrite-Install.log" -ForegroundColor Red
  }

}
function Test-IISUrlRewrite {
    <#
    .SYNOPSIS
        Checks if IIS URL Rewrite Module is installed.
    .OUTPUTS
        [bool] True if installed, False otherwise.
    #>
    [CmdletBinding()]
    param()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $rewrite = foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -like "IIS URL Rewrite*" } |
                Select-Object DisplayName, DisplayVersion
        }
    }

    if ($rewrite) {
        Ok "IIS URL Rewrite is installed:" -ForegroundColor Green
        $rewrite | ForEach-Object {
            Ok " - $($_.DisplayName) (Version $($_.DisplayVersion))"
        }
        return $true
    }
    else {
        Warn "IIS URL Rewrite is not installed." -ForegroundColor Red
        return $false
    }
}
function Install-ARR {
    param (
        [bool]$ARRInstalled,
        [bool]$ARRActivated,
        [string]$ArrUrl,
        [string]$tempDir,
        # Offline: full path to a pre-downloaded requestRouter MSI. When set, the
        # download is skipped and this file is used directly.
        [string]$LocalPath
    )

    Info "Installing IIS Advanced Request Routing (ARR)..."

    $DownloadDir = Join-Path $tempDir "ARR"

    # Ensure download directory exists
    if (-not (Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    # NOTE: online download is named requestRouter_x64.msi here, but the offline
    # bundle/manifest uses requestRouter_amd64.msi. Harmless because the offline
    # path overrides $installer via -LocalPath, but keep the two names in mind.
    $installer = Join-Path $DownloadDir "requestRouter_x64.msi"

    # 1. Install ARR if missing
    if (-not $ARRInstalled) {
        if ($LocalPath) {
            if (-not (Test-Path $LocalPath)) { throw "ARR MSI not found at offline path: $LocalPath" }
            $installer = $LocalPath
            Info "Using offline ARR MSI: $installer"
        }
        else {
            Info "Downloading ARR 3.0 from $ArrUrl ..."
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $ArrUrl -OutFile $installer -TimeoutSec $DownloadTimeoutSec

            Info "Downloaded ARR to $installer"
        }

        Info "Installing ARR silently..."
        $proc = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i", "`"$installer`"", "/quiet", "/norestart", "/log", "$DownloadDir\ARR-Install.log" `
            -Verb RunAs -Wait -PassThru

        if ($proc.ExitCode -ne 0) {
            throw "ARR install failed with exit code $($proc.ExitCode). See log: $DownloadDir\ARR-Install.log"
        }

        Ok "ARR installed successfully."
    }
    else {
        Ok "ARR already installed. Skipping installation."
    }

    # 2. Enable ARR proxy if not activated
    if (-not $ARRActivated) {
        Info "Enabling ARR proxy in IIS..."
        Import-Module WebAdministration

        if (-not (Get-WebConfiguration "//system.webServer/proxy" -ErrorAction SilentlyContinue)) {
            Add-WebConfigurationSection -PSPath 'MACHINE/WEBROOT/APPHOST' -SectionPath 'system.webServer/proxy'
        }

        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter "system.webServer/proxy" `
            -name "enabled" `
            -value "True"

        Ok "ARR proxy enabled in IIS."
    }
    else {
        Ok "ARR proxy already enabled in IIS. Skipping activation."
    }
}
function Test-IISARR {
    <#
    .SYNOPSIS
        Checks if IIS Application Request Routing (ARR) is installed
        and if it is activated in IIS configuration.
    .OUTPUTS
        [PSCustomObject] with ARRInstalled and ARRActivated properties.
    #>
    [CmdletBinding()]
    param()

    # ------------------------
    # 1. Check if ARR is installed (registry)
    # ------------------------
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $arrInstalled = $false
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $match = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -like "*Application Request Routing*" }
            if ($match) {
                $arrInstalled = $true
                break
            }
        }
    }

    # ------------------------
    # 2. Check if ARR is activated in IIS
    # ------------------------
    $arrActivated = $false
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        $proxySection = Get-WebConfigurationProperty `
            -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter "system.webServer/proxy" `
            -name "." -ErrorAction Stop

        if ($proxySection -and $proxySection.enabled -eq $true) {
            $arrActivated = $true
        }
    }
    catch {
        $arrActivated = $false
    }

    # Return both values as an object
    [PSCustomObject]@{
        ARRInstalled = $arrInstalled
        ARRActivated = $arrActivated
    }
}
function Install-PSP {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$PSPUrl,

    [Parameter(Mandatory = $true)]
    [string]$tempDir,

    [Parameter(Mandatory = $true)]
    [string]$FrontendHost,

    [int]$httpPort = 5000,
    [int]$httpsPort = 5001,

    [string]$SqlInstance = "SQLEXPRESS",
    [string]$SqlDatabase = "PowerSyncProDB",
    [string]$SqlAddress = "localhost",
    [string]$SqlPort = "1433",

    [string]$PSPServiceUser = $null,
    [string]$PSPServicePassword = $null
  )

  # -----------------------------------
  # Download or use local PowerSyncPro MSI
  # -----------------------------------

  $DownloadDir = $tempDir
  $Installer   = Join-Path $DownloadDir "PowerSyncProInstaller.msi"
  $LogFile     = Join-Path $DownloadDir "PSPInstaller_Log.txt"

  Info "Beginning Installation of PowerSyncPro..."

  # Ensure temp directory exists
  if (-not (Test-Path $DownloadDir)) {
    New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null
    Info "Created folder: $DownloadDir"
  }

  # Determine if $PSPUrl is a local file or URL
  if (Test-Path $PSPUrl -PathType Leaf) {
    # Local installer provided
    Info "Using local installer: $PSPUrl"
    $Installer = (Resolve-Path $PSPUrl).Path
  }
  else {
    # Remote URL - download it
    Info "Downloading PowerSyncPro installer from $PSPUrl..."
    $ProgressPreference = 'SilentlyContinue'
    try {
      Invoke-WebRequest -Uri $PSPUrl -OutFile $Installer -UseBasicParsing -TimeoutSec $DownloadTimeoutSec
      Info "Downloaded to $Installer"
    }
    catch {
      Err "Failed to download installer from $PSPUrl. $_"
      return
    }
  }

  # -----------------------------------
  # Run MSI installer silently with flags and logging
  # -----------------------------------
  Info "Starting PowerSyncPro MSI installation..."

    # Base Arguments
    $Arguments = @(
    "/i", "`"$Installer`"",
    "USE_LOCAL_SYSTEM=1",
    "PSP_HTTP_PORT=$httpPort",
    "PSP_HTTPS_PORT=$httpsPort",
    "PSP_BIND_ALL=1",
    "PSP_SQL_SERVER=$SqlAddress",
    "PSP_SQL_PORT=$SqlPort",
    "PSP_SQL_INSTANCE=$SqlInstance",
    "PSP_SQL_DATABASE=$SqlDatabase",
    "PSP_CREATE_PROXY=True",
    "PSP_PROXY_SITE=`"Default Web Site`"",
    "PSP_DOMAIN_REWRITE=$FrontendHost",
    "PSP_USE_LOCAL_KEY=True",
    "PSP_SQL_SERVER_IS_LOCAL=1",
    "/qn",
    "/L*v", "`"$LogFile`""
    )

    # If Instance is Blank (e.g. Default Instance), remove the PSP_SQL_INSTANCE Flag
    if ([string]::IsNullOrWhiteSpace($SqlInstance) -or $SqlInstance -eq "MSSQLSERVER") {
        $Arguments = $Arguments | Where-Object { $_ -notmatch '^PSP_SQL_INSTANCE=' }
    }

    # If Service Account is provided, add relevant flags and remove "USE_LOCAL_SYSTEM"
    if (-not [string]::IsNullOrWhiteSpace($PSPServiceUser)) {

        # Split domain/hostname from username
        $parts = $PSPServiceUser.Split('\', 2)
        $accountPrefix = $parts[0]
        $accountName   = $parts[1]

        # Determine if the service account is local or domain
        $isLocalAccount = $accountPrefix -ieq $env:COMPUTERNAME

        if (-not $isLocalAccount) {
            # Account is domain-based, not local - disable local key usage
            $Arguments = $Arguments | Where-Object { $_ -notmatch '^PSP_USE_LOCAL_KEY=' }
            $Arguments += "PSP_USE_LOCAL_KEY=False"
        }

        # Add service account details
        $Arguments += "PSP_SERVICE_USERNAME=$($PSPServiceUser.ToLower())"
        $Arguments += "PSP_SERVICE_USERNAME_SAM=$($PSPServiceUser.ToLower())"
        $Arguments += "PSP_SERVICE_PASSWORD=`"$PSPServicePassword`""

        # Remove USE_LOCAL_SYSTEM
        $Arguments = $Arguments | Where-Object { $_ -notmatch '^USE_LOCAL_SYSTEM=' }
    }

    #Info "Current MSI Arguments: $Arguments"

    # Start MSIExec and Start the Process
    Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow

  Ok "Installation complete. Log file: $LogFile"
  Info "Checking status of PowerSyncPro Service...."

  # -----------------------------------
  # Verify PowerSyncPro Service
  # -----------------------------------
  $svc = $null
  $maxWaitSeconds = 60
  $elapsed = 0

  while ($elapsed -lt $maxWaitSeconds) {
    $svc = Get-Service -Name "PowerSyncPro" -ErrorAction SilentlyContinue
    if ($svc) {
      if ($svc.Status -eq 'Running') {
        Ok "PowerSyncPro service is running."
        break
      }
      elseif ($svc.Status -eq 'Stopped') {
        Warn "PowerSyncPro service is installed but stopped. Attempting to start..."
        try {
          Start-Service -Name "PowerSyncPro"
          $svc.WaitForStatus('Running','00:00:20')
          Ok "PowerSyncPro service started successfully."
          break
        } catch {
            Warn "PowerSyncPro service could not be started: $_"
          return
        }
      }
    }

    Start-Sleep -Seconds 5
    $elapsed += 5
  }

  if (-not $svc -or $svc.Status -ne 'Running') {
    Warn "PowerSyncPro service not found or not running after $maxWaitSeconds seconds."
  }
}
function Test-PowerSyncPro {
    param(
        [string]$MsiGuid = "{C76A6947-4CAD-4382-9D6F-672ADFB0FCCF}"
    )

    $serviceRunning = $false
    $msiInstalled   = $false

    # 1. Check if service is running
    $svc = Get-Service -Name "PowerSyncPro" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        $serviceRunning = $true
    }

    # 2. Check if MSI is installed (registry)
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($key in $uninstallKeys) {
        if (Test-Path "$key\$MsiGuid") {
            $msiInstalled = $true
            break
        }
    }

    # Return true if either condition is met
    return ($serviceRunning -or $msiInstalled)
}
function Install-Scripts {
    <#
    .SYNOPSIS
        Drops a PowerShell script to disk from either a Base64-encoded string or a URL.

    .PARAMETER TargetFile
        The filename to save (e.g., 'Cert-Puller_PoshACME.ps1').

    .PARAMETER TargetFolder
        The folder path where the file should be saved.

    .PARAMETER Encoded
        Base64-encoded string of the script content (optional).

    .PARAMETER Url
        HTTP/HTTPS URL to download the script from (optional).

    .EXAMPLE
        Install-Scripts -TargetFile 'Child.ps1' -TargetFolder 'C:\Scripts' -Encoded $Base64String

    .EXAMPLE
        Install-Scripts -TargetFile 'Child.ps1' -TargetFolder 'C:\Scripts' -Url 'https://example.com/script.ps1'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetFile,

        [Parameter(Mandatory)]
        [string]$TargetFolder,

        [string]$Encoded,

        [string]$Url,

        # Offline: read the script from a local file (bundled) instead of a URL.
        [string]$LocalPath
    )

    try {
        $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile

        # Ensure the folder exists
        if (-not (Test-Path $TargetFolder)) {
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }

        $ChildScript = $null

        if ($LocalPath) {
            Info "Using local script: $LocalPath"
            if (-not (Test-Path $LocalPath)) { throw "Local script not found: $LocalPath" }
            $ChildScript = Get-Content -Path $LocalPath -Raw
        }
        elseif ($Encoded) {
            Info "Decoding Base64 content..."
            $Bytes = [Convert]::FromBase64String($Encoded)
            $ChildScript = [System.Text.Encoding]::UTF8.GetString($Bytes)
        }
        elseif ($Url) {
            Info "Downloading script from $Url ..."
            try {
                # -TimeoutSec is the fix for the field report of the installer HANGING
                # when GitHub is blocked on a corporate network: a blackholed URL plus
                # the PS 5.1 default of TimeoutSec 0 waits forever.
                $ChildScript = (Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop -TimeoutSec $WebTimeoutSec).Content
            }
            catch {
                throw "Failed to download script from $Url. Error: $($_.Exception.Message)"
            }
        }
        else {
            throw "You must specify either -Encoded, -Url, or -LocalPath."
        }

        if (-not $ChildScript) {
            throw "No content received. Aborting write operation."
        }

        # Write with UTF-8 (no BOM), cross-version compatible
        if ($PSVersionTable.PSEdition -eq 'Core' -or $PSVersionTable.PSVersion.Major -ge 6) {
            $ChildScript | Out-File -FilePath $TargetPath -Encoding utf8NoBOM -Force
        }
        else {
            $Utf8NoBom = New-Object System.Text.UTF8Encoding($False)
            [System.IO.File]::WriteAllText($TargetPath, $ChildScript, $Utf8NoBom)
        }

        Ok "Script written to $TargetPath"
        return $TargetPath
    }
    catch {
        Err "Error in Install-Scripts: $($_.Exception.Message)"
        return $null
    }
}
function Get-KestrelBackendPort {
    <#
    .SYNOPSIS
        Reads the Kestrel HTTP listen port out of a PowerSyncPro appsettings.json.
    .DESCRIPTION
        The reverse proxy has to forward to whatever port PowerSyncPro actually listens on.
        For an installation this script performed that is the -KestrelHttpPort it handed to
        the MSI, but on a hand-installed or upgraded server it can be anything - so the value
        is read back from the application's own configuration rather than assumed.

        The configured URL looks like "http://*:5000". '*' is not a legal URI host, so the
        port is taken with a regular expression rather than by parsing it as a [uri].
    .OUTPUTS
        [int] The discovered port, or $null when it cannot be determined.
    #>
    [CmdletBinding()]
    param(
        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"
    )

    if (-not (Test-Path $AppSettingsPath)) {
        Info "No appsettings.json at $AppSettingsPath - PowerSyncPro does not appear to be installed on this server."
        return $null
    }

    try {
        $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json
    }
    catch {
        Warn "Could not parse ${AppSettingsPath}: $($_.Exception.Message)"
        return $null
    }

    $url = $null
    try {
        if ($json.Kestrel.Endpoints.PSObject.Properties.Name -contains 'Http') {
            $url = $json.Kestrel.Endpoints.Http.Url
        }
    }
    catch {
        # No Kestrel / Endpoints section at all - reported below.
    }

    if ([string]::IsNullOrWhiteSpace($url)) {
        Warn "appsettings.json contains no Kestrel HTTP endpoint URL to read a port from."
        return $null
    }

    $match = [regex]::Match($url, ':(\d{1,5})/?\s*$')
    if (-not $match.Success) {
        Warn ("Could not read a port from the Kestrel HTTP URL '{0}'." -f $url)
        return $null
    }

    $port = [int]$match.Groups[1].Value
    if ($port -lt 1 -or $port -gt 65535) {
        Warn ("The Kestrel HTTP URL '{0}' yielded an out-of-range port." -f $url)
        return $null
    }

    Ok ("Discovered the PowerSyncPro Kestrel HTTP port from appsettings.json: {0}" -f $port)
    return $port
}
function Install-WebConfig {
    param(
        [string]$FrontendHost,
        [string]$TargetFolder,
        [string]$TargetFile,
        [int]$KestrelHttpPort = 5000,

        # Full URL of the reverse-proxy backend. When supplied (e.g. -IISOnly mode with a
        # remote PSP server such as https://psp.corp.local:5001), the rewrite / ARR rules
        # forward here instead of the local Kestrel HTTP port. When omitted, the original
        # local backend of http://localhost:<KestrelHttpPort> is used (on-box install).
        [string]$BackendUrl,

        # Lock down the PSP admin site (used only in -IISOnly / reverse-proxy-only mode).
        # When set, the root <ipSecurity> becomes a full default-deny with NO allowed
        # entries, so the admin site returns 403 for every source INCLUDING localhost.
        # The /Agent (and /.well-known unless -DenyWellKnown) <location> blocks remain
        # reachable. When NOT set, the root ipSecurity keeps the original 127.0.0.1
        # localhost allow (on-box default).
        [switch]$LockAdmin,

        # Remove the <location path=".well-known"> allowUnlisted="true" exception (used only
        # in -IISOnly mode when the cert type is NOT LetsEncrypt). The .well-known exception
        # exists solely for the ACME HTTP-01 challenge, so when ACME is not in use it is an
        # unnecessary hole; removing it lets /.well-known fall under the root default-deny.
        # The /Agent <location> is never affected. When NOT set, the template is emitted
        # unchanged (on-box default always includes .well-known).
        [switch]$DenyWellKnown
    )

    # Build paths
    $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile
    $ForbiddenTargetFolder = Join-Path -Path $TargetFolder -ChildPath "CustomErrors"
    $ForbiddenTarget = Join-Path -Path $ForbiddenTargetFolder -ChildPath "forbidden.html"

    # Construct the Frontend URL
    $FrontendUrl = "https://$FrontendHost/"

    # Resolve the reverse-proxy backend target.
    #  - $BackendBase     is the scheme://host:port used as the inbound rewrite target.
    #  - $BackendHostPort is the host:port used to build the outbound (link-rewrite) match.
    # For the default on-box case this reproduces the original http://localhost:<port>
    # values byte-for-byte; [regex]::Escape leaves the dot-free localhost:<port> unchanged.
    if (-not [string]::IsNullOrWhiteSpace($BackendUrl)) {
        $backendUri      = [uri]$BackendUrl
        $BackendBase     = ("{0}://{1}" -f $backendUri.Scheme, $backendUri.Authority)
        $BackendHostPort = $backendUri.Authority
    }
    else {
        $BackendBase     = "http://localhost:$KestrelHttpPort"
        $BackendHostPort = "localhost:$KestrelHttpPort"
    }
    $BackendMatch = [regex]::Escape($BackendHostPort)

    # Full XML web.config with variable substitution
    $WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <!-- 403 Error Handling -->
    <httpErrors errorMode="Custom" existingResponse="Auto" defaultResponseMode="File">
      <remove statusCode="403" />
      <error statusCode="403"
             path="CustomErrors\forbidden.html"
             responseMode="File" />
    </httpErrors>
    <staticContent>
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <add name="ACMEStaticFile" path="*" verb="GET" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
    </handlers>
    <proxy enabled="true" />
    <security>
      <ipSecurity allowUnlisted="false">
        <add ipAddress="127.0.0.1" subnetMask="255.255.255.255" allowed="true" />
      </ipSecurity>
    </security>
    <rewrite>
      <rules>
        <rule name="RedirectToHTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
            <add input="{REQUEST_URI}" pattern="^/.well-known/" negate="true" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
        <rule name="PowerSyncProReverseProxyInboundRule" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{REQUEST_URI}" pattern="^/.well-known/" negate="true" />
          </conditions>
          <action type="Rewrite" url="$BackendBase/{R:1}" />
        </rule>
      </rules>
      <outboundRules>
        <rule name="PowerSyncProReverseProxyOutboundRule1" preCondition="PowerSyncProResponseIsHtml">
          <match filterByTags="A, Form, Img" pattern="^http(s)?://$BackendMatch/(.*)" />
          <action type="Rewrite" value="$FrontendUrl{R:2}" />
        </rule>
        <preConditions>
          <preCondition name="PowerSyncProResponseIsHtml">
            <add input="{RESPONSE_CONTENT_TYPE}" pattern="^text/html" />
          </preCondition>
        </preConditions>
      </outboundRules>
    </rewrite>
  </system.webServer>
  <location path="Agent">
    <system.webServer>
      <security>
        <ipSecurity allowUnlisted="true" />
      </security>
    </system.webServer>
  </location>
  <location path=".well-known">
    <system.webServer>
      <security>
        <ipSecurity allowUnlisted="true" />
      </security>
    </system.webServer>
  </location>
</configuration>
"@

    $ForbiddenPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@400;700&display=swap" rel="stylesheet">
  <style>
    body {
      margin: 0;
      height: 100vh;
      font-family: 'Source Sans Pro', Arial, sans-serif;
      background-color: #00a8ff;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .error-box {
      background: #ffffff;
      padding: 40px;
      border-radius: 6px;
      width: 360px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.15);
      text-align: center;
    }
    h1 {
      margin: 0 0 15px;
      font-size: 2.5em;
      font-weight: 700;
      color: #e84118;
    }
    h2 {
      margin: 0 0 15px;
      font-size: 1.3em;
      font-weight: 400;
      color: #2f3640;
    }
    p {
      margin: 0;
      font-size: 0.95em;
      line-height: 1.4;
      color: #636e72;
    }
  </style>
</head>
<body>
  <div class="error-box">
    <h1>403</h1>
    <h2>Access Forbidden</h2>
    <p>
      You don't have permission to access this resource.<br>
      This may be expected behavior or an error.<br><br>
      Please review the documentation or contact your support staff for assistance.
    </p>
  </div>
</body>
</html>
"@

    # Ensure target folder exists
    if (-not (Test-Path $TargetFolder)) {
        New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        Info "Created folder $TargetFolder"
    }

    # Ensure CustomErrors folder exists
    if (-not (Test-Path $ForbiddenTargetFolder)) {
        New-Item -Path $ForbiddenTargetFolder -ItemType Directory -Force | Out-Null
        Info "Created folder $ForbiddenTargetFolder"
    }

    # -LockAdmin (reverse-proxy-only): remove the root 127.0.0.1 allow entry so the root
    # <ipSecurity allowUnlisted="false"> becomes a full default-deny with NO allowed
    # entries. The admin site then returns 403 for every source, including localhost. Only
    # the /Agent and /.well-known <location> blocks (which set allowUnlisted="true") stay
    # reachable. This is a surgical, newline-agnostic removal of a single line: the template
    # above is left completely unchanged, so the on-box (switch off) output is byte-for-byte
    # identical to prior versions. The 127.0.0.1 allow appears only in the root block (the
    # <location> blocks use self-closing allowUnlisted="true"), so this targets it uniquely.
    if ($LockAdmin) {
        $WebConfig = $WebConfig -replace '(?m)^[ \t]*<add ipAddress="127\.0\.0\.1" subnetMask="255\.255\.255\.255" allowed="true" />\r?\n', ''
        Info "Reverse-proxy admin lockdown: root ipSecurity set to full default-deny (403 for all sources, including localhost)."
    }

    # -DenyWellKnown (reverse-proxy-only, non-LetsEncrypt cert): remove the entire
    # <location path=".well-known"> allowUnlisted="true" block so /.well-known falls under
    # the root default-deny instead of being publicly reachable. The exception is only
    # needed for the ACME HTTP-01 challenge, so this closes an unnecessary hole for
    # BYOC / SelfSigned. This is a surgical, newline-agnostic removal: the template above is
    # left unchanged, so the on-box (switch off) output stays byte-for-byte identical. The
    # non-greedy match begins at the ".well-known" location, so the earlier /Agent location
    # block (identical structure, different path) is never touched.
    if ($DenyWellKnown) {
        $WebConfig = $WebConfig -replace '(?s)[ \t]*<location path="\.well-known">.*?</location>\r?\n', ''
        Info "Reverse-proxy hardening: /.well-known exception removed (cert type is not LetsEncrypt) - path now falls under the root default-deny."
    }

    # Write web.config
    $WebConfig | Out-File -FilePath $TargetPath -Encoding UTF8 -Force
    Ok "Full web.config written to $TargetPath (frontend $FrontendUrl -> backend $BackendBase)"

    # Write forbidden.html
    $ForbiddenPage | Out-File -FilePath $ForbiddenTarget -Encoding UTF8 -Force
    Ok "Forbidden page template written to $ForbiddenTarget..."
}
function Harden-TlsConfiguration {
    <#
    .SYNOPSIS
        Hardens the server by disabling legacy SSL/TLS protocols and weak ciphers.

    .DESCRIPTION
        - Disables SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1
        - Explicitly enables TLS 1.2 (TLS 1.3 is left at OS defaults; not configured here)
        - Disables weak ciphers (RC4, DES, 3DES, EXPORT, NULL, MD5)
        - Creates required SCHANNEL registry keys if missing
        - Backs up the current SCHANNEL configuration to C:\Temp\SchannelBackup.reg

    .EXAMPLE
        Harden-TlsConfiguration
    #>

    [CmdletBinding()]
    param()

    Info "Starting TLS/SSL hardening..."

    $backupPath = "C:\Temp\SchannelBackup.reg"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory | Out-Null }

    try {
        Info "Backing up current SCHANNEL configuration to $backupPath"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $backupPath /y | Out-Null
    }
    catch {
        Warn "Failed to back up SCHANNEL registry branch. Continuing anyway."
    }

    # Define protocols to disable
    $Protocols = @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1"
    )

    foreach ($proto in $Protocols) {
        $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"
        $clientKey = Join-Path $basePath "Client"
        $serverKey = Join-Path $basePath "Server"

        foreach ($key in @($clientKey, $serverKey)) {
            if (-not (Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
            }
            New-ItemProperty -Path $key -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $key -Name "DisabledByDefault" -PropertyType DWord -Value 1 -Force | Out-Null
        }

        Ok "Disabled $proto protocol"
    }

    # Enable TLS 1.2
    $tls12Paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    )

    foreach ($path in $tls12Paths) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        New-ItemProperty -Path $path -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $path -Name "DisabledByDefault" -PropertyType DWord -Value 0 -Force | Out-Null
    }

    Ok "Ensured TLS 1.2 is enabled."

    # Disable weak ciphers
    $WeakCiphers = @(
        "RC2 128/128", "RC2 40/128", "RC2 56/128",
        "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128",
        "DES 56/56", "3DES 168/168",
        "NULL", "EXP", "MD5"
    )

    foreach ($cipher in $WeakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (-not (Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
        New-ItemProperty -Path $cipherPath -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
        Ok "Disabled weak cipher: $cipher"
    }

    Ok "TLS/SSL hardening complete."
    Info "Reboot the server for changes to take effect."
}
function Initialize-IIS{
  # Unlock IIS Configuration for Static Modules
  # Path to appcmd
  $appcmd = Join-Path $env:SystemRoot "System32\inetsrv\appcmd.exe"

  if (Test-Path $appcmd) {
      Info "Unlocking IIS config sections with appcmd..."

      & $appcmd unlock config /section:system.webServer/handlers
      & $appcmd unlock config /section:system.webServer/modules
      & $appcmd unlock config /section:system.webServer/security/ipSecurity
  }
  else {
      Warn "appcmd.exe not found. IIS may not be installed or management tools missing."
  }

  # Restart IIS
  Info "Restarting IIS..."
  Restart-Service -Name W3SVC -Force
  Ok "IIS Restarted..."
  Ok "IIS Configuration has been sucessfully configured for use with PowerSyncPro."
}
function Install-HostsFile {
    param (
        [string]$FrontendHost,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 2
    )

    $HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
    $HostsEntry = "127.0.0.1`t$FrontendHost"

    # Direct .NET file I/O throughout. Set-Content on the hosts file was seen failing
    # in the field with "Stream was not readable" (security software filtering the
    # hosts file can hand the provider a half-usable handle); File.ReadAllLines /
    # WriteAllLines go through a plain FileStream and sidestep the provider entirely.
    try {
        $HostsContent = [System.IO.File]::ReadAllLines($HostsPath)
    }
    catch {
        Err "Failed to read hosts file: $($_.Exception.Message)"
        return $false
    }

    # Strip out existing entries for this host only. @() is load-bearing: a hosts file
    # with a single line comes back as a STRING, and += on a string concatenates
    # instead of appending an array element - corrupting the file on write.
    $FilteredHosts = @($HostsContent | Where-Object {
        $_ -notmatch "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)"
    })

    # Add new entry only if it isn't already present
    if (-not ($FilteredHosts -match "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)")) {
        $FilteredHosts += $HostsEntry
        Info "Adding hosts entry: $HostsEntry"
    }
    else {
        Warn "Hosts entry already exists: $HostsEntry"
    }

    # A read-only attribute (set by some security tooling) fails every write attempt
    # identically - clear it up front rather than burning the retries on it.
    try {
        $attrs = [System.IO.File]::GetAttributes($HostsPath)
        if ($attrs -band [System.IO.FileAttributes]::ReadOnly) {
            Warn "Hosts file is marked read-only; clearing the attribute."
            [System.IO.File]::SetAttributes($HostsPath, $attrs -bxor [System.IO.FileAttributes]::ReadOnly)
        }
    } catch { }

    # Retry EVERY failure, not just IOException: the field failure ("Stream was not
    # readable") took the old catch-all branch, which broke out of the loop on attempt
    # 1 while still reporting "failed after 3 attempts". Transient interference from
    # AV/EDR filtering is exactly what a retry with backoff is for.
    $success = $false
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            [System.IO.File]::WriteAllLines($HostsPath, [string[]]$FilteredHosts, [System.Text.Encoding]::ASCII)
            Ok "Hosts file updated successfully."
            $success = $true
            break
        }
        catch {
            Warn "Attempt ${i} of ${MaxRetries}: could not write hosts file ($($_.Exception.Message)). Retrying in ${RetryDelaySeconds} second(s)..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    if (-not $success) {
        Warn "Failed to update hosts file after $MaxRetries attempts. Entry not added for $FrontendHost."
        Warn "Add it by hand if needed: $HostsEntry"
        return $false
    }
    return $true
}
# ------------------ Certificate Functions ------------------
function Install-ACMECertificate{
  param(
    [string]$FrontendHost,
    [string]$ContactEmail,
    [int]$KestrelHttpsPort = 5001
  )
  
  # -----------------------------------
  # Install ACME Certificate
  # -----------------------------------

  # Install Posh-ACME
  $ModuleName = "Posh-ACME"

  # Preseed Nuget to ensure user isn't prompted.
  # Ensure NuGet package provider is installed
  try {
      Info "Installing NuGet to install Powershell Modules..."
      Install-PackageProvider -Name NuGet -ForceBootstrap -Force -ErrorAction Stop | Out-Null
      Ok "NuGet provider installed successfully."
  }
  catch {
      Warn "Failed to install NuGet provider: $_"
      exit 1
  }

  # Install the Posh-ACME Module
  Info "Installing Powershell Posh-ACME for certificate request..."
  Install-Module -Name $ModuleName -Force -Scope AllUsers -AllowClobber
  
  # Run Cert-Puller_PoshACME.ps1 with provided options above.
  Info "Beginning certificate request for $FrontendHost with contact e-mail $ContactEmail"
  & C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain $FrontendHost -ContactEmail $ContactEmail -KestrelHttpsPort $KestrelHttpsPort
}
function Get-CertPrivateKeyPath {
    <#
    .SYNOPSIS
        Resolves the on-disk private key file for a certificate.
    .DESCRIPTION
        Handles both key storage generations. Legacy CryptoAPI (CSP) keys live under
        Crypto\RSA\MachineKeys and are named by CspKeyContainerInfo; modern CNG (KSP)
        keys live under Crypto\Keys and are named by the CNG key's UniqueName.
        Enterprise-issued and ACME certificates are usually CNG, so a CAPI-only lookup
        silently fails on them - which is why the ACL step used to be unreliable.
    .OUTPUTS
        [string] Full path to the key file, or $null when it cannot be resolved.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate.HasPrivateKey) {
        Warn "Certificate $($Certificate.Thumbprint) has no associated private key."
        return $null
    }

    $keyPath = $null

    # Legacy CryptoAPI (CSP) container. Touching CspKeyContainerInfo throws on a CNG
    # key, so this is deliberately wrapped and allowed to fall through.
    try {
        $csp = $Certificate.PrivateKey.CspKeyContainerInfo
        if ($csp -and $csp.UniqueKeyContainerName) {
            $candidate = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $csp.UniqueKeyContainerName
            if (Test-Path $candidate) { $keyPath = $candidate }
        }
    }
    catch {
        # Not a CAPI key - handled below.
    }

    # Modern CNG (KSP) container, via the managed API. Locale independent, unlike
    # scraping certutil output.
    if (-not $keyPath) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
            if ($rsa -and $rsa -is [System.Security.Cryptography.RSACng]) {
                $unique = $rsa.Key.UniqueName
                if ($unique) {
                    $candidate = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $unique
                    if (Test-Path $candidate) { $keyPath = $candidate }
                }
            }
        }
        catch {
            # Fall through to the certutil fallback below.
        }
    }

    # Last resort: ask certutil for the container name. Only reached when the managed
    # lookup failed, and it depends on English output, so it is not the primary path.
    if (-not $keyPath) {
        try {
            $line = & certutil.exe -store my $Certificate.Thumbprint 2>$null | Select-String 'Unique container name:'
            if ($line) {
                $name = ($line[0].ToString() -replace '.*:\s*', '').Trim()
                if ($name) {
                    $candidate = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $name
                    if (Test-Path $candidate) { $keyPath = $candidate }
                }
            }
        }
        catch {
            Warn "certutil lookup for the private key container failed: $($_.Exception.Message)"
        }
    }

    if (-not $keyPath) {
        Warn "Could not resolve a private key file for certificate $($Certificate.Thumbprint)."
    }
    return $keyPath
}
function Grant-CertPrivateKeyAccess {
    <#
    .SYNOPSIS
        Grants an account FullControl over a certificate's private key file.
    .OUTPUTS
        [bool] $true when the ACL was applied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$User
    )

    $keyPath = Get-CertPrivateKeyPath -Certificate $Certificate
    if (-not $keyPath) { return $false }

    try {
        $resolved = (New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.NTAccount]).Value
        Info "Applying FullControl on the private key at $keyPath for $resolved"
        $acl  = Get-Acl $keyPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($resolved, "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl
        Ok "Granted FullControl on the private key to $resolved"
        return $true
    }
    catch {
        Warn "Failed to adjust private key permissions for ${User}: $($_.Exception.Message)"
        return $false
    }
}
function Set-PspCertificate {
    <#
    .SYNOPSIS
        Applies a certificate that is already in the LocalMachine store to this server.
    .DESCRIPTION
        Everything that has to happen once a certificate exists: grant the PowerSyncPro
        service account access to the private key, point appsettings.json at it, and bind
        it to the IIS HTTPS site on port 443.

        Shared by every certificate path - BYOC PFX import, self-signed generation, and
        selecting a certificate already present in the store - which previously each
        carried their own near-identical copy of this logic.

        The PowerSyncPro service is restarted ONLY when appsettings.json actually changed,
        so re-running against an already-correct box is not an unannounced outage.
    .PARAMETER RemoveOldSameSubject
        Delete other certificates in the store sharing this subject. Opt-in, because it is
        correct when we just issued or imported a replacement but WRONG when the operator
        picked a certificate they already had - a same-subject sibling may be in use
        elsewhere on the server.
    .PARAMETER SkipAppSettings
        Skip the appsettings.json update entirely, for a reverse-proxy host that has no
        local PowerSyncPro installation.
    .OUTPUTS
        [bool] $true when the certificate was applied successfully.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint,

        # Subject written into appsettings.json. Defaults to the certificate's simple name.
        [string]$SubjectName,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json",

        [int]$KestrelHttpsPort = 5001,

        [switch]$RemoveOldSameSubject,

        [switch]$SkipAppSettings
    )

    try {
        $certPath = Join-Path $StoreLocation $Thumbprint
        if (-not (Test-Path $certPath)) {
            Err "Certificate $Thumbprint was not found in $StoreLocation."
            return $false
        }
        $cert = Get-Item $certPath

        if ([string]::IsNullOrWhiteSpace($SubjectName)) {
            $SubjectName = $cert.GetNameInfo('SimpleName', $false)
        }
        Info "Applying certificate '$SubjectName' (Thumbprint $($cert.Thumbprint))..."

        # --- Optionally prune superseded certificates sharing this subject ---
        if ($RemoveOldSameSubject) {
            Get-ChildItem -Path $StoreLocation | Where-Object {
                ($_.Subject -like "*CN=$SubjectName*") -and ($_.Thumbprint -ne $cert.Thumbprint)
            } | ForEach-Object {
                Info "Removing superseded certificate Thumbprint=$($_.Thumbprint)"
                Remove-Item -Path (Join-Path $StoreLocation $_.Thumbprint) -Force
            }
        }

        # --- Private key ACL for the PowerSyncPro service account ---
        # Read the account off the installed service rather than any -PSPServiceUser flag,
        # so this stays correct for a PowerSyncPro that was installed by hand.
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='PowerSyncPro'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.StartName -and $svc.StartName -ne "LocalSystem") {
            $null = Grant-CertPrivateKeyAccess -Certificate $cert -User $svc.StartName
        }
        elseif ($svc) {
            Info "PowerSyncPro runs as $($svc.StartName) - no private key ACL change required."
        }
        else {
            Info "No local PowerSyncPro service on this host - skipping the private key ACL step."
        }

        # --- appsettings.json (Kestrel HTTPS endpoint) ---
        $appSettingsChanged = $false
        if ($SkipAppSettings) {
            Info "Skipping appsettings.json - no local PowerSyncPro installation on this host."
        }
        elseif (-not (Test-Path $AppSettingsPath)) {
            Warn "appsettings.json not found at $AppSettingsPath - skipping Kestrel certificate configuration."
        }
        else {
            try {
                $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

                if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                    Warn "HTTPS endpoint not found in appsettings.json. Creating one on port $KestrelHttpsPort."
                    $json.Kestrel.Endpoints | Add-Member -MemberType NoteProperty -Name "Https" -Value @{
                        Url         = "https://*:$KestrelHttpsPort"
                        Protocols   = "Http1AndHttp2"
                        Certificate = @{
                            Subject      = $SubjectName
                            Store        = "My"
                            Location     = "LocalMachine"
                            AllowInvalid = $true
                        }
                    }
                    $appSettingsChanged = $true
                    Ok "Created HTTPS endpoint in appsettings.json"
                }
                else {
                    $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                    if ($configuredSubject -ne $SubjectName) {
                        Warn "Configured certificate subject ($configuredSubject) does not match this certificate ($SubjectName). Updating."
                        $json.Kestrel.Endpoints.Https.Certificate.Subject = $SubjectName
                        $appSettingsChanged = $true
                    }
                    else {
                        Info "appsettings.json already matches the current certificate subject."
                    }
                }

                if ($appSettingsChanged) {
                    $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
                    Ok "Updated appsettings.json successfully."
                }
            }
            catch {
                Warn "Failed to update appsettings.json: $($_.Exception.Message)"
            }
        }

        # --- IIS HTTPS binding on port 443 ---
        Import-Module WebAdministration -ErrorAction Stop

        if (-not (Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue)) {
            Info "No HTTPS binding on '$SiteName' - creating one."
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
        }

        $sslBinding = Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue |
                      Where-Object { $_.Port -eq 443 } | Select-Object -First 1
        if ($sslBinding) {
            Info "Updating SSL binding $($sslBinding.PSPath)"
            Set-Item -Path $sslBinding.PSPath -Value $cert -Force
        }
        else {
            Info "Creating SSL binding on 0.0.0.0:443"
            New-Item "IIS:\SslBindings\0.0.0.0!443" -Value $cert -SSLFlags 0 | Out-Null
        }
        Ok "Certificate bound to '$SiteName' on port 443."

        # --- Restart PowerSyncPro only when its configuration actually changed ---
        if ($appSettingsChanged) {
            if (Get-Service -Name "PowerSyncPro" -ErrorAction SilentlyContinue) {
                Restart-Service -Name "PowerSyncPro" -Force
                Ok "Restarted PowerSyncPro service to pick up the new certificate."
            }
        }
        else {
            Info "appsettings.json unchanged - leaving the PowerSyncPro service running."
        }

        return $true
    }
    catch {
        Err "Failed to apply certificate ${Thumbprint}: $($_.Exception.Message)"
        return $false
    }
}
function Install-CustomPfxCertificate {
    <#
    .SYNOPSIS
        Imports a user-provided PFX certificate and applies it to PowerSyncPro + IIS.
    .OUTPUTS
        [bool] $true on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json",

        [int]$KestrelHttpsPort = 5001,

        [switch]$SkipAppSettings
    )

    try {
        Info "Importing PFX from $PfxPath..."
        $imported = Import-PfxCertificate -FilePath $PfxPath `
            -Password $Password `
            -CertStoreLocation $StoreLocation `
            -Exportable

        if (-not $imported) { throw "Failed to import PFX certificate." }

        $newCert = $imported[0]
        Ok "Imported cert: $($newCert.GetNameInfo('SimpleName', $false)) Thumbprint=$($newCert.Thumbprint)"

        # A freshly imported PFX supersedes any earlier certificate for the same subject.
        return Set-PspCertificate -Thumbprint $newCert.Thumbprint `
            -StoreLocation $StoreLocation `
            -SiteName $SiteName `
            -AppSettingsPath $AppSettingsPath `
            -KestrelHttpsPort $KestrelHttpsPort `
            -RemoveOldSameSubject `
            -SkipAppSettings:$SkipAppSettings
    }
    catch {
        Err "Error importing PFX certificate: $($_.Exception.Message)"
        return $false
    }
}
function Install-SelfSignedCertificate {
    <#
    .SYNOPSIS
        Generates a self-signed certificate for a given FQDN and applies it to
        PowerSyncPro + IIS.
    .OUTPUTS
        [bool] $true on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DnsName,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json",

        [int]$KestrelHttpsPort = 5001,

        [switch]$SkipAppSettings
    )

    try {
        Info "Creating self-signed certificate for $DnsName..."

        $newCert = New-SelfSignedCertificate `
            -DnsName $DnsName `
            -CertStoreLocation $StoreLocation `
            -FriendlyName "SelfSigned - $DnsName" `
            -KeyExportPolicy Exportable `
            -KeySpec Signature `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(1) `
            -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")

        if (-not $newCert) { throw "Failed to generate self-signed certificate for $DnsName" }

        Ok "Generated cert: $DnsName Thumbprint=$($newCert.Thumbprint)"

        # A newly generated self-signed cert supersedes any earlier one for the same name.
        return Set-PspCertificate -Thumbprint $newCert.Thumbprint `
            -SubjectName $DnsName `
            -StoreLocation $StoreLocation `
            -SiteName $SiteName `
            -AppSettingsPath $AppSettingsPath `
            -KestrelHttpsPort $KestrelHttpsPort `
            -RemoveOldSameSubject `
            -SkipAppSettings:$SkipAppSettings
    }
    catch {
        Err "Error creating self-signed certificate: $($_.Exception.Message)"
        return $false
    }
}
function Register-CertRenewalScheduledTask {
    <#
    .SYNOPSIS
        Creates or updates a scheduled task to run Cert-Puller_PoshACME.ps1 weekly.

    .DESCRIPTION
        This function registers a scheduled task called 'LetsEncrypt-CertRenewal' that
        runs every Sunday at 3:00 AM as SYSTEM with highest privileges. It points to
        C:\Scripts\Cert-Puller_PoshACME.ps1 and passes required parameters.

    .PARAMETER Domain
        The domain name to renew.

    .PARAMETER ContactEmail
        The email address for Let's Encrypt account registration.

    .PARAMETER DaysBeforeExpiry
        Days before expiry to trigger renewal (default 30).

    .PARAMETER WebRoot
        Path to web server root for HTTP-01 challenge. Default C:\inetpub\wwwroot.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$ContactEmail,

        [int]$DaysBeforeExpiry = 30,

        [string]$WebRoot = "C:\inetpub\wwwroot"
    )

    $taskName = "LetsEncrypt-CertRenewal"
    $scriptPath = "C:\Scripts\Cert-Puller_PoshACME.ps1"

    if (-not (Test-Path $scriptPath)) {
        throw "Script not found at $scriptPath"
    }

    # Build the action with arguments
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Domain `"$Domain`" -ContactEmail `"$ContactEmail`" -DaysBeforeExpiry $DaysBeforeExpiry -WebRoot `"$WebRoot`""

    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force

    Ok "Scheduled task '$taskName' created/updated successfully." -ForegroundColor Green
}
# ------------------ Helper Functions ------------------
function Confirm-YesNo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)

    while ($true) {
        $r = Read-Host "$Message [Y/N]"
        switch ($r.ToUpper()) {
            "Y" { return $true }
            "YES" { return $true }
            "N" { return $false }
            "NO" { return $false }
            default { Warn "Please enter Y or N." }
        }
    }
}
function Get-PfxSubject {
    param (
        [string]$PfxPath,
        [SecureString]$Password
    )

    # Load certificate
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($PfxPath, $Password, 'Exportable,PersistKeySet')

    # Collect DNS names from SAN
    $dnsNames = @()
    foreach ($ext in $cert.Extensions) {
        if ($ext.Oid.FriendlyName -eq "Subject Alternative Name") {
            $entries = $ext.Format($false) -split ',\s*'
            foreach ($entry in $entries) {
                if ($entry -match '^DNS Name=') {
                    $dnsNames += ($entry -replace '^DNS Name=','').Trim().ToLower()
                }
            }
        }
    }

    # If SANs exist, return them
    if ($dnsNames.Count -gt 0) {
        return ,$dnsNames
    }

    # Otherwise return CN fallback
    return ,($cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false).ToLower())
}
function Test-HostnameFormat {
    param([Parameter(Mandatory)][string]$Name)
    return $Name -match '^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
}
function Resolve-CertHostname {
    <#
    .SYNOPSIS
        Picks the FQDN this server will be published under, from a certificate's DNS names.
    .DESCRIPTION
        Shared by every certificate path that reads names off a certificate: a BYOC PFX and
        selecting a certificate already present in the LocalMachine store.

        Three cases:
          - A wildcard name is present. Prompt for a specific host exactly one label under
            the wildcard root and validate it. Several wildcards are offered as a list.
          - Several plain names are present. Let the operator pick which one this server
            answers on; enterprise certificates routinely carry a handful of SANs and
            silently taking the first is a coin flip.
          - Exactly one plain name. Use it without prompting.
    .OUTPUTS
        [PSCustomObject] with Hostname, ChosenWildcard and WildcardValidated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$CertFqdns
    )

    $names = @($CertFqdns |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToLower() } |
        Select-Object -Unique)

    if ($names.Count -eq 0) { throw "The certificate contains no usable DNS names." }

    $wildcards = @($names | Where-Object { $_.StartsWith('*.') })
    $plain     = @($names | Where-Object { -not $_.StartsWith('*.') })

    $ChosenWildcard = $null

    if ($wildcards.Count -gt 1) {
        Warn "Multiple wildcard domains detected:"
        for ($i = 0; $i -lt $wildcards.Count; $i++) {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $wildcards[$i])
        }
        while ($true) {
            $choice = Read-Host ("Select which wildcard root to use (1-{0})" -f $wildcards.Count)
            if ([int]::TryParse($choice, [ref]$null) -and [int]$choice -ge 1 -and [int]$choice -le $wildcards.Count) {
                $ChosenWildcard = $wildcards[[int]$choice - 1]
                break
            }
            Warn ("Invalid choice. Please enter a number between 1 and {0}." -f $wildcards.Count)
        }
    }
    elseif ($wildcards.Count -eq 1) {
        $ChosenWildcard = $wildcards[0]
    }

    # A wildcard applies, so the operator has to name the specific host it covers.
    if ($ChosenWildcard) {
        $wildRoot = $ChosenWildcard.Substring(2)
        Warn ("Detected wildcard certificate for: {0}" -f $wildRoot)
        while ($true) {
            $entered = Read-Host ("Enter the specific FQDN for this host (must be exactly one label under {0}, e.g. host.{0})" -f $wildRoot)
            if ([string]::IsNullOrWhiteSpace($entered)) { Warn "Hostname cannot be empty."; continue }
            $entered = $entered.Trim()
            if (-not (Test-HostnameFormat -Name $entered)) { Warn "Invalid hostname format. Please enter a valid FQDN."; continue }

            $hostLabels = ($entered -split '\.').Count
            $rootLabels = ($wildRoot -split '\.').Count
            $endsOk     = $entered.ToLower().EndsWith("." + $wildRoot.ToLower())
            $oneLevel   = ($hostLabels -eq ($rootLabels + 1))

            if ($endsOk -and $oneLevel) {
                Ok ("Hostname {0} is valid for wildcard {1}" -f $entered, $ChosenWildcard)
                return [PSCustomObject]@{
                    Hostname          = $entered
                    ChosenWildcard    = $ChosenWildcard
                    WildcardValidated = $true
                }
            }
            Warn ("{0} is not valid for wildcard {1}. Must add exactly one label under {2}." -f $entered, $ChosenWildcard, $wildRoot)
        }
    }

    if ($plain.Count -eq 1) {
        Info ("Using the certificate's only DNS name: {0}" -f $plain[0])
        return [PSCustomObject]@{
            Hostname          = $plain[0]
            ChosenWildcard    = $null
            WildcardValidated = $false
        }
    }

    Write-Host ""
    Write-Host "This certificate carries several DNS names. Select the one this server will be published under:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $plain.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $plain[$i])
    }
    while ($true) {
        $choice = Read-Host ("Select 1-{0}" -f $plain.Count)
        if ([int]::TryParse($choice, [ref]$null) -and [int]$choice -ge 1 -and [int]$choice -le $plain.Count) {
            $selected = $plain[[int]$choice - 1]
            Ok ("Using hostname {0}" -f $selected)
            return [PSCustomObject]@{
                Hostname          = $selected
                ChosenWildcard    = $null
                WildcardValidated = $false
            }
        }
        Warn ("Invalid choice. Please enter a number between 1 and {0}." -f $plain.Count)
    }
}
function Test-IsPublicIPv4 {
    param([Parameter(Mandatory)][string]$IP)
    if ($IP -notmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $false }
    $o = $IP.Split('.').ForEach({ [int]$_ })
    if ($o[0] -eq 10) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 127) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }
    if ($o[0] -eq 198 -and $o[1] -ge 18 -and $o[1] -le 19) { return $false }
    if ($o[0] -ge 224) { return $false }
    return $true
}
function Resolve-IPv4A {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$DnsServers = @('1.1.1.1','8.8.8.8','9.9.9.9'),
        [switch]$PublicOnly
    )
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($srv in $DnsServers) {
        try {
            $rs = Resolve-DnsName -Name $Name -Type A -Server $srv -ErrorAction Stop
            foreach ($rec in ($rs | Where-Object { $_.IPAddress })) {
                if ($rec.IPAddress -and ($ips -notcontains $rec.IPAddress)) {
                    $ips.Add($rec.IPAddress)
                }
            }
        } catch {}
    }
    $result = $ips.ToArray()
    if ($PublicOnly) {
        $result = $result | Where-Object { Test-IsPublicIPv4 $_ }
    }
    return $result
}
function Get-PublicIPv4 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    $endpoints = @(
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://ipinfo.io/ip'
    )
    foreach ($u in $endpoints) {
        try {
            $ip = (Invoke-RestMethod -Uri $u -Method GET -TimeoutSec 5).ToString().Trim()
            if ($ip -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $ip }
        } catch {}
    }
    throw "Unable to determine public IPv4 from external services."
}
function Test-PortExternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        # FQDN or IP address to check externally
        [string]$TargetHost
    )
    # NOTE: the temporary firewall rule below is intentionally hardcoded to port 80.
    # This function is only ever used to verify the LetsEncrypt HTTP-01 challenge
    # path (port 80), so the temp listener/rule are always for 80 by design.

    $result = [PSCustomObject]@{
        Port          = $Port
        TargetHost    = $TargetHost
        LocalListener = $false
        ExternalCheck = $null
        IsOpen        = $false
        Provider      = $null
    }

    $tcpListener   = $null
    $listenerBound = $false

    if (-not $result.TargetHost) {
        try {
            $pub = Get-PublicIPv4
            if ($pub) { $result.TargetHost = $pub }
        } catch { }
    }

    try {
        # Step 1: Detect existing listener
        $localListener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($localListener) {
            Info "Detected an existing listener on port $Port. Skipping local bind test."
            $listenerBound = $true
            $result.LocalListener = $true
        }
        else {
            try {
                $tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
                $tcpListener.Start()
                Info "Temporary listener started on port $Port."
                # Add Firewall Rule to Allow Port 80
                Add-FirewallRuleForPort -Port 80
                
            } catch {
                Warn "Failed to start temporary listener on port $Port`: $($_.Exception.Message)"
            }
        }

        # Step 2: External checks
        $open = $false
        $why  = $null

        # ---- Provider 1: PortChecker.io
        try {
            $pcUri   = 'https://portchecker.io/api/v1/query'
            $payload = @{ host = $result.TargetHost; ports = @($Port) } | ConvertTo-Json -Depth 3

            $resp = Invoke-RestMethod -Method Post -Uri $pcUri -ContentType 'application/json' -Body $payload -TimeoutSec 12

            if ($resp.check -and $resp.check[0].status -eq $true) {
                $open = $true; $why = 'Open (PortChecker.io)'
            }
            elseif ($resp.check -and $resp.check[0].status -eq $false) {
                $open = $false; $why = 'Closed (PortChecker.io)'
            }
            else {
                throw "Unrecognized PortChecker.io response"
            }
        } catch {
            Warn "DEBUG: PortChecker.io failed -> $($_.Exception.Message)"
        }

        # ---- Provider 2: CanYouSeeMe.org fallback
        if (-not $why) {
            try {
                $resp = Invoke-WebRequest -Uri "http://canyouseeme.org/" -Method Post -Body @{ serviceport = $Port } -UseBasicParsing -TimeoutSec 12
                $content = $resp.Content

                if ($content -match "Success") {
                    $open = $true;  $why = 'Open (CanYouSeeMe)'
                }
                elseif ($content -match "Error") {
                    $open = $false; $why = 'Closed (CanYouSeeMe)'
                }
                else {
                    $why = 'Unknown (CanYouSeeMe parse failed)'
                }
            } catch {
                Warn "DEBUG: CanYouSeeMe failed -> $($_.Exception.Message)"
                $why = 'External check failed (all providers)'
            }
        }

        $result.IsOpen        = $open
        $result.ExternalCheck = $why

        if ($why -match 'PortChecker') {
            $result.Provider = 'PortChecker.io'
        }
        elseif ($why -match 'CanYouSeeMe') {
            $result.Provider = 'CanYouSeeMe.org'
        }
        else {
            $result.Provider = 'Unknown'
        }
    }
    finally {
        if ($null -ne $tcpListener -and -not $listenerBound) {
            $tcpListener.Stop()
            Info "Temporary listener stopped on port $Port." -ForegroundColor Cyan
            # Remove Firewall Rule
            Remove-FirewallRuleForPort -Port 80
        }
    }

    return $result
}
function Add-FirewallRuleForPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [string]$RuleName = ""
    )

    if (-not $RuleName -or $RuleName -eq "") {
        $RuleName = "Allow Port $Port TCP"
    }

    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Info "Firewall rule '$RuleName' already exists."
    }
    else {
        New-NetFirewallRule -DisplayName $RuleName `
                            -Direction Inbound `
                            -LocalPort $Port `
                            -Protocol TCP `
                            -Action Allow `
                            -Profile Domain,Private,Public | Out-Null
        Ok "Firewall rule '$RuleName' created to allow inbound TCP/$Port."
    }
}
function Remove-FirewallRuleForPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [string]$RuleName = ""
    )

    if (-not $RuleName -or $RuleName -eq "") {
        $RuleName = "Allow Port $Port TCP"
    }

    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $RuleName
        Ok "Firewall rule '$RuleName' removed."
    }
    else {
        Warn "Firewall rule '$RuleName' not found."
    }
}
function Test-IsServer2016OrNewer {
    <#
    .SYNOPSIS
        Checks if the machine is running Windows Server 2016 or later.
    .DESCRIPTION
        Returns $true only if the OS is a Windows Server edition AND the version
        is 10.0 build 14393 (Server 2016) or newer.
        Prints the detected OS version before returning.
    #>
    try {
        $os = Get-CimInstance Win32_OperatingSystem

        # Display what we detected
        Info "Detected OS: $($os.Caption) ($($os.Version) Build $($os.BuildNumber))"

        # Workstation (desktop OS) - always false
        if ($os.ProductType -eq 1) {
            return $false
        }

        # Parse version
        $version = [version]$os.Version

        # Windows Server 2016 is version 10.0, build 14393+
        if ($version.Major -gt 10) {
            return $true
        }
        elseif ($version.Major -eq 10 -and $version.Build -ge 14393) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        Warn "Failed to detect OS version: $($_.Exception.Message)"
        return $false
    }
}
function Get-ListeningPort {
    <#
    .SYNOPSIS
        Returns all listening TCP/UDP ports and their associated processes.
        If PID 4 (System) is found, identifies which IIS site(s) use that port.

    .PARAMETER Port
        One or more port numbers to check (e.g. -Port 80,443,5001).

    .PARAMETER Protocol
        The protocol type: TCP or UDP (default: TCP).

    .PARAMETER All
        When set, lists all listening ports (IPv4 only).

    .EXAMPLE
        Get-ListeningPort -Port 80,443,5001
    .EXAMPLE
        Get-ListeningPort -All | Export-Csv C:\Temp\Ports.csv -NoTypeInformation
    #>

    [CmdletBinding(DefaultParameterSetName='ByPort')]
    param(
        [Parameter(ParameterSetName='ByPort', Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int[]]$Port,

        [Parameter(ParameterSetName='ByPort')]
        [Parameter(ParameterSetName='AllPorts')]
        [ValidateSet('TCP','UDP')]
        [string]$Protocol = 'TCP',

        [Parameter(ParameterSetName='AllPorts')]
        [switch]$All
    )

    try {
        $netstatOutput = netstat -ano | Select-String "LISTENING"
        $listeners = $netstatOutput | Where-Object { $_ -match "^\s*$Protocol" }

        if (-not $listeners) {
            Write-Verbose "No $Protocol listeners found."
            return @()
        }

        # Build IIS site --> port map (if available)
        $iisMap = @{}
        try {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            Get-Website | ForEach-Object {
                $siteName = $_.Name
                $_.Bindings.Collection | ForEach-Object {
                    $bind = $_.bindingInformation
                    if ($bind -match ":(\d+):?") {
                        $portNum = [int]$matches[1]
                        if (-not $iisMap.ContainsKey($portNum)) { $iisMap[$portNum] = @() }
                        $iisMap[$portNum] += $siteName
                    }
                }
            }
        }
        catch { }

        # Determine which ports to scan
        $targetPorts = if ($All) {
            ($listeners | ForEach-Object {
                if ($_ -match ":(\d+)\s") { [int]$matches[1] }
            } | Sort-Object -Unique)
        }
        else { $Port }

        $results = @()

        foreach ($p in $targetPorts) {
            $portMatches = $listeners | Where-Object { $_ -match "[:.]$p\s" }
            if (-not $portMatches) {
                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $null
                    State     = 'Not Listening'
                    ProcId    = $null
                    Process   = $null
                    IISSite   = $null
                }
                continue
            }

            foreach ($line in $portMatches) {
                $parts = $line -split '\s+' | Where-Object { $_ -ne '' }

                # Skip IPv6 (anything in [brackets])
                if ($parts[1] -match '^\[.+\]:\d+$') { continue }

                $procId = $parts[-1]
                $process = Get-Process -Id $procId -ErrorAction SilentlyContinue
                $iisSite = if ($procId -eq 4 -and $iisMap.ContainsKey($p)) {
                    ($iisMap[$p] -join ', ')
                } else { $null }

                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $parts[1]
                    State     = 'LISTENING'
                    ProcId    = $procId
                    Process   = if ($process) { $process.ProcessName } else { 'Unknown' }
                    IISSite   = $iisSite
                }
            }
        }

        return $results
    }
    catch {
        Warn "Error checking port usage: $_"
        return @()
    }
}
function Add-ServiceDependency {
    <#
    .SYNOPSIS
        Safely adds one or more dependencies to a Windows service using sc.exe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string[]]$DependsOn
    )

    # Ensure elevated
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Please run this in an elevated PowerShell session." }

    # Confirm target service exists
    $null = Get-Service -Name $ServiceName -ErrorAction Stop

    # --- Gather existing dependencies (CIM first, then registry)
    $existing = @()
    try {
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($cim.PSObject.Properties.Name -contains 'Dependencies' -and $cim.Dependencies) {
            $existing = @($cim.Dependencies)
        }
    } catch {}

    if (-not $existing) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        try {
            $regVal = (Get-ItemProperty -Path $svcPath -Name DependOnService -ErrorAction SilentlyContinue).DependOnService
            if ($regVal) { $existing = @($regVal) }
        } catch {}
    }

    # --- Merge, remove blanks and duplicates (force array form)
    $newList = @(@($existing) + @($DependsOn)) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    $newList = @($newList)

    # --- Build dependency string (slash-separated)
    $depString   = if ($newList.Count -gt 0) { ($newList -join '/') } else { '' }
    $displayList = if ($depString) { $depString } else { '<none>' }

    # --- Status output
    Info "Updating Service Dependencies for $ServiceName to include $DependsOn"

    # --- Apply via sc.exe (always perform update)
    $args = @('config', $ServiceName, "depend= $depString")
    $p = Start-Process -FilePath sc.exe -ArgumentList $args -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "sc.exe failed with exit code $($p.ExitCode)." }

    Info "After update:"
    sc.exe qc $ServiceName
}
function Test-SqlInstanceService {
    <#
    .SYNOPSIS
        Checks whether a specific SQL Server instance exists as a Windows service.
    .DESCRIPTION
        Given an instance name (e.g. "SQLEXPRESS" or "MSSQLSERVER"), this function looks
        for the corresponding Windows service (MSSQL$InstanceName or MSSQLSERVER).
        Returns the service object if found, or $null otherwise.
    .PARAMETER InstanceName
        The SQL instance name. For default instances, use "MSSQLSERVER".
    .OUTPUTS
        System.ServiceProcess.ServiceController or $null
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstanceName
    )

    # Default instance uses MSSQLSERVER (no $)
    $ServiceName = if ($InstanceName -eq "MSSQLSERVER") {
        "MSSQLSERVER"
    } else {
        "MSSQL`$$InstanceName"
    }

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            Info "Found SQL instance service: $($service.DisplayName) (Status: $($service.Status))"
            return $service
        }
        else {
            Warn "SQL instance '$InstanceName' service not found."
            return $null
        }
    }
    catch {
        Err "Error checking for SQL instance '$InstanceName': $($_.Exception.Message)"
        return $null
    }
}
function Select-SqlTarget {
    <#
    # Updated to handle External Logic to collect information for external servers when in CompletionOnly Mode
    .SYNOPSIS
        Presents detected local SQL Server instances and allows the user to select
        a target for the PowerSyncPro database, including support for external SQL servers
        and optional SQL Express installation.

    .DESCRIPTION
        This function displays all SQL Server instances discovered on the local system
        using Get-LocalSqlInstances and prompts the user to select where the PowerSyncPro
        database should be hosted.

        When running in normal installation mode, the user may choose:
        - An existing local SQL Server instance
        - A new SQL Express instance to be installed
        - An external SQL Server

        When running in CompletionOnly mode, installation of new SQL Express instances
        is disabled and only existing local instances or an external SQL Server may be selected.

        The function returns an object describing the selected mode, instance details,
        and whether an external SQL server is in use.

    .OUTPUTS
        PSCustomObject with properties:
        - Mode (Existing, External, InstallExpress)
        - Instance (when applicable)
        - NewInstanceName (when applicable)
        - ExternalServerInUse (Boolean)

    .NOTES
        Designed for use in PowerSyncPro installation and recovery workflows.
        Compatible with Windows PowerShell 5.1 and uses ASCII-only characters.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Instances,

        [bool]$CompletionOnly = $false,
        [bool]$PreReqOnly = $false
    )

    $Instances = @($Instances)

    Info "Detected local SQL instances:"

    if ($Instances.Count -eq 0) {
        Warn "No local SQL instances were detected."
    }
    else {
        for ($i = 0; $i -lt $Instances.Count; $i++) {
            $inst = $Instances[$i]

            $typeText    = if ($inst.IsExpress) { "Express" } else { "Full" }
            $versionText = if ([string]::IsNullOrWhiteSpace($inst.Version)) { "Unknown" } else { $inst.Version }

            Write-Host ("[{0}] {1} ({2}) Version: {3}" -f ($i + 1), $inst.Instance, $typeText, $versionText) -ForegroundColor Gray
        }
    }

    $nextOption = $Instances.Count + 1

    $optExternal = $null
    $optInstall  = $null

    # External SQL only appears in CompletionOnly mode
    if ($CompletionOnly) {
        $optExternal = $nextOption
        Write-Host ("[{0}] PowerSyncPro is using an EXTERNAL SQL Server" -f $optExternal) -ForegroundColor Gray
        $nextOption++
    }

    # SQL Express install only appears in normal install mode
    if (-not $CompletionOnly) {
        $optInstall = $nextOption
        Write-Host ("[{0}] Install a NEW SQL Express instance" -f $optInstall) -ForegroundColor Gray
        if (-not $PreReqOnly ) {
            Warn "IMPORTANT: The account running this installer must have permission to create databases on the chosen instance."
        }
        else {
            Warn "Script Running PreReq Only Mode: Please select the database you plan to use, or install a new copy of SQL Express."
        }
        $nextOption++
    }

    while ($true) {
        $choice = Read-Host ("Select an option [1-{0}]" -f ($nextOption - 1))

        $n = 0
        if ([int]::TryParse($choice, [ref]$n)) {

            # Existing local instance
            if ($n -ge 1 -and $n -le $Instances.Count) {
                return [PSCustomObject]@{
                    Mode               = "Existing"
                    Instance           = $Instances[$n - 1]
                    InstanceName       = $Instances[$n -1].Instance
                    ExternalServerInUse = $false
                }
            }

            # External SQL Server
            if ($n -eq $optExternal) {
                return [PSCustomObject]@{
                    Mode               = "External"
                    Instance           = $null
                    ExternalServerInUse = $true
                }
            }

            # Install SQL Express
            if (-not $CompletionOnly -and $n -eq $optInstall) {
                $newName = Read-InstanceName -Default "SQLEXPRESS"
                return [PSCustomObject]@{
                    Mode               = "InstallExpress"
                    NewInstanceName    = $newName
                    Instance           = $null
                    ExternalServerInUse = $false
                }
            }
        }

        Warn "Invalid selection."
    }
}
function Get-LocalSqlInstances {
    [CmdletBinding()]
    param()

    $keyPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    )

    $all = @()

    foreach ($keyPath in $keyPaths) {
        if (-not (Test-Path $keyPath)) { continue }

        $instanceMap = Get-ItemProperty $keyPath
        foreach ($prop in $instanceMap.PSObject.Properties) {

            $psMetaProps = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
            if ($psMetaProps -contains $prop.Name) { continue }

            $instanceName = $prop.Name
            $instanceId   = $prop.Value

            $setupKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\Setup"
            $edition  = $null
            $version  = $null

            if (Test-Path $setupKey) {
                $setup = Get-ItemProperty $setupKey -ErrorAction SilentlyContinue
                if ($setup) {
                    $edition = $setup.Edition
                    $version = $setup.Version
                }
            }

            $isExpress = $false
            if ($edition -and ($edition -match "Express")) { $isExpress = $true }

            $all += [PSCustomObject]@{
                Instance  = $instanceName
                Edition   = $edition
                Version   = $version
                IsExpress = $isExpress
            }
        }
    }

    $all | Sort-Object Instance -Unique
}
function Read-InstanceName {
    [CmdletBinding()]
    param(
        [string]$Prompt  = "Enter new SQL Express instance name",
        [string]$Default = "SQLEXPRESS"
    )

    while ($true) {
        $name = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $Default }

        # letters/numbers/underscore only (safe for service names, etc.)
        if ($name -match '^[A-Za-z0-9_]+$') { return $name }

        Warn "Invalid instance name. Use letters, numbers, and underscore only."
    }
}
function New-LocalSqlAdminsGroup {
    param(
        [Parameter(Mandatory = $false)]
        [string]$GroupName = "SQL_Admins",

        [Parameter(Mandatory = $true)]
        [string]$ServiceUser
    )

    Info "Creating or updating local group '$GroupName'..."

    # --- Ensure the group exists ---
    if (-not (Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $GroupName -Description "SQL Setup Admins (created by installer)" | Out-Null
        Ok "Created group '$GroupName'."
    }
    else {
        Info "Group '$GroupName' already exists."
    }

    # --- Add local Administrators group ---
    try {
        Add-LocalGroupMember -Group $GroupName -Member "Administrators" -ErrorAction Stop
        Ok "Added local Administrators to $GroupName."
    }
    catch {
        Warn "Local Administrators already part of $GroupName or could not be added."
    }

    # --- Add custom service account ---
    try {
        Add-LocalGroupMember -Group $GroupName -Member $ServiceUser -ErrorAction Stop
        Ok "Added $ServiceUser to $GroupName."
    }
    catch {
        Warn "Service account $ServiceUser already part of $GroupName or could not be added."
    }
    return $GroupName
}
function Test-AndFixCertPermissions {
    <#
    .SYNOPSIS
        Verifies and, if necessary, fixes private key ACLs for a given domain certificate.
    .DESCRIPTION
        Finds the most recent certificate matching the domain in the LocalMachine store and
        grants the specified user FullControl over its private key. Key location and ACL
        work are delegated to Get-CertPrivateKeyPath / Grant-CertPrivateKeyAccess, which
        handle both modern CNG and legacy CSP keys.
    .PARAMETER Domain
        The CN or DNS name of the certificate.
    .PARAMETER User
        The account to grant FullControl to (e.g., 'PSP-MISSOURI\pspsvc').
    .PARAMETER StoreLocation
        The certificate store location. Default: Cert:\LocalMachine\My
    .OUTPUTS
        [bool] $true when the ACL was applied.
    #>
    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$User,
        [string]$StoreLocation = "Cert:\LocalMachine\My"
    )

    try {
        # Locate the most recent certificate for this domain (issuer agnostic).
        $cert = Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$Domain*" -or $_.DnsNameList -contains $Domain)
        } | Sort-Object NotAfter -Descending | Select-Object -First 1

        if (-not $cert) {
            Warn "No certificate found for $Domain in $StoreLocation."
            return $false
        }

        Info "Found certificate for $Domain (Thumbprint: $($cert.Thumbprint))"
        return (Grant-CertPrivateKeyAccess -Certificate $cert -User $User)
    }
    catch {
        Err "Error fixing private key permissions for ${Domain}: $($_.Exception.Message)"
        return $false
    }
}
function Test-UserCredential {
    <#
    .SYNOPSIS
        Tests whether a given username and password are valid credentials.
    #>

    param (
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$ComputerName
    )

    # Try to load the required .NET assembly
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    }
    catch {
        Err "[!] Could not load required .NET assembly: System.DirectoryServices.AccountManagement"
        return $false
    }

    try {
        # Parse username
        if ($Username -match '^(?<Domain>[^\\]+)\\(?<User>.+)$') {
            $Domain = $Matches.Domain
            $User   = $Matches.User
            $ContextType = if ($Domain -eq $env:COMPUTERNAME -or $Domain -eq '.') { 'Machine' } else { 'Domain' }
        } else {
            $Domain = $env:COMPUTERNAME
            $User   = $Username
            $ContextType = 'Machine'
        }

        $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $Domain)
        $isValid = $context.ValidateCredentials($User, $Password)
    }
    catch {
        Warn "Failed to validate via PrincipalContext: $($_.Exception.Message)"
        $isValid = $false
    }

    if ($isValid) {
        Ok "Credentials are valid."
        $true
    } else {
        Err "Invalid username or password."
        $false
    }
}
function Get-BoundCertificateThumbprint {
    <#
    .SYNOPSIS
        Returns the thumbprint of the certificate currently bound to an HTTPS port.
    .DESCRIPTION
        Prefers the IIS SslBindings provider and falls back to 'netsh http show sslcert',
        so this still answers on a server where the WebAdministration module is missing.
    .OUTPUTS
        [string] Uppercase thumbprint, or $null when nothing is bound to the port.
    #>
    [CmdletBinding()]
    param(
        [int]$Port = 443
    )

    try {
        Import-Module WebAdministration -ErrorAction Stop
        $binding = Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue |
                   Where-Object { $_.Port -eq $Port } | Select-Object -First 1
        if ($binding -and $binding.Thumbprint) {
            return $binding.Thumbprint.ToUpper()
        }
    }
    catch {
        # WebAdministration unavailable - fall through to netsh.
    }

    # netsh lists EVERY HTTP.SYS SSL binding, not just port 443, so its output has to be
    # walked as records rather than scanned for the first certificate hash. A typical
    # server has WinRM over HTTPS bound on 5986 with a self-signed 'localhost' certificate;
    # taking the first hash would offer that as "the certificate already serving HTTPS"
    # and pre-select it, which is how an operator ends up binding a localhost certificate
    # to their PowerSyncPro site by pressing Enter.
    try {
        $lines = & netsh.exe http show sslcert 2>$null
        $currentPort = $null
        foreach ($line in $lines) {
            if ($line -match '^\s*(?:IP:port|Hostname:port)\s*:\s*(\S+)\s*$') {
                # Binding looks like 0.0.0.0:443, [::]:443 or hostname:443 - the port is
                # whatever follows the final colon.
                $currentPort = ($Matches[1] -split ':')[-1]
                continue
            }
            if ($line -match '^\s*Certificate Hash\s*:\s*([0-9a-fA-F]+)') {
                if ($currentPort -eq [string]$Port) {
                    return $Matches[1].ToUpper()
                }
            }
        }
    }
    catch {
        # Nothing bound, or netsh output not in a form we recognise.
    }

    return $null
}
function Select-ExistingCertificate {
    <#
    .SYNOPSIS
        Lets the operator choose a certificate already installed on this server.
    .DESCRIPTION
        Lists usable server certificates from the LocalMachine store: one that has a private
        key, is inside its validity period, and is valid for Server Authentication. Anything
        that cannot terminate TLS is filtered out rather than offered and failing later.

        The certificate already bound to port 443 is listed first and is the default, since
        on a server that is already serving HTTPS that is nearly always the one wanted.

        This exists for operators who installed a certificate by hand and no longer have the
        original PFX, which is common on servers that have been running for a while.
    .OUTPUTS
        [X509Certificate2] The chosen certificate, or $null when there are none to offer or
        the operator backed out.
    #>
    [CmdletBinding()]
    param(
        [string]$StoreLocation = "Cert:\LocalMachine\My"
    )

    $now           = Get-Date
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ekuOid        = '2.5.29.37'

    $candidates = @(Get-ChildItem -Path $StoreLocation -ErrorAction SilentlyContinue |
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt $now -and $_.NotBefore -le $now } |
        Where-Object {
            # A certificate with no EKU extension is unrestricted; otherwise Server
            # Authentication has to be present or it cannot serve HTTPS.
            $eku = @($_.Extensions | Where-Object { $_.Oid.Value -eq $ekuOid })
            ($eku.Count -eq 0) -or
            (@($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $serverAuthOid }).Count -gt 0)
        } |
        Sort-Object NotAfter -Descending)

    if ($candidates.Count -eq 0) {
        Warn "No usable certificates were found in $StoreLocation."
        Warn "A certificate must have a private key, be within its validity period, and permit Server Authentication."
        return $null
    }

    # Float the certificate already serving HTTPS to the top so it can be the default.
    $boundThumb = Get-BoundCertificateThumbprint -Port 443
    if ($boundThumb) {
        $bound  = @($candidates | Where-Object { $_.Thumbprint.ToUpper() -eq $boundThumb })
        $others = @($candidates | Where-Object { $_.Thumbprint.ToUpper() -ne $boundThumb })
        $candidates = @($bound) + @($others)
    }

    Write-Host ""
    Write-Host "Certificates already installed on this server:" -ForegroundColor Cyan
    Write-Host ""
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        $c     = $candidates[$i]
        $names = (@($c.DnsNameList | ForEach-Object { $_.Unicode }) -join ', ')
        if ([string]::IsNullOrWhiteSpace($names)) { $names = $c.GetNameInfo('SimpleName', $false) }

        $isBound = ($boundThumb -and $c.Thumbprint.ToUpper() -eq $boundThumb)
        if ($isBound) {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $names) -ForegroundColor Green
            Write-Host "      Currently bound to port 443 on this server." -ForegroundColor Green
        }
        else {
            Write-Host ("  [{0}] {1}" -f ($i + 1), $names)
        }
        Write-Host ("      Issuer  : {0}" -f $c.Issuer)
        Write-Host ("      Expires : {0:yyyy-MM-dd}    Thumbprint: {1}" -f $c.NotAfter, $c.Thumbprint)
        Write-Host ""
    }

    $defaultIsBound = ($boundThumb -and $candidates[0].Thumbprint.ToUpper() -eq $boundThumb)
    if ($defaultIsBound) {
        Write-Host "  (Press Enter for [1], the certificate already serving HTTPS here. Type Q to go back.)"
    }
    else {
        Write-Host "  (Press Enter for [1], the certificate with the latest expiry. Type Q to go back.)"
    }
    Write-Host ""

    while ($true) {
        $choice = Read-Host ("Select 1-{0}, or Q to go back" -f $candidates.Count)
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' } else { $choice = $choice.Trim() }

        if ($choice -match '^(q|quit|exit)$') { return $null }

        if ([int]::TryParse($choice, [ref]$null) -and [int]$choice -ge 1 -and [int]$choice -le $candidates.Count) {
            $selected = $candidates[[int]$choice - 1]
            Ok ("Selected certificate {0} (expires {1:yyyy-MM-dd})" -f $selected.Thumbprint, $selected.NotAfter)
            return $selected
        }
        Warn ("Invalid choice. Enter a number between 1 and {0}, or Q." -f $candidates.Count)
    }
}
# ------------------ Menu & UI ------------------
function Show-CertificateTypeMenu {
    Clear-Host 2>$null
    Write-Host $asciiLogo -ForegroundColor Cyan
    Write-Host "PowerSyncPro Automated Installation Script - $scriptVer"
    Write-Host ""
    Write-Host "Which type of certificate would you like to use for this installation?" -ForegroundColor Cyan
    Write-Host ""

    # LetsEncrypt needs internet access and public DNS, so it is unavailable for an
    # offline / air-gapped install. Every other option works without a network.
    $offline = ($script:OfflineMode -eq 'Install')

    $options = @()
    if (-not $offline) {
        $options += @{ Key = '1'; Name = 'LetsEncrypt'; Desc = 'ACME via DNS Verification' }
    }
    $options += @{ Key = '2'; Name = 'BYOC';       Desc = 'Bring Your Own Certificate (PFX with Private Keys Required)' }
    $options += @{ Key = '3'; Name = 'SelfSigned'; Desc = 'Generate a Self-Signed Certificate (May cause loss of functionality)' }
    $options += @{ Key = '4'; Name = 'Existing';   Desc = 'Use a certificate already installed on this server (no PFX needed)' }

    if ($offline) {
        Write-Host "  (Offline install: LetsEncrypt is unavailable without internet access.)" -ForegroundColor Yellow
        Write-Host ""
    }
    foreach ($o in $options) {
        Write-Host ("  [{0}] {1} - {2}" -f $o.Key, $o.Name, $o.Desc)
    }
    Write-Host ""
    if ($offline) {
        Write-Host "  (Press Enter for default: 2 = BYOC; or type the name. Type Q to quit.)"
    } else {
        Write-Host "  (Press Enter for default: 1 = LetsEncrypt; or type the name, e.g., 'byoc'. Type Q to quit.)"
    }
    Write-Host ""

    while ($true) {
        if ($offline) { $prompt = "Select 2-4, name, or Q" } else { $prompt = "Select 1-4, name, or Q" }
        $raw = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($raw)) {
            if ($offline) { $raw = '2' } else { $raw = '1' }
        } else {
            $raw = $raw.Trim()
        }
        switch -regex ($raw) {
            '^(1|letsencrypt)$' {
                if ($offline) {
                    Write-Host "LetsEncrypt is not available for an offline install. Choose BYOC, SelfSigned or Existing." -ForegroundColor Yellow
                    continue
                }
                return 'LetsEncrypt'
            }
            '^(2|byoc|bring.*)$' { return 'BYOC' }
            '^(3|self.*)$' { return 'SelfSigned' }
            '^(4|existing|installed)$' { return 'Existing' }
            '^(q|quit|exit)$' {
                                throw "User cancelled the wizard."
                            }
            default { Write-Host "Invalid selection. Try again." -ForegroundColor Yellow }
        }
    }
}
# ------------------ Wizard Core ------------------
function Run-Wizard {
    # Looped so a branch that produces nothing usable - notably 'Existing' on a server with
    # no suitable certificate, or the operator backing out of that list - returns to the type
    # menu instead of dead-ending the install. Every other branch always sets $CertConfig,
    # so their behaviour is unchanged.
    while ($true) {
    $SelectedCertificateType = Show-CertificateTypeMenu
    Write-Host ""
    Write-Host ("Certificate Type selected: {0}" -f $SelectedCertificateType) -ForegroundColor Green

    $CertConfig = $null

    switch ($SelectedCertificateType) {

        'LetsEncrypt' {
            Write-Host ""
            Write-Host "LetsEncrypt Requirements:" -ForegroundColor Yellow
            Write-Host " - Port 80 must be open on this server to the Internet."
            Write-Host " - You need a public A record for the requested domain pointing here (e.g. psp.company.com --> 1.2.3.4)."
            Write-Host " - You must provide an e-mail address for renewal notifications."
            Write-Host " - LetsEncrypt certificates are only valid for 90 days."
            Write-Host "   A scheduled task will be installed to automatically handle renewal every 90 days."
            Write-Host ""

            # Hostname input with format validation
            while ($true) {
                $PublicHostname = Read-Host "Enter the public hostname (A record) for this system (e.g. psp.company.com)"
                if (Test-HostnameFormat -Name $PublicHostname) { break }
                Write-Host "Invalid hostname format. Please enter a valid FQDN." -ForegroundColor Yellow
            }

            # Email validation loop
            while ($true) {
                $ContactEmail = Read-Host "Enter your e-mail address for LetsEncrypt renewal notifications"
                if ($ContactEmail -match '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { break }
                Write-Host "Invalid email format. Please enter a valid e-mail (e.g. user@foo.com or user@foo.co.uk)" -ForegroundColor Yellow
            }

            # Resolve DNS A records using public resolvers
            # Wrap result in an array to allow "count" to always work.
            $ResolvedIPs = @(Resolve-IPv4A -Name $PublicHostname -PublicOnly)
            if (-not $ResolvedIPs -or $ResolvedIPs.Count -eq 0) {
                Warn "Warning: No public A records found for $PublicHostname from public DNS resolvers."
            } else {
                Info ("Resolved public A records for {0}: {1}" -f $PublicHostname, ($ResolvedIPs -join ', '))
            }

            # Determine public IPv4 of this system
            $PublicIPv4 = $null
            try {
                $PublicIPv4 = Get-PublicIPv4
                Info ("Detected public IPv4 for this system: {0}" -f $PublicIPv4)
            } catch {
                Warn ("Unable to determine public IPv4 automatically: {0}" -f $_.Exception.Message)
            }

            # Handle multiple A records or mismatch
            if ($ResolvedIPs.Count -gt 1) {
                Write-Host ""
                Warn "Multiple A records detected for $PublicHostname. This can cause Let's Encrypt validation to fail."
                Info "Resolved IPs: $($ResolvedIPs -join ', ')"
                if ($PublicIPv4) { Info "This system public IP: $PublicIPv4" }
            }

            if ($PublicIPv4) {
                $match = $ResolvedIPs -contains $PublicIPv4
                if (-not $match) {
                    Write-Host ""
                    Warn "DNS/IP mismatch detected!"
                    Write-Host (" - Hostname: {0}" -f $PublicHostname)
                    Write-Host (" - Public A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                    Write-Host (" - This system public IP: {0}" -f $PublicIPv4)

                    while ($true) {
                        $action = Read-Host "Do you want to retry DNS (R), change hostname (H), or continue anyway (C)? [R/H/C]"
                        switch -regex ($action) {
                            '^(R|r)$' {
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Info ("Refreshed A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                            }
                            '^(H|h)$' {
                                while ($true) {
                                    $PublicHostname = Read-Host "Enter the public hostname (A record) for this system"
                                    if (Test-HostnameFormat -Name $PublicHostname) { break }
                                    Warn "Invalid hostname format. Please enter a valid FQDN."
                                }
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Info ("Resolved A records for {0}: {1}" -f $PublicHostname, ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                            }
                            '^(C|c)$' { break }
                            default   { Write-Host "Invalid choice. Please select R, H, or C." -ForegroundColor Yellow }
                        }
                        if ($action -match '^(C|c)$') { break }
                    }
                }
            }

            # External port 80 check
            try {
                $portResult = Test-PortExternal -Port 80
                if ($null -ne $portResult) {
                    if ($portResult.IsOpen) {
                        Ok ("External connectivity check: Port {0} is OPEN ({1})" -f $portResult.Port, $portResult.ExternalCheck)
                    }
                    else {
                        Warn ("External connectivity check: Port {0} is CLOSED ({1})" -f $portResult.Port, $portResult.ExternalCheck)
                        $retry = Read-Host "Port 80 must be open for LetsEncrypt. Do you want to continue anyway? (Y/N)"
                        if ($retry -notmatch '^(Y|y)$') {
                            throw "LetsEncrypt prerequisites not met - port 80 is closed."
                        }
                    }
                }
                else {
                    Warn "External connectivity test did not return a result. Continuing with caution."
                }
            }
            catch {
                Err "Error while testing external connectivity: $($_.Exception.Message)"
            }

            # Final config object
            $CertConfig = [PSCustomObject]@{
                Type         = 'LetsEncrypt'
                Hostname     = $PublicHostname
                Email        = $ContactEmail
                DnsARecords  = $ResolvedIPs
                PublicIPv4   = $PublicIPv4
                DnsMatchesIP = [bool]($PublicIPv4 -and ($ResolvedIPs -contains $PublicIPv4))
                Port80Open   = ($portResult.IsOpen -eq $true)
            }
        }

        'BYOC' {
            $PfxPath = $null
            Write-Host ""
            Write-Host "Bring Your Own Certificate:" -ForegroundColor Cyan

            # --- Look in current directory for .pfx files ---
            $localPfxFiles = @(Get-ChildItem -Path (Get-Location) -Filter *.pfx -File -ErrorAction SilentlyContinue)

            if ($localPfxFiles.Count -gt 0) {
                Info "Found the following PFX files in the current directory:"
                for ($i=0; $i -lt $localPfxFiles.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i+1), $localPfxFiles[$i].Name)
                }
                while ($true) {
                    $choice = Read-Host "Select which file to use (1-$($localPfxFiles.Count)), or press Enter to type a path"
                    if ([string]::IsNullOrWhiteSpace($choice)) {
                        # user wants to manually type path
                        $PfxPath = $null
                        break
                    }
                    elseif ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $localPfxFiles.Count) {
                        $PfxPath = $localPfxFiles[$choice-1].FullName
                        break
                    }
                    Warn "Invalid selection. Please enter a number between 1 and $($localPfxFiles.Count) or press Enter."
                }
            } 

            # If no files found, or user pressed Enter, prompt for path
            if (-not $PfxPath) {
                while ($true) {
                    $rawPath = Read-Host "Please provide the full path of a PFX file (e.g. C:\Temp\companycert.pfx)"
                    $PfxPath = $rawPath.Trim('"').Trim("'")
                    $PfxPath = [System.Environment]::ExpandEnvironmentVariables($PfxPath)
                    try { $PfxPath = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $PfxPath)) } catch {}
                    if (-not (Test-Path -Path $PfxPath -PathType Leaf)) { Warn "The file path does not exist. Please try again."; continue }
                    if ([System.IO.Path]::GetExtension($PfxPath) -ne ".pfx") { Warn "The file must have a .pfx extension. Please try again."; continue }
                    break
                }
            }

            # --- Prompt for password + read cert ---
            while ($true) {
                $PfxPass = Read-Host "Please provide the password for the provided PFX file" -AsSecureString
                try {
                    $CertFqdns = Get-PfxSubject -PfxPath $PfxPath -Password $PfxPass

                    # Normalize to array
                    if (-not ($CertFqdns -is [System.Array])) {
                        $CertFqdns = @($CertFqdns)
                    }

                    if (-not $CertFqdns -or $CertFqdns.Count -eq 0) { throw "Unable to read any DNS names from the certificate." }

                    Info "Certificate loaded. Found the following DNS names:"
                    $CertFqdns | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                    break
                } catch {
                    Warn ("Failed to open PFX or read subject: {0}" -f $_.Exception.Message)
                    $retry = Read-Host "Password may be incorrect. Try again? (Y/N)"
                    if ($retry -notmatch '^(Y|y)$') { throw "Invalid PFX or password." }
                }
            }

            # --- Resolve which name this server is published under ---
            $HostChoice = Resolve-CertHostname -CertFqdns $CertFqdns

            # --- Final config object ---
            $CertConfig = [PSCustomObject]@{
                Type              = 'BYOC'
                PfxPath           = $PfxPath
                PfxPass           = $PfxPass
                CertFqdns         = $CertFqdns
                ChosenWildcard    = $HostChoice.ChosenWildcard
                Hostname          = $HostChoice.Hostname
                WildcardValidated = $HostChoice.WildcardValidated
            }
        }



        'SelfSigned' {
            Write-Host ""
            Write-Host "WARNING: Self-Signed certificates may cause functionality issues when using PowerSyncPro with SSL. This option is not recommended." -ForegroundColor Red
            Write-Host "You may need to export the self signed certificate produced into the Root Certificate Store on Endpoints for full functionality."

            while ($true) {
                $SelfSignedHostname = Read-Host "Enter the FQDN that will be used for this system (e.g. psp.company.com)"
                if (Test-HostnameFormat -Name $SelfSignedHostname) { break }
                Warn "Invalid hostname format. Please enter a valid FQDN."
            }

            $CertConfig = [PSCustomObject]@{
                Type     = 'SelfSigned'
                Hostname = $SelfSignedHostname
            }
        }

        'Existing' {
            Write-Host ""
            Write-Host "Use a certificate already installed on this server:" -ForegroundColor Cyan
            Write-Host "No PFX file is needed - the certificate and its private key are already in the"
            Write-Host "LocalMachine store. This is the option to use when a certificate was installed"
            Write-Host "by hand, or by another process, and the original PFX is no longer available."

            $chosenCert = Select-ExistingCertificate

            if ($chosenCert) {
                # Read the names off the certificate and resolve which one this server is
                # published under, using the same wildcard / multi-SAN handling as BYOC.
                $CertFqdns = @($chosenCert.DnsNameList | ForEach-Object { $_.Unicode })
                if ($CertFqdns.Count -eq 0) {
                    $CertFqdns = @($chosenCert.GetNameInfo('SimpleName', $false))
                }

                Info "Certificate DNS names:"
                $CertFqdns | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

                $HostChoice = Resolve-CertHostname -CertFqdns $CertFqdns

                $CertConfig = [PSCustomObject]@{
                    Type              = 'Existing'
                    Thumbprint        = $chosenCert.Thumbprint
                    CertFqdns         = $CertFqdns
                    ChosenWildcard    = $HostChoice.ChosenWildcard
                    Hostname          = $HostChoice.Hostname
                    WildcardValidated = $HostChoice.WildcardValidated
                    NotAfter          = $chosenCert.NotAfter
                }
            }
        }
    }

    if ($CertConfig) { return $CertConfig }

    # Nothing usable came back - loop round to the certificate type menu.
    Write-Host ""
    Warn "No certificate configuration was produced. Returning to the certificate type menu."
    Start-Sleep 2
    }
}
# -------------------------------------------------
# Menu / Script Actions / Logic

# If dot-sourced, stop here (only load functions)
if ($MyInvocation.InvocationName -eq '.') {
    return
} 

# Initialize logging
# Register exit cleanup handler
#Start Transcription
# -PrepareOffline may run on a non-elevated workstation, where creating C:\Temp
# requires admin. Route its log to the user-writable temp folder instead.
if ($PrepareOffline) {
    $LogPath = Join-Path $env:TEMP "PSP_AutoInstall_Prepare.txt"
}
if (-not (Test-Path -Path (Split-Path $LogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force | Out-Null
    }

Start-Transcript -Path $LogPath -Append

Register-EngineEvent PowerShell.Exiting -Action {
    try { Stop-Transcript | Out-Null } catch {}
} | Out-Null

try{
    $ErrorActionPreference = "Stop"
    $ExternalServerInUse = $false

    # Reverse-proxy state, resolved in the preflight below. Initialised here because
    # Set-StrictMode makes reading an unassigned variable a terminating error, and the
    # completion path reads both regardless of which mode ran.
    $RemoteBackend = $false
    $LockAdminSite = $false

    # Tracks whether a certificate was successfully applied. Previously only assigned
    # inside the certificate switch, so an unknown type or a failed ACL fix left it unset
    # and StrictMode threw when the completion banner read it.
    $certInstalled = $false

    # Evaluate CLI Flags
    # Validate mutually-exclusive and dependent CLI flags before doing any work.
    if ($PreReqOnly -and $CompletionOnly) {
        Err "You cannot run both Prequisites and Completion at the same time... Exiting."
        exit 1
    }

    # ---------------- Offline / air-gapped mode dispatch ----------------
    if ($PrepareOffline -and $InstallOffline) {
        Err "You cannot use -PrepareOffline and -InstallOffline together... Exiting."
        exit 1
    }

    # -IncludeSSMS only makes sense while preparing a bundle.
    if ($IncludeSSMS -and -not $PrepareOffline) {
        Err "ERROR: -IncludeSSMS can only be used with -PrepareOffline. Exiting."
        exit 1
    }

    if ($PrepareOffline) {
        # Prepare is a standalone, online-only operation: build the bundle and exit.
        # It must not be combined with install-time flags.
        if ($CompletionOnly -or $ReverseProxyOnly -or $IISOnly -or $Headless -or $PSPServiceUser -or $PSPServicePassword) {
            Err "ERROR: -PrepareOffline cannot be combined with -CompletionOnly, -ReverseProxyOnly, -IISOnly, -Headless, or service account flags. Exiting."
            exit 1
        }
        $script:OfflineMode = 'Prepare'
        Initialize-OfflinePaths -Path $OfflinePath -Create
        $asciiLogo
        Info "Running in PREPARE OFFLINE mode."
        Info "Bundle directory: $script:BundleDir"
        Invoke-PrepareOffline -MetadataUrl $metadataUrl -IncludeSSMS:$IncludeSSMS
        exit 0
    }

    if ($InstallOffline) {
        $script:OfflineMode = 'Install'
        Initialize-OfflinePaths -Path $OfflinePath
        Info "Running in INSTALL OFFLINE mode."
        Info "Bundle directory: $script:BundleDir"
        if (-not (Test-Path $script:ManifestPath)) {
            Err "No manifest.json found at $script:BundleDir. Point -OfflinePath at a bundle built with -PrepareOffline. Exiting."
            exit 1
        }

        # Verify every required payload is present and its SHA256 matches before we
        # commit to a long install.
        $offlineManifest = Read-OfflineManifest
        Info "Verifying bundle integrity (SHA256)..."
        if (-not (Test-BundleIntegrity -Manifest $offlineManifest)) {
            Err "Offline bundle failed integrity verification. Aborting."
            exit 1
        }
        Ok "Bundle integrity verified (prepared $($offlineManifest.preparedOn))."

        # Files carried in on removable media get a Mark-of-the-Web (Zone.Identifier)
        # that can block installers on hardened servers. Clear it across the bundle.
        Info "Clearing Mark-of-the-Web from bundle files..."
        Get-ChildItem -Path $script:BundleDir -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
        Ok "Offline bundle ready."
    }

    # Enforce elevation for every mode that actually installs software. This runs
    # after the offline dispatch so -PrepareOffline (which exits above) can build a
    # bundle on a non-elevated workstation; all other paths require admin.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Err "This operation requires an elevated (Run as Administrator) PowerShell session. Exiting."
        exit 1
    }

    # -----------------------------------------------------------------------------------
    # Reverse-proxy mode resolution
    # -ReverseProxyOnly configures just the IIS reverse-proxy layer. -IISOnly and
    # -CompletionOnly are retained as aliases for it: all three end up in the same code
    # path, differing only in whether the backend is local or remote (see -PSPBackendUrl).
    # -----------------------------------------------------------------------------------
    if ($IISOnly) {
        Warn "-IISOnly is deprecated. Use -ReverseProxyOnly; continuing as -ReverseProxyOnly."
        $ReverseProxyOnly = $true
    }

    if ($CompletionOnly) {
        Info "-CompletionOnly now runs as -ReverseProxyOnly, which additionally ensures the IIS"
        Info "reverse-proxy stack is present and reads the Kestrel port from appsettings.json."
        $ReverseProxyOnly = $true
    }

    if ($ReverseProxyOnly -and $PreReqOnly) {
        Err "-ReverseProxyOnly cannot be combined with -PreReqOnly. -PreReqOnly installs PowerSyncPro's prerequisites; -ReverseProxyOnly only configures the proxy layer. Exiting."
        exit 1
    }

    if ($ReverseProxyOnly -and $Headless) {
        Err "-ReverseProxyOnly cannot be combined with -Headless. -Headless is a -PreReqOnly automation flag and the certificate menu is interactive. Exiting."
        exit 1
    }

    if ($ReverseProxyOnly -and (-not [string]::IsNullOrWhiteSpace($PSPServiceUser) -or -not [string]::IsNullOrWhiteSpace($PSPServicePassword))) {
        Err "-ReverseProxyOnly does not install PowerSyncPro, so a PSP service account (-PSPServiceUser / -PSPServicePassword) is not applicable. Exiting."
        exit 1
    }

    # -PSPBackendUrl and -NoLockAdmin only mean something in reverse-proxy mode. Reject them
    # elsewhere so the operator's intent is never silently ignored.
    if ((-not $ReverseProxyOnly) -and (-not [string]::IsNullOrWhiteSpace($PSPBackendUrl))) {
        Err "-PSPBackendUrl is only valid together with -ReverseProxyOnly. A normal install forwards to the local Kestrel backend. Exiting."
        exit 1
    }

    if ((-not $ReverseProxyOnly) -and $NoLockAdmin) {
        Err "-NoLockAdmin is only valid together with -ReverseProxyOnly. Exiting."
        exit 1
    }

    # The certificate menu (Run-Wizard / Show-CertificateTypeMenu) is fully interactive and
    # has no non-interactive fallback, so fail fast when there is no interactive session
    # (remote PS / Server Core) rather than hanging on a Read-Host that can never return.
    if ($ReverseProxyOnly -and -not [Environment]::UserInteractive) {
        Err "-ReverseProxyOnly needs an interactive session: the certificate selection menu prompts for input and has no non-interactive fallback. Run it from an interactive console. Exiting."
        exit 1
    }

    # Cannot use the PSPServiceUser / PSPServicePassword flags with the PreReqOnly or CompletionOnly flags.
    if ( ($PreReqOnly -or $CompletionOnly) -and
     (-not [string]::IsNullOrWhiteSpace($PSPServiceUser) -or
      -not [string]::IsNullOrWhiteSpace($PSPServicePassword)) ) {
        Err "-PreReq and -Completion Flags are not compatible with Service Accounts... Exiting."
        exit 1
    }

    # Headless can only be used with PreReqOnly
    if ($Headless -and -not $PreReqOnly) {
        Err "ERROR: -Headless can only be used with -PreReqOnly. Exiting."
        exit 1
    }

    # Validate Service Credentials
    if ($PSPServiceUser -and -not $PSPServicePassword) {
        Err "ERROR: You provided -PSPServiceUser but did not specify -PSPServicePassword."
        exit 1
    }

    if (-not $PSPServiceUser -and $PSPServicePassword) {
        Err "ERROR: You provided -PSPServicePassword but no -PSPServiceUser."
        exit 1
    }

    # Notify that script will be run in PreReq Only Mode, we will do everything up to installing PSP.
    if ($PreReqOnly) {
        $asciiLogo
        Info "Installing PowerSyncPro Installation Prequisites Only."
        Info "After manually installing the MSI, you can complete the certificate installation and hardening using the -ReverseProxyOnly flag."
        Start-Sleep 5
    }

    # Service Account Tasks - Only if not in PreReq / reverse-proxy Mode
    if (-not $PreReqOnly -and -not $ReverseProxyOnly) {

        # Expand .\username into HOSTNAME\username if needed
        if ($PSPServiceUser -like '.\*') {
            $hostname = $env:COMPUTERNAME
            $PSPServiceUser = $PSPServiceUser -replace "^\.\\", "$env:COMPUTERNAME\"
            Info "Expanded local user reference to: $PSPServiceUser"
        }

        # Validate Name Format
        if ($PSPServiceUser) {
            # Acceptable formats:
            #   DOMAIN\User
            #   HOSTNAME\User
            $userPattern = '^[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+$'

            if ($PSPServiceUser -notmatch $userPattern) {
                Err "ERROR: Invalid service account format. Use DOMAIN\Username or .\Username"
                exit 1
            }
        }

        # Let script know whether we're using a specific service account / check credentials
        if (-not [string]::IsNullOrWhiteSpace($PSPServiceUser)) {
            # Check if the provided service account creds are good.
            if (Test-UserCredential -Username $PSPServiceUser -Password $PSPServicePassword) {
                $UseServiceAccount = $true
                Ok "We are using a specific service account, $PSPServiceUser to install PowerSyncPro..."
                Warn "This service account must have access to your database or installation may fail."
                Start-Sleep 2
            }
            else {
                Err "Service account credentials provided are invalid, please test and attempt install again."
                exit 1
            }
        }
        else {
            $UseServiceAccount = $false
        }
    }

    # -----------------------------------------------------------------------------------
    # Reverse-proxy preflight
    # Decide what this proxy forwards to, and confirm the OS is supported. No SQL selection
    # or Kestrel port prompting applies here; the proxy stack, hardening, certificate and
    # firewall rules are handled by the shared (-not $PreReqOnly) completion path below.
    # -----------------------------------------------------------------------------------
    if ($ReverseProxyOnly) {
        Info "Running in reverse-proxy mode: configuring only the IIS proxy layer (no SQL, VC++, .NET Hosting Bundle, PSP MSI, PSP service account or SSMS)."

        if (-not (Test-IsServer2016OrNewer)) {
            Err "This operating system is not supported. Windows Server 2016 or newer is required."
            exit 1
        }
        Ok "OS check passed - continuing reverse-proxy configuration..."

        # An explicit -PSPBackendUrl means PowerSyncPro lives on another server. Otherwise
        # look for a local installation and read the port it actually listens on, rather
        # than assuming the 5000 default - a hand-installed server may use anything.
        if (-not [string]::IsNullOrWhiteSpace($PSPBackendUrl)) {
            $RemoteBackend = $true
            Info ("Reverse proxy will forward client traffic to the remote PowerSyncPro backend: {0}" -f $PSPBackendUrl)
        }
        else {
            $discoveredPort = Get-KestrelBackendPort -AppSettingsPath $PspAppSettingsPath

            if ($discoveredPort) {
                $RemoteBackend   = $false
                $KestrelHttpPort = $discoveredPort
                Ok ("Local PowerSyncPro detected - reverse proxy will forward to http://localhost:{0}" -f $KestrelHttpPort)

                # PowerSyncPro being stopped does not prevent us configuring the proxy layer,
                # so this is a warning rather than the hard exit older versions used.
                if (-not (Test-PowerSyncPro)) {
                    Warn "The PowerSyncPro service is installed but not running. The proxy will still be configured; start the service before using the site."
                }
            }
            else {
                # No local appsettings.json, so PowerSyncPro is not on this box. That makes
                # this a standalone proxy, which needs a backend URL to forward to.
                Warn "No local PowerSyncPro installation was detected on this server."

                if (-not [Environment]::UserInteractive) {
                    Err "PowerSyncPro is not installed here and -PSPBackendUrl was not supplied, so there is nothing to forward to. Re-run with -PSPBackendUrl https://psp.example.com:5001. Exiting."
                    exit 1
                }

                Write-Host ""
                Write-Host "PowerSyncPro does not appear to be installed on this server, so this is being" -ForegroundColor Yellow
                Write-Host "configured as a standalone reverse proxy in front of PowerSyncPro on another" -ForegroundColor Yellow
                Write-Host "machine. The admin site will be locked down here by default." -ForegroundColor Yellow
                Write-Host ""

                while ($true) {
                    $enteredUrl = Read-Host "Enter the PowerSyncPro backend URL (e.g. https://psp.corp.local:5001), or Q to quit"
                    if ($enteredUrl -match '^(q|quit|exit)$') {
                        Err "No backend supplied. Exiting."
                        exit 1
                    }
                    $enteredUrl = $enteredUrl.Trim()
                    $parsedUrl  = $null
                    if ([uri]::TryCreate($enteredUrl, [System.UriKind]::Absolute, [ref]$parsedUrl) -and
                        ($parsedUrl.Scheme -eq 'http' -or $parsedUrl.Scheme -eq 'https')) {
                        $PSPBackendUrl = $enteredUrl
                        $RemoteBackend = $true
                        Ok ("Reverse proxy will forward client traffic to: {0}" -f $PSPBackendUrl)
                        break
                    }
                    Warn "Enter a well-formed absolute URL including the scheme, e.g. https://psp.corp.local:5001"
                }
            }
        }

        # A standalone proxy fronting a remote PowerSyncPro is locked down by default;
        # -NoLockAdmin opts out. A proxy in front of a LOCAL install keeps the existing
        # localhost-allow behaviour and is never locked.
        $LockAdminSite = ($RemoteBackend -and (-not $NoLockAdmin))

        if ($NoLockAdmin -and (-not $RemoteBackend)) {
            Info "-NoLockAdmin has no effect here: a proxy in front of a local PowerSyncPro is not locked down."
        }
    }

    # Run a bunch of stuff if not in Completion Only / IIS Only mode....
    if (-not $ReverseProxyOnly) {
        # Test if PowerSyncPro is running
        if (Test-PowerSyncPro) {
            Warn "PowerSyncPro Service is already installed or running on this system. Aborting installation script."
            exit 1
        }

        # Test if machine is a server - we shouldn't run on non-server OS and versions under 2016.
        Ok "PowerSyncPro Service is *not* present or running - continuing installation..."

        if (-not (Test-IsServer2016OrNewer)) {
            Err "This operating system is not supported. Windows Server 2016 or newer is required."
            exit 1   # stops the script with an error code
        }

        Ok "OS check passed - continuing installation..."

        if (-not [Environment]::UserInteractive) {
            Info "Non-interactive session detected (remote PS / Server Core)."
            Info "  - SQL Server will be installed silently via a SYSTEM scheduled task."
            Info "  - SSMS installation will be skipped (GUI tool, not applicable on headless servers)."
            Info "  - All other GUI prompts will be suppressed where possible."
        }

        # Choose SQL Target Database Instance
        $SqlAddress  = "localhost"
        $SqlPort     = "1433"
        $SqlDatabase = "PowerSyncProDB"

        # Kestrel backend ports - set via script params (defaults: HTTP 5000 / HTTPS 5001)
        # May be changed below if conflicts are detected or user customises.

        $InstallSqlExpress = $false

        # Headless mode: assume local FULL SQL default instance (MSSQLSERVER)
        if ($Headless) {
            Info "Headless mode detected. Using local default SQL instance (MSSQLSERVER)."
            $SqlInstance      = "MSSQLSERVER"
            $InstallSqlExpress = $false

            $svc = Test-SqlInstanceService -InstanceName $SqlInstance
            if (-not $svc) { throw ("Headless selected MSSQLSERVER but it was not found/valid on this system.") }

            if ($svc.Status -ne "Running") {
                Info ("SQL service '{0}' is {1}. Starting it..." -f $svc.Name, $svc.Status)
                Start-Service -Name $svc.Name -ErrorAction Stop
                $svc.WaitForStatus("Running", "00:00:20")
            }

            Warn ("Selected SQL target: {0}\{1}" -f $SqlAddress, $SqlInstance)

        }
        else {
            # Get all SQL Instances on the system.
            $instances = @(Get-LocalSqlInstances)

            if ($instances.Count -gt 0) {

                $selection = Select-SqlTarget -Instances $instances -PreReqOnly $PreReqOnly

                if ($selection.Mode -eq "Existing") {
                    $SqlInstance = $selection.Instance.Instance

                    # Only notify if script is not in PreReqOnly Mode
                    if (-not $PreReqOnly) {
                        Warn "IMPORTANT: The account running this installer must have permission to create databases on this instance."
                    }

                    Warn ("Selected SQL target: {0}\{1}" -f $SqlAddress, $SqlInstance)
                    Warn ("Database to be created: {0}" -f $SqlDatabase)

                    $svc = Test-SqlInstanceService -InstanceName $SqlInstance
                    if (-not $svc) { throw ("SQL instance '{0}' was selected but is not valid." -f $SqlInstance) }

                    if ($svc.Status -ne "Running") {
                        if (Confirm-YesNo -Message ("SQL service is {0}. Start it now" -f $svc.Status)) {
                            Start-Service -Name $svc.Name -ErrorAction Stop
                            $svc.WaitForStatus("Running", "00:00:20")
                        }
                    }
                }
                else {
                    $SqlInstance = $selection.NewInstanceName
                    $InstallSqlExpress = $true
                }

            }
            # No existing SQL Installs present, determine what to do next.
            else {
                # If in PreReqOnly mode, ask the user how they want to proceed.
                if ($PreReqOnly) {
                    while ($true) {
                        Info "Script is in PreReq Only mode and no local SQL installations were found..."
                        Write-Host "Please Select an Option:"
                        Write-Host "1. Install a new default SQL Express installation."
                        Write-Host "2. Use an externally hosted SQL server."

                        $choice = Read-Host "Select an Option"

                        if ($choice -eq "1") {
                            Write-Host "Installing SQL Express..."
                            Info "SQL Express will be installed with default instance name (SQLEXPRESS)."
                            $SqlInstance = "SQLEXPRESS"
                            $InstallSqlExpress = $true
                            break
                        }
                        elseif ($choice -eq "2") {
                            Write-Host "Using external SQL server..."
                            Info "Prerequisite installation will continue without installing SQL."
                            Info "Please setup SQL to an external server during a manual MSI install of PowerSyncPro."
                            $InstallSqlExpress = $false
                            break
                        }
                        else {
                            Write-Host "Invalid selection. Please try again." -ForegroundColor Yellow
                        }
                    }
                }
                # Script is not in PreReqOnly mode, no instances - do a default SQLEXPRESS install.
                else {
                    Info "No SQL instances detected. SQL Express will be installed with default instance name (SQLEXPRESS)."
                    $SqlInstance = "SQLEXPRESS"
                    $InstallSqlExpress = $true
                }
            }
        }

        if (-not $Headless) {
            # -------------------------------------------------------------------
            # Kestrel port selection
            # If the configured Kestrel ports are free, confirm them; only prompt for
            # alternatives when one is already in use (see $needCustomPorts below).
            # If they are in use, the user must choose alternative ports.
            # -------------------------------------------------------------------
            $kestrelInUse = @(Get-ListeningPort -Port $KestrelHttpPort,$KestrelHttpsPort |
                              Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })

            $needCustomPorts = $false

            if ($kestrelInUse) {
                Write-Host ""
                Warn "[WARNING] Default Kestrel Port Conflicts Detected"
                foreach ($c in $kestrelInUse) {
                    Write-Host (" Port {0} in use by process '{1}' (PID {2})" -f $c.Port, $c.Process, $c.ProcId) -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host ("The default Kestrel ports ({0} HTTP / {1} HTTPS) are already in use." -f $KestrelHttpPort, $KestrelHttpsPort) -ForegroundColor Yellow
                Write-Host "You must choose alternative ports for the PowerSyncPro backend." -ForegroundColor Yellow
                $needCustomPorts = $true
            } else {
                Ok ("Kestrel ports available and confirmed: HTTP {0} / HTTPS {1}" -f $KestrelHttpPort, $KestrelHttpsPort)
            }

            if ($needCustomPorts) {
                Write-Host ""

                # --- HTTP port ---
                do {
                    $raw = Read-Host ("  Enter Kestrel HTTP port [default: {0}]" -f $KestrelHttpPort)
                    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "$KestrelHttpPort" }
                    $p = 0
                    $portOk = [int]::TryParse($raw, [ref]$p) -and $p -ge 1024 -and $p -le 65535
                    if (-not $portOk) {
                        Write-Host "  Invalid port. Enter a number between 1024 and 65535." -ForegroundColor Red
                    } else {
                        $inUse = @(Get-ListeningPort -Port $p | Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })
                        if ($inUse) {
                            Write-Host ("  Port {0} is in use by '{1}'. Choose a different port." -f $p, $inUse[0].Process) -ForegroundColor Red
                            $portOk = $false
                        }
                    }
                } while (-not $portOk)
                $KestrelHttpPort = $p

                # --- HTTPS port ---
                do {
                    $raw = Read-Host ("  Enter Kestrel HTTPS port [default: {0}]" -f $KestrelHttpsPort)
                    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "$KestrelHttpsPort" }
                    $p = 0
                    $portOk = [int]::TryParse($raw, [ref]$p) -and $p -ge 1024 -and $p -le 65535
                    if (-not $portOk) {
                        Write-Host "  Invalid port. Enter a number between 1024 and 65535." -ForegroundColor Red
                    } elseif ($p -eq $KestrelHttpPort) {
                        Write-Host ("  HTTPS port must differ from HTTP port ({0})." -f $KestrelHttpPort) -ForegroundColor Red
                        $portOk = $false
                    } else {
                        $inUse = @(Get-ListeningPort -Port $p | Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })
                        if ($inUse) {
                            Write-Host ("  Port {0} is in use by '{1}'. Choose a different port." -f $p, $inUse[0].Process) -ForegroundColor Red
                            $portOk = $false
                        }
                    }
                } while (-not $portOk)
                $KestrelHttpsPort = $p

                Ok ("Kestrel ports set to: HTTP {0} / HTTPS {1}" -f $KestrelHttpPort, $KestrelHttpsPort)
            }

            # -------------------------------------------------------------------
            # Full port conflict check (80, 443, and the chosen Kestrel ports)
            # -------------------------------------------------------------------
            $checkPorts  = 80, 443, $KestrelHttpPort, $KestrelHttpsPort
            $noConflicts = $false

            $listeners = Get-ListeningPort -Port $checkPorts
            $listeners  = @($listeners)
            $active     = @($listeners | Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })

            if ($active.Count -eq 0) {
                Ok "No conflicts detected. All required ports are available."
                $noConflicts = $true
            }

            if (-not $noConflicts) {
                $reverseProxyConflicts = $active | Where-Object { $_.Port -in 80, 443 }
                $kestrelConflicts      = $active | Where-Object { $_.Port -in $KestrelHttpPort, $KestrelHttpsPort }

                # IIS / Reverse Proxy check
                if ($reverseProxyConflicts) {
                    Write-Host ""
                    Warn "[WARNING] Reverse Proxy (IIS) Port Conflicts Detected"
                    foreach ($c in $reverseProxyConflicts) {
                        if ($c.IISSite) {
                            Write-Host (" Port {0} in use by IIS site '{1}' (Process: {2})" -f $c.Port, $c.IISSite, $c.Process) -ForegroundColor Yellow
                        } else {
                            Write-Host (" Port {0} in use by process '{1}' (PID {2})" -f $c.Port, $c.Process, $c.ProcId) -ForegroundColor Yellow
                        }
                    }

                    Write-Host ""
                    Write-Host "Port 80 or 443 are used by IIS or another process." -ForegroundColor Yellow
                    Write-Host "If you continue, current IIS configuration may be modified or overwritten." -ForegroundColor Yellow
                    Write-Host "If you have a default IIS configuration on this system, you can safely ignore this warning." -ForegroundColor Yellow
                    Write-Host "If you are using IIS on this system for another purpose, you should *NOT* continue." -ForegroundColor Yellow

                    $response = Read-Host "Do you want to continue setup anyway? (Y/N)"
                    if ($response -notmatch '^[Yy]$') {
                        Write-Host ""
                        Err "Setup aborted by user to prevent overwriting IIS configuration."
                        exit 1
                    }
                }

                # Kestrel conflict safeguard (should not trigger after selection above)
                if ($kestrelConflicts) {
                    Write-Host ""
                    Err "[ERROR] PowerSyncPro Backend Port Conflicts Detected"
                    foreach ($c in $kestrelConflicts) {
                        Write-Host (" Port {0} in use by process '{1}' (PID {2})" -f $c.Port, $c.Process, $c.ProcId) -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "PowerSyncPro will not be able to bind to these ports. Please review the processes using them and reconfigure them if possible." -ForegroundColor Red
                    exit 1
                }

                Ok "Port check complete. No blocking conflicts detected. Continuing setup..."
            }

            Start-Sleep -Seconds 8
        }
        
    }
    
    # -----------------------------------------------------------------------------------
    # Reverse-proxy mode: ensure the IIS proxy stack is present BEFORE the certificate menu.
    # The ordering matters twice over. The menu offers the certificate currently bound to
    # port 443, which needs IIS present to enumerate; and Web-IP-Security has to exist before
    # a web.config containing <ipSecurity> is written, or IIS answers every request with
    # HTTP 500.19. Only proxy components are installed here - the .NET Hosting Bundle, VC++,
    # SQL and SSMS are PowerSyncPro application prerequisites and mean nothing to a proxy.
    # -----------------------------------------------------------------------------------
    if ($ReverseProxyOnly) {
        Info "Checking current IIS status on this server..."

        # An air-gapped proxy sources the IIS modules from the offline bundle instead of
        # the internet. Online, these splats are empty and the calls are unchanged.
        $rpRewriteSplat = @{}; $rpArrSplat = @{}
        if ($script:OfflineMode -eq 'Install') {
            $rpRewriteSplat['LocalPath'] = (Resolve-OfflineAsset -Key 'urlrewrite')
            $rpArrSplat['LocalPath']     = (Resolve-OfflineAsset -Key 'arr')
        }

        $features = Test-IISFeatures
        Install-IIS -IISInstalled $features.IISInstalled -WebIPInstalled $features.WebIPInstalled

        if (-not (Test-IISUrlRewrite)) {
            Install-URLRewrite -RewriteUrlBase $RewriteUrlBase -tempDir $tempDir @rpRewriteSplat
        }

        $arrStatus = Test-IISARR
        Install-ARR -ARRInstalled $arrStatus.ARRInstalled -ARRActivated $arrStatus.ARRActivated -ArrUrl $ArrUrl -tempDir $tempDir @rpArrSplat
    }

    # Run the certificate setup menu if we are not only doing prereqs.
    if (-not $PreReqOnly) {
        # Start Menu Loop for Certificate Configuration
        try {
            while ($true) {
                $CertConfig = Run-Wizard

                Write-Host ""
                Write-Host "Summary of Certificate Configuration:" -ForegroundColor Green
                $CertConfig | Format-List | Out-String | Write-Host

                $confirm = Read-Host "Do you want to continue with this configuration? (Y/N)"
                if ($confirm -match '^(Y|y)$') { break }
                Write-Host ""
                Write-Host "Restarting wizard..." -ForegroundColor Yellow
            }

            Write-Host ""
            Ok "Certificate configuration accepted, beginning installation."
        }
        catch {
            Err ("Error: {0}" -f $_.Exception.Message)
            exit 1
        }


        # Grab Details for CertConfig
        $FrontendHost = $CertConfig.Hostname # FrontendHost FQDN
        $CertType = $CertConfig.Type # Type of Cert Chosen
    }
    

    # Begin Installation
    # Print proper status.
    if ($ReverseProxyOnly) {
        if ($RemoteBackend) {
            Info "Configuring the IIS reverse-proxy layer in front of a remote PowerSyncPro..."
            Info ("Reverse-proxy backend target: {0}" -f $PSPBackendUrl)
        }
        else {
            Info "Configuring the IIS reverse-proxy layer in front of the local PowerSyncPro..."
            Info ("Reverse-proxy backend target: http://localhost:{0}" -f $KestrelHttpPort)
        }
        Info "Using a $CertType Certificate with a Hostname of $FrontendHost..."
    }
    elseif ($PreReqOnly) {
        Info "Beginning install of PowerSyncPro dependencies..."
    }
    else {
        # Normal full install.
        Info "Beginning install of PowerSyncPro dependencies and application...."
        Info "Using a $CertType Certificate with a Hostname of $FrontendHost..."
    }

    # Install the PowerSyncPro prerequisites, unless this run only touches the proxy layer.
    if (-not $ReverseProxyOnly){

        # Offline sourcing: when installing from a bundle, resolve local payload
        # paths and pass them to the installers via splatting. In online mode these
        # splats are empty, so the install calls are unchanged.
        $dnSplat = @{}; $vcSplat = @{}; $rewriteSplat = @{}; $arrSplat = @{}; $sqlSplat = @{}
        if ($script:OfflineMode -eq 'Install') {
            $dnSplat['LocalPath']       = (Resolve-OfflineAsset -Key 'dotnet-hosting')
            $vcSplat['LocalPath']       = (Resolve-OfflineAsset -Key 'vcredist')
            $rewriteSplat['LocalPath']  = (Resolve-OfflineAsset -Key 'urlrewrite')
            $arrSplat['LocalPath']      = (Resolve-OfflineAsset -Key 'arr')
            $sqlSplat['LocalMediaPath'] = (Resolve-OfflineAsset -Key 'sql-media')
            # PSP MSI: honor a user-supplied local file (lets an operator swap the PSP
            # version without rebuilding the bundle); otherwise use the bundled MSI.
            # A URL is unusable offline, so anything that isn't a local file falls back
            # to the bundle. Install-PSP treats a local file path in -PSPUrl as a local installer.
            if (Test-Path $PSPUrl -PathType Leaf) {
                Info "Using operator-supplied PSP installer: $PSPUrl"
            } else {
                $PSPUrl = (Resolve-OfflineAsset -Key 'psp')
            }
        }

        if (-not (Test-dotNet8Hosting -RequiredVersions $DotNetVer)) {
            Install-dotNet8Hosting -metadataUrl $metadataUrl -tempDir $tempDir @dnSplat
        }

        if (-not (Test-VCRedistributable -RequiredVersion $vcVer)){
            Install-VCRedistributable -DownloadURL $vcDownloadURL -TempDir $tempDir @vcSplat
        }

        # Install SQL Express only if the user selected "Install new SQL Express"
        if ($InstallSqlExpress) {

            Info ("Installing SQL Express instance '{0}'..." -f $SqlInstance)

            if (-not [string]::IsNullOrWhiteSpace($PSPServiceUser)) {
                $SQLAdminsGroup = New-LocalSqlAdminsGroup -ServiceUser $PSPServiceUser
                Install-SQLExpress -BootstrapperUrl $SQLBootstrapperUrl -tempDir $tempDir `
                                -InstanceName $SqlInstance -SQLAdminsGroup $SQLAdminsGroup @sqlSplat
            }
            else {
                Install-SQLExpress -BootstrapperUrl $SQLBootstrapperUrl -tempDir $tempDir `
                                -InstanceName $SqlInstance @sqlSplat
            }
        }

        # Install SSMS if not installed, not using an external server, and running in an
        # interactive desktop session. SSMS is a GUI tool with no value on Server Core
        # or in remote PS sessions.
        if (-not (Test-SSMS) -and -not $ExternalServerInUse -and [Environment]::UserInteractive) {
            if ($script:OfflineMode -eq 'Install') {
                # Offline: install SSMS from the bundled VS offline layout. The layout
                # folder contains its own bootstrapper; running it with --noWeb forces
                # it to use only the local packages (no internet).
                $ssmsLayout = Resolve-OfflineAsset -Key 'ssms'
                if ($ssmsLayout) {
                    Info "Installing SSMS from offline layout: $ssmsLayout"

                    # The VS setup engine verifies the Authenticode signature of the
                    # layout package before installing. On an air-gapped box the
                    # signing chain can't be fetched, so import the certs shipped in
                    # the layout first (per the MS install-certificates guide):
                    #   - *.cer  = standard 2010/2011 roots -> Trusted Root ("Root")
                    #   - *.crt  = Code Signing PCA 2024 intermediate -> Intermediate ("CA")
                    $certDir = Join-Path $ssmsLayout "certificates"
                    if (Test-Path $certDir) {
                        Info "Importing SSMS offline signing certificates..."
                        Get-ChildItem -Path $certDir -Filter "*.cer" -File -ErrorAction SilentlyContinue | ForEach-Object {
                            & certutil.exe -addstore -f "Root" $_.FullName | Out-Null
                        }
                        Get-ChildItem -Path $certDir -Filter "*.crt" -File -ErrorAction SilentlyContinue | ForEach-Object {
                            & certutil.exe -addstore -f "CA" $_.FullName | Out-Null
                        }
                    } else {
                        Warn "No certificates folder found in the SSMS layout; signature verification may fail."
                    }

                    $boot = Get-ChildItem -Path $ssmsLayout -Filter "*.exe" -File -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "vs_*" -or $_.Name -like "SSMS*" } | Select-Object -First 1
                    if (-not $boot) {
                        $boot = Get-ChildItem -Path $ssmsLayout -Filter "*.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    }
                    if (-not $boot) {
                        Warn "Could not find an SSMS bootstrapper in the layout - skipping SSMS."
                    } else {
                        Info "Installing SSMS from the offline layout via the Visual Studio Installer."
                        Info "This runs silently and can take SEVERAL MINUTES to complete - please wait..."
                        $proc = Start-Process -FilePath $boot.FullName `
                            -ArgumentList "--quiet","--norestart","--wait","--noWeb" `
                            -Verb RunAs -Wait -PassThru
                        Info "SSMS layout installer returned exit code $($proc.ExitCode)."
                        if (Find-SsmsExe) { Ok "SSMS installed from offline layout." }
                        else { Warn "SSMS not detected after offline layout install; check the VS Installer logs." }
                    }
                } else {
                    Info "SSMS not included in the offline bundle - skipping."
                }
            } else {
                Install-SSMS -SsmsUrl $SsmsUrl -tempDir $tempDir
            }
        } elseif (-not [Environment]::UserInteractive) {
            Info "Skipping SSMS install - no interactive desktop session detected."
        }

        # Test IIS and other functions are installed.
        Info "Checking current IIS Status on system..."
        $features = Test-IISFeatures
        Install-IIS -IISInstalled $features.IISInstalled -WebIPInstalled $features.WebIPInstalled

        # Install IIS Dependencies
        # Install IIS URL Rewrite
        if(-not (Test-IISUrlRewrite)){
        Install-URLRewrite -RewriteUrlBase $RewriteUrlBase -tempDir $tempDir @rewriteSplat
        }

        # Install and Activate IIS ARR (Advanced Request Routing)
        $arrStatus = Test-IISARR
        Install-ARR -ARRInstalled $arrStatus.ARRInstalled -ARRActivated $arrStatus.ARRActivated -ArrUrl $ArrUrl -tempDir $tempDir @arrSplat
    }

    # Dump out of Script if we are in PreReq Only Mode (prevent from running further)
    if ($PreReqOnly) {
        Write-Host "`n"
        Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
        Write-Host $asciiLogo
        Write-Host "Prerequisite installation completed..." -ForegroundColor Green
        Write-Host "You can now complete your PowerSyncPro Installation using the PowerSyncPro MSI."
        Write-Host "Once the installation is completed and PowerSyncPro is running, you can"
        Write-Host "complete installation by running this script with the -CompletionOnly flag."
        Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
        exit 0
    }

    # Install PSP if we are not in PreReq / Completion / IISOnly Mode
    if (-not $PreReqOnly -and -not $ReverseProxyOnly) {
        # Install PSP, choose proper database for installation type.
        Info ("Installing PowerSyncPro using SQL instance '{0}'..." -f $SqlInstance)
        if ($UseServiceAccount -eq $true) {
            Install-PSP -PSPUrl $PSPUrl -tempDir $TempDir -SqlAddress $SqlAddress -SqlPort $SqlPort `
                        -SqlInstance $SqlInstance -SqlDatabase $SqlDatabase -FrontendHost $FrontendHost `
                        -httpPort $KestrelHttpPort -httpsPort $KestrelHttpsPort `
                        -PSPServiceUser $PSPServiceUser -PSPServicePassword $PSPServicePassword
        }
        else {
            Install-PSP -PSPUrl $PSPUrl -tempDir $TempDir -SqlAddress $SqlAddress -SqlPort $SqlPort `
                        -SqlInstance $SqlInstance -SqlDatabase $SqlDatabase -FrontendHost $FrontendHost `
                        -httpPort $KestrelHttpPort -httpsPort $KestrelHttpsPort
        }
    }

    # Setup Service Dependencies in Full Mode Only
    # If Script is in Normal mode and if we are not using an external server (-not $ExternalServerInUse)
    # Skipped in -IISOnly mode - there is no local PowerSyncPro or SQL service on a proxy box.
    if (-not $PreReqOnly -and -not $ExternalServerInUse -and -not $ReverseProxyOnly) {
        # Determine SQL Server service name for dependency
        $SQLInstanceTemp = $SqlInstance

        try {
            if ($SQLInstanceTemp -eq "MSSQLSERVER") {
                $ExpectedSQLServiceName = "MSSQLSERVER"
            }
            else {
                $SqlService = Test-SqlInstanceService -InstanceName $SQLInstanceTemp
                if ($null -ne $SqlService) {
                    $ExpectedSQLServiceName = $SqlService.Name
                }
                else {
                    Warn ("SQL instance '{0}' not found as a service. Using expected service name." -f $SQLInstanceTemp)
                    $ExpectedSQLServiceName = "MSSQL`$$SQLInstanceTemp"
                }
            }
        }
        catch {
            Warn ("Error while checking SQL service for instance '{0}': {1}" -f $SQLInstanceTemp, $_.Exception.Message)

            if ($SQLInstanceTemp -eq "MSSQLSERVER") {
                $ExpectedSQLServiceName = "MSSQLSERVER"
            }
            else {
                $ExpectedSQLServiceName = "MSSQL`$$SQLInstanceTemp"
            }
        }

        # Set PSP to be Dependent on SQL running before it starts as a service.
        Add-ServiceDependency -ServiceName "PowerSyncPro" -DependsOn $ExpectedSQLServiceName
    }

    # Complete Script if not in PreReqOnly mode.
    if (-not $PreReqOnly) {
        # Drop Support Scripts and custom Webconfig - We don't check that they already exist.
        # In offline mode these are sourced from the bundle's scripts\ folder
        # instead of GitHub (passed via -LocalPath through the splats below).
        $offlineInstall = ($script:OfflineMode -eq 'Install')

        # ACME Cert Puller - if doing a LetsEncrypt Certificate
        if ($CertType -eq "LetsEncrypt"){
            Info "Installing ACME / LetsEncrypt Certificate Tool `($CertPullerScriptName`) to $ScriptFolder"
            Install-Scripts -TargetFile $CertPullerScriptName -TargetFolder $ScriptFolder -URL $CertPullerURL
        }

        # Cert Renewer - for any certificate the operator supplies and has to renew
        # themselves. Someone using an already-installed certificate needs this at least as
        # much as a BYOC user, since they typically no longer have the original PFX.
        if ($CertType -eq "BYOC" -or $CertType -eq "Existing"){
            $renewerSplat = @{}
            if ($offlineInstall) { $renewerSplat['LocalPath'] = (Resolve-OfflineAsset -Key 'cert-renewer') }
            Info "Installing Certificate Renewal Tool `($CertRenewerScriptName`) to $ScriptFolder"
            Install-Scripts -TargetFile $CertRenewerScriptName -TargetFolder $ScriptFolder -URL $CertRenewerURL @renewerSplat
        }

        # WebConfig Editor Tool
        $webcfgSplat = @{}
        if ($offlineInstall) { $webcfgSplat['LocalPath'] = (Resolve-OfflineAsset -Key 'webconfig') }
        Info "Installing Web.Config Editor Tool `($WebConfigScriptName`) to $ScriptFolder"
        Install-Scripts -TargetFile $WebConfigScriptName -TargetFolder $ScriptFolder -URL $WebConfigScriptURL @webcfgSplat

        # Install Custom WebConifg
        Info "Installing Customized $WebConfigName to $WebConfigFolder"
        if ($RemoteBackend) {
            # Standalone proxy: forward to the REMOTE PowerSyncPro given by -PSPBackendUrl
            # rather than a local Kestrel port. The admin site is locked down by default so
            # only /Agent is published here; -NoLockAdmin opts out and keeps the localhost
            # allow. The /.well-known exception is retained ONLY for LetsEncrypt (ACME
            # HTTP-01); BYOC / SelfSigned / Existing deny it via -DenyWellKnown.
            Install-WebConfig -FrontendHost $FrontendHost -TargetFolder $WebConfigFolder -TargetFile $WebConfigName -BackendUrl $PSPBackendUrl -LockAdmin:$LockAdminSite -DenyWellKnown:($CertType -ne "LetsEncrypt")
        }
        else {
            # PowerSyncPro is on this server. $KestrelHttpPort is either the port this run
            # passed to the MSI, or - in reverse-proxy mode - the port discovered from the
            # existing installation's appsettings.json.
            Install-WebConfig -FrontendHost $FrontendHost -TargetFolder $WebConfigFolder -TargetFile $WebConfigName -KestrelHttpPort $KestrelHttpPort
        }

        # Setup IIS and Unlock Required Sections
        Info "Unlocking configuration section for web.config..."
        Initialize-IIS

        # Add Frontend Host to local Hosts File. Capture the bool - uncaptured it
        # prints a bare "False" into the console output on failure.
        Info "Editing Hosts file to add entry for $FrontendHost pointing to 127.0.0.1..."
        $hostsUpdated = Install-HostsFile -FrontendHost $FrontendHost
        if (-not $hostsUpdated) {
            Warn "Continuing without the hosts entry - the reverse proxy still works, but local requests to $FrontendHost will resolve via DNS instead of loopback."
        }

        # Add Firewall Rule for Port 443
        # 443/tcp inbound is the PRIMARY client-facing rule for the reverse proxy.
        # (Port 80/tcp is opened only when LetsEncrypt is chosen - see the LetsEncrypt
        # certificate branch below - for the ACME HTTP-01 challenge. There is no dedicated
        # HTTP :80 -> HTTPS :443 redirect binding; the HTTP-to-HTTPS redirect is a URL
        # Rewrite rule in web.config operating on the IIS default-site :80 binding.)
        Info "Opening Port 443 on Firewall for IIS..."
        Add-FirewallRuleForPort -Port 443

        # -IISOnly OUTBOUND note.
        # Windows allows outbound traffic by default, so no outbound firewall rule is
        # created here. However, a hardware / perimeter firewall must permit this proxy
        # box to reach the REMOTE PSP backend. Document the required outbound host:port
        # (derived from -PSPBackendUrl) so a network admin can mirror it upstream.
        if ($RemoteBackend -and -not [string]::IsNullOrWhiteSpace($PSPBackendUrl)) {
            $backendUri = [uri]$PSPBackendUrl
            Warn "NETWORK ADMIN ACTION: allow OUTBOUND from this proxy to the PSP backend on a hardware firewall."
            Info ("  Required outbound destination: {0}/tcp (host '{1}', from URL {2})" -f $backendUri.Port, $backendUri.Host, $PSPBackendUrl)
            Info  "  Windows permits this outbound traffic by default; no local outbound rule was created."
        }

        # Harden TLS / SSL - Disable Insecure Ciphers
        Harden-TlsConfiguration

        # Install certificate depending on type chosen at beginning if script.
        switch ($CertType) {
            'LetsEncrypt' {
                Info "Installation tasks completed, getting a certificate from LetsEncrypt for $FrontendHost..."
                try{
                    Info "Opening Port 80 on Firewall for IIS, ensuring LetsEncrypt can reach server..."
                    Add-FirewallRuleForPort -Port 80
                    # Run Cert Puller Script to Install Scripts
                    Info "Running CertPuller Script to grab LetsEncrypt Certificate for $FrontendHost..."
                    Install-ACMECertificate -FrontendHost $FrontendHost -ContactEmail $CertConfig.Email -KestrelHttpsPort $KestrelHttpsPort

                    if ([string]::IsNullOrWhiteSpace($PSPServiceUser) -or
                        $PSPServiceUser -eq "LocalSystem" -or
                        $PSPServiceUser -eq "NT AUTHORITY\SYSTEM" -or
                        $PSPServiceUser -eq "NT AUTHORITY\NetworkService" -or
                        $PSPServiceUser -eq "NT AUTHORITY\LocalService") {
                            Info "Skipping private key ACL update: service user is blank or system account."
                            $certInstalled = $true
                        }
                    else {
                        if (-not (Test-AndFixCertPermissions -Domain $FrontendHost -User $PSPServiceUser)) {
                            Warn "Private key ACL update failed or not required. Continuing..."
                        } else {
                            Ok "Private key ACL verified for $PSPServiceUser"
                            $certInstalled = $true
                        }
                    }

                    # Register Scheduled Task to Renew Certificate.
                    Info "Registering Scheduled task to renew LetsEncrypt Certificate..."
                    Register-CertRenewalScheduledTask -Domain $FrontendHost -ContactEmail $CertConfig.Email
                    Ok "Scheduled task registered..."
                    
                } catch {
                    Warn "LetsEncrypt install failed: $($_.Exception.Message)"
                    # --- DEBUG: Check the certificate type and private key provider ---
                    try {
                        $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
                            Where-Object { $_.Subject -like "*$FrontendHost*" } |
                            Sort-Object NotAfter -Descending |
                            Select-Object -First 1

                        if ($null -eq $cert) {
                            Warn "DEBUG: No certificate found for $FrontendHost after Install-ACMECertificate."
                        }
                        else {
                            Info "DEBUG: Retrieved cert subject: $($cert.Subject)"
                            Info "DEBUG: Cert has private key: $($cert.HasPrivateKey)"
                            
                            # Test if CAPI (legacy) or CNG (modern) key
                            try {
                                $null = $cert.PrivateKey.CspKeyContainerInfo.ProviderName
                                Ok "DEBUG: Certificate uses CAPI (CSP) provider: $($cert.PrivateKey.CspKeyContainerInfo.ProviderName)"
                            }
                            catch {
                                if ($cert.PrivateKey -is [System.Security.Cryptography.RSACng]) {
                                    Warn "DEBUG: Certificate uses CNG (KSP) provider: Microsoft Software Key Storage Provider"
                                }
                                else {
                                    Warn "DEBUG: Unknown key provider type for certificate."
                                }
                            }
                        }
                    }
                    catch {
                        Warn "DEBUG: Error while inspecting certificate: $_"
                    }
                    exit 1
                    # --- END DEBUG BLOCK ---
                    
                    $certInstalled = $false
                }
            }
            'BYOC' {
                Info "Installation tasks completed, installing BYOC certificate for $FrontendHost..."
                try{
                    $certInstalled = Install-CustomPfxCertificate -PfxPath $CertConfig.PfxPath -Password $CertConfig.PfxPass -KestrelHttpsPort $KestrelHttpsPort -SkipAppSettings:$RemoteBackend
                } catch {
                    Warn "BYOC certificate install failed: $($_.Exception.Message)"
                    $certInstalled = $false
                }
            }
            'SelfSigned' {
                try{
                    Info "Installation tasks completed, installing self-signed certificate for $FrontendHost..."
                    $certInstalled = Install-SelfSignedCertificate -DnsName $FrontendHost -KestrelHttpsPort $KestrelHttpsPort -SkipAppSettings:$RemoteBackend
                } catch {
                    Warn "Self Signed certificate install failed: $($_.Exception.Message)"
                    $certInstalled = $false
                }
            }
            'Existing' {
                # The certificate is already in the store, so there is nothing to import or
                # generate - it only has to be applied. -RemoveOldSameSubject is deliberately
                # NOT passed here: a sibling certificate sharing this subject may be in use
                # elsewhere on the server, and deleting an operator's own certificate would
                # be unrecoverable.
                Info "Installation tasks completed, applying the existing certificate for $FrontendHost..."
                try{
                    $certInstalled = Set-PspCertificate -Thumbprint $CertConfig.Thumbprint -KestrelHttpsPort $KestrelHttpsPort -SkipAppSettings:$RemoteBackend
                } catch {
                    Warn "The existing certificate could not be applied: $($_.Exception.Message)"
                    $certInstalled = $false
                }
            }
            default {
                Warn "Unknown certificate type: $CertType - Certificate has not been installed.  Please contact support."
                $certInstalled = $false
            }
        }

        # Handle Certificate Installation Failures.
        if ($certInstalled) {
            Ok "Certificate installation completed successfully."
        }
        else {
            Err "Certificate installation failed."

            switch ($CertType) {
                'LetsEncrypt' {
                    Write-Host "Troubleshooting steps for LetsEncrypt:" -ForegroundColor Yellow
                    Write-Host " - Ensure Port 80 is open to the Internet (Firewall / NSG / load balancer rules)." -ForegroundColor Yellow
                    Write-Host " - Verify DNS A record for $FrontendHost points to this systems public IP." -ForegroundColor Yellow
                    Write-Host " - The script to retry is located at: C:\Scripts\Cert-Puller_PoshACME.ps1" -ForegroundColor Yellow
                    Write-Host " - Example retry command:" -ForegroundColor Yellow
                    Write-Host "   `"C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain $FrontendHost -ContactEmail $($CertConfig.Email)`"" -ForegroundColor Cyan
                }

                'BYOC' {
                    Write-Host "Troubleshooting steps for BYOC (PFX Import):" -ForegroundColor Yellow
                    Write-Host " - Ensure the PFX file exists at: $($CertConfig.PfxPath)" -ForegroundColor Yellow
                    Write-Host " - Verify the password is correct and contains the private key." -ForegroundColor Yellow
                    Write-Host " - Confirm the certificate subject matches the intended hostname $FrontendHost." -ForegroundColor Yellow
                    Write-Host "Contact Support if you continue to have issues."
                }

                'SelfSigned' {
                    Write-Host "Troubleshooting steps for Self-Signed certificates:" -ForegroundColor Yellow
                    Write-Host " - Ensure the FQDN you provided ($FrontendHost) is correct." -ForegroundColor Yellow
                    Write-Host " - Be aware self-signed certs may cause SSL/TLS trust warnings in browsers and clients." -ForegroundColor Yellow
                    Write-Host " - If possible, consider switching to LetsEncrypt or BYOC for production environments." -ForegroundColor Yellow
                }

                'Existing' {
                    Write-Host "Troubleshooting steps for an existing certificate:" -ForegroundColor Yellow
                    Write-Host " - Confirm the certificate is still present in the LocalMachine\My store:" -ForegroundColor Yellow
                    Write-Host "   Get-ChildItem Cert:\LocalMachine\My\$($CertConfig.Thumbprint)" -ForegroundColor Cyan
                    Write-Host " - Confirm it still has an associated private key (HasPrivateKey must be True)." -ForegroundColor Yellow
                    Write-Host " - Confirm the certificate covers the hostname $FrontendHost." -ForegroundColor Yellow
                    Write-Host " - Check the IIS HTTPS binding on port 443:" -ForegroundColor Yellow
                    Write-Host "   netsh http show sslcert" -ForegroundColor Cyan
                    Write-Host "Contact Support if you continue to have issues."
                }

                default {
                    Write-Host "Unknown certificate type $CertType - no troubleshooting guidance available. Contact Support." -ForegroundColor Yellow
                }
            }
        }

        # Complete. Let the user know that installation is complete.

        # Ensure that the dash deliminator at the top and bottom of this block is not changed, the Azure Image uses it to write the readme. -JRR
        Write-Host "`n"
        # Don't remove or change this, see above.
        Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
        Write-Host $asciiLogo
        if ($certInstalled) {
            Write-Host "Installation Complete and Certificate Installed..." -ForegroundColor Green
        }
        else {
            Write-Host "Installation Complete but Certificate Installation Failed..." -ForegroundColor Red
        }
        Write-Host "`n"

        # Print Relevant Info per Certificate Type
        switch($CertType){
            'LetsEncrypt' {
                Write-Host "LetsEncrypt certificates must be renewed every 90 days." -ForegroundColor Cyan
                Write-Host "A scheduled task has been installed to run C:\Scripts\Cert-Puller_PoshACME.ps1 every week to check the status of the"
                Write-Host "certificate and renew it if necessary."
                Write-Host "You must leave Port 80 on this server exposed to the Internet for sucessful certificate renewals."
            }
            'BYOC' {
                Write-Host "Your BYOC PFX Certificate has been installed." -ForegroundColor Cyan
                Write-Host "To renew your certificate, please use the renewal script at C:\Scripts\Cert-Renewer.ps1"
            }
            'Existing' {
                Write-Host "The certificate already installed on this server is now bound to IIS." -ForegroundColor Cyan
                Write-Host ("Thumbprint {0}, expires {1:yyyy-MM-dd}." -f $CertConfig.Thumbprint, $CertConfig.NotAfter)
                Write-Host "No copy of the PFX was needed and nothing was removed from the certificate store."
                Write-Host "To replace this certificate later, use the renewal script at C:\Scripts\Cert-Renewer.ps1"
            }
        }
        Write-Host "`n"
        if ($RemoteBackend) {
            Write-Host "This server was configured as a REVERSE PROXY ONLY (no PowerSyncPro / SQL installed here)." -ForegroundColor Cyan
            Write-Host ("Client HTTPS traffic to https://{0}/ is forwarded to the remote PowerSyncPro backend: {1}" -f $FrontendHost, $PSPBackendUrl) -ForegroundColor Cyan
            Write-Host ("Ensure any hardware / perimeter firewall allows OUTBOUND from this box to {0}:{1}/tcp." -f ([uri]$PSPBackendUrl).Host, ([uri]$PSPBackendUrl).Port) -ForegroundColor Yellow
            Write-Host "`n"

            if ($LockAdminSite) {
                Write-Host "This proxy publishes ONLY /Agent (https://$FrontendHost/Agent) to the remote PowerSyncPro server." -ForegroundColor Cyan
                Write-Host "The PSP admin site is fully blocked here (including localhost) by design." -ForegroundColor Cyan
                Write-Host "Manage PSP admin directly on the PowerSyncPro server over the internal network." -ForegroundColor Cyan
                if ($CertType -eq "LetsEncrypt") {
                    Write-Host "The /.well-known path stays open only to serve LetsEncrypt ACME challenge tokens." -ForegroundColor Cyan
                }
                else {
                    Write-Host "The /.well-known path is also locked down (not needed without LetsEncrypt/ACME)." -ForegroundColor Cyan
                }
            }
            else {
                Warn "ADMIN LOCKDOWN DISABLED (-NoLockAdmin) on this internet-facing proxy."
                Warn "The PSP admin site is reachable per the localhost-allow web.config (root ipSecurity retains the 127.0.0.1 allow)."
                Warn "Run C:\Scripts\WebConfig_Editor.ps1 to control which client IPs may reach the admin site."
                if ($CertType -eq "LetsEncrypt") {
                    Write-Host "This proxy forwards https://$FrontendHost/ to the remote PowerSyncPro server; /Agent and /.well-known remain published." -ForegroundColor Cyan
                }
                else {
                    Write-Host "This proxy forwards https://$FrontendHost/ to the remote PowerSyncPro server; /Agent remains published (/.well-known denied - no LetsEncrypt/ACME)." -ForegroundColor Cyan
                }
            }
        }
        else {
            if ($ReverseProxyOnly) {
                Write-Host "The IIS reverse-proxy layer was configured in front of the PowerSyncPro already installed on this server." -ForegroundColor Cyan
                Write-Host ("Client HTTPS traffic to https://{0}/ is forwarded to http://localhost:{1}." -f $FrontendHost, $KestrelHttpPort) -ForegroundColor Cyan
                Write-Host "`n"
            }
            Write-Host "Admin access to PSP via the Reverse Proxy - e.g. https://$FrontendHost has been restricted to localhost only." -ForegroundColor Cyan
            Write-Host "You can modify hosts which are allowed to access the HTTPS Reverse Proxy by running C:\Scripts\WebConfig_Editor.ps1."
            Write-Host "This restriction does not apply on https://$FrontendHost/Agent which is used for the PSP Migration Agent."
            Write-Host "`n"
            if ([Environment]::UserInteractive) {
                Write-Host "You can now access PowerSyncPro at https://$FrontendHost/ from this system." -ForegroundColor Yellow
            } else {
                Write-Host "PowerSyncPro is now available at https://$FrontendHost/ from any machine that can reach this server." -ForegroundColor Yellow
                Write-Host "Admin access is currently restricted to localhost - run C:\Scripts\WebConfig_Editor.ps1 to allow access from your IP before logging in." -ForegroundColor Yellow
            }
        }
        if (-not $ReverseProxyOnly) {
            Write-Host "The default password is admin / 123qwe, please change it." -ForegroundColor Yellow
        }
        Write-Host "`n"
        Write-Host "We recommend you reboot your server before using PowerSyncPro." -ForegroundColor Yellow
        Write-Host "If you need additional support or assistance:"
        Write-Host "PowerSyncPro Knowledge Base: https://kb.powersyncpro.com/"
        Write-Host "Open a ticket at https://support.powersyncpro.com/portal."
        Write-Host "`n"
        Write-Host "Congrats!" -ForegroundColor Green
        # Don't remove or change this, see above.
        Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
    }
    
}
catch {
    Write-Error "Unhandled error: $($_.Exception.Message)"
}
finally{
    Stop-Transcript
}
