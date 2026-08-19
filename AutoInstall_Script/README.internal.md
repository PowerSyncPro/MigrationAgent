# PSP_AutoInstall - Internal Developer Reference

> **Internal / maintainers only.** This explains how the PowerSyncPro automated
> installer is structured, how it flows, what every function does, and where the
> sharp edges are. End-user documentation lives in `README.md` and the KB.

## File status

| File | Role |
|------|------|
| `PSP_AutoInstall.ps1` | Production installer, **v1.0** (promoted 2026-08-18): offline / air-gapped support (`-PrepareOffline` / `-InstallOffline`), reverse-proxy-only mode (`-ReverseProxyOnly`, absorbing Trevor's `-IISOnly`), the Existing certificate type, download timeouts, hardened hosts-file update. **This document describes this file.** |
| `Install_SSMS.ps1`, `Install_SSMS_Simple.ps1` | Standalone SSMS silent-install test harnesses from the SSMS 21/22 bootstrapper fix. Not part of the installer. |

History: v1.0 was developed as `PSP_AutoInstall_withOffline.ps1` (merging the offline
fork with Trevor's `colleague_versions/PSP_AutoInstall_IISOnly.ps1`; both files removed
at promotion - git history has them). Validated by an automated 31-case harness against
real Server 2025 VMs - ALL 31 PASSING, re-validated in a full overnight sweep
2026-08-18: full installs including live LetsEncrypt issuances, air-gapped installs
from offline bundles with and without SSMS, reverse proxy, existing-cert, guard-rail,
and elevation cases, plus live-application checks (portal API login and TLS
certificate presentation). The promoted file is byte-identical to the tested build.

---

## 1. What it does

Installs PowerSyncPro (PSP) and all prerequisites on a Windows Server, then
hardens the box and configures TLS. Resulting topology:

```
  Internet / LAN
        |
        v
  IIS (ports 80/443)              <- reverse proxy, NOT configurable by installer
   |  - URL Rewrite + ARR proxy
   |  - forces HTTP -> HTTPS
   |  - locks admin UI to 127.0.0.1 (except /Agent and /.well-known)
   v
  Kestrel (PSP app)              <- HTTP 5000 / HTTPS 5001 default (configurable)
        |
        v
  SQL Server Express             <- local instance, or an external SQL server
```

Prerequisites: .NET 8 ASP.NET Core Hosting Bundle, VC++ 2015-2022 x64, SQL Express
(optional), SSMS (optional, interactive desktop only), IIS + URL Rewrite + ARR, and
the PSP MSI. Post-install: maintenance scripts, reverse-proxy `web.config`, hosts
entry, firewall ports, SCHANNEL hardening, and a certificate.

## 2. Requirements

- Windows Server 2016 or newer (`Test-IsServer2016OrNewer`).
- Administrator elevation for every install mode (enforced at runtime).
- Internet for a normal install, or a prepared bundle for offline.
- PowerShell 5.1 compatible: **ASCII-only source, no `?.` / `&&` / ternary.**

## 3. Parameters

| Parameter | Type | Purpose |
|-----------|------|---------|
| `-PSPUrl` | string | PSP MSI download URL, **or** a local `.msi` path to pin a version. |
| `-PSPServiceUser` | string | Service account (`DOMAIN\User` / `.\LocalUser`). Blank = LocalSystem. |
| `-PSPServicePassword` | string | Password for the service account (plaintext, for MSI). |
| `-PreReqOnly` | switch | Install prerequisites only; stop before the PSP MSI. |
| `-ReverseProxyOnly` | switch | Configure only the IIS reverse-proxy layer + cert + hardening. Local backend by default (Kestrel port read from appsettings.json); remote backend with `-PSPBackendUrl`. Interactive session required. |
| `-PSPBackendUrl` | string | Absolute http/https URL of a REMOTE PSP backend. Its presence flips `-ReverseProxyOnly` into standalone-proxy shape. ValidateScript-enforced. |
| `-NoLockAdmin` | switch | Opt out of the standalone-proxy admin lockdown. Remote-backend only. |
| `-CompletionOnly` | switch | Deprecated alias for `-ReverseProxyOnly` (warns, then maps). |
| `-IISOnly` | switch | Deprecated alias for `-ReverseProxyOnly` (warns, then maps). |
| `-Headless` | switch | Reduce prompts; **only valid with `-PreReqOnly`**; assumes default SQL instance. Rejected in reverse-proxy mode. |
| `-KestrelHttpPort` | int | Kestrel HTTP backend port (default 5000). |
| `-KestrelHttpsPort` | int | Kestrel HTTPS backend port (default 5001). |
| `-PrepareOffline` | switch | Build an offline bundle at `-OfflinePath`, then exit. Online-only, runs non-elevated. Rejected alongside any install-mode flag. |
| `-InstallOffline` | switch | Install using payloads from a prepared bundle; no internet used. |
| `-OfflinePath` | string | Bundle dir (output for prepare, source for install). Default `.\PSP_Offline`. |
| `-IncludeSSMS` | switch | While preparing, also build the large SSMS offline layout. Prepare-only. |

## 4. Operating modes and flag compatibility

| Mode | What runs |
|------|-----------|
| **Normal** (no mode flag) | Full install: prereqs -> PSP MSI -> cert + hardening. Interactive wizard. |
| **`-PreReqOnly`** | Prereqs only, then `exit 0`. No PSP, no cert. |
| **`-ReverseProxyOnly`** | IIS stack + cert + hardening only; no prereqs, no PSP MSI. Local shape reads the Kestrel port from appsettings.json and warns (not exits) if the PSP service is stopped; remote shape (`-PSPBackendUrl`) proxies another server and locks the admin site down unless `-NoLockAdmin`. The IIS stack installs BEFORE the certificate menu so existing bindings can be enumerated. |
| **`-CompletionOnly` / `-IISOnly`** | Deprecated aliases: warn, then run as `-ReverseProxyOnly`. |
| **`-Headless`** | Automation lane for `-PreReqOnly` (no prompts, default SQL instance). |
| **`-PrepareOffline`** | Downloads everything into a bundle + manifest, then `exit 0`. Never installs. |
| **`-InstallOffline`** | Modifier: verifies bundle, then runs the normal install sourcing from it. |

### Offline flag matrix (`-InstallOffline`)

| Flag | Works offline? | Notes |
|------|----------------|-------|
| `-OfflinePath` | Required | Points at the bundle. |
| `-PreReqOnly` | Yes | Installs deps from bundle, stops before PSP. |
| `-CompletionOnly` | Yes | Cert/hardening local; helper scripts sourced from bundle. |
| `-PSPServiceUser` / `-PSPServicePassword` | Yes | Local/domain service account, no network. |
| `-KestrelHttpPort` / `-KestrelHttpsPort` | Yes | Pure config. |
| `-Headless` | Yes (with `-PreReqOnly`) | Non-interactive -> SSMS auto-skipped. |
| `-PSPUrl` | Yes, if a local file | A local `.msi` is honored; a URL falls back to the bundle MSI. |
| `-PrepareOffline` / `-IncludeSSMS` | No | Prepare-only; mutually exclusive with install. |

**Certificate offline:** LetsEncrypt is suppressed (needs internet + public DNS).
BYOC (PFX), self-signed and Existing are offered. There is **no fully-unattended
full offline install** today (Headless is PreReqOnly-only; a full install needs
the interactive cert menu).

---

## 5. Main execution flow

Everything below the function definitions runs inside one `try/catch/finally`.

1. **Dot-source guard** - if dot-sourced, `return` (load functions only).
2. **Logging** - Prepare-mode log goes to `%TEMP%` (workstation may lack `C:\Temp`);
   otherwise `C:\Temp\PSP_AutoInstall.txt`. `Start-Transcript` + exit handler.
3. **Flag validation** - reject `PreReqOnly+CompletionOnly`, `PrepareOffline+InstallOffline`,
   `IncludeSSMS` without `PrepareOffline`.
4. **Offline dispatch:**
   - `-PrepareOffline`: reject install-time flags, create bundle dirs, run
     `Invoke-PrepareOffline`, **`exit 0`**.
   - `-InstallOffline`: require `manifest.json`, `Test-BundleIntegrity` (SHA256),
     `Unblock-File` the bundle (clears Mark-of-the-Web), then fall through.
5. **Elevation check** - after the offline dispatch (so Prepare can run non-elevated);
   all remaining paths require Administrator.
6. **More flag validation** - service accounts incompatible with PreReq/Completion;
   Headless requires PreReqOnly; user/password must be supplied together.
7. **Mode notifications** - PreReqOnly banner; CompletionOnly verifies PSP is running.
8. **Service-account resolution** - expand `.\user`, validate `DOMAIN\User`, check
   credentials, set `$UseServiceAccount`.
9. **Pre-install checks** - abort if PSP already present; require Server 2016+; warn
   about non-interactive (Server Core / remote PS) caveats.
10. **SQL target selection** (`Select-SqlTarget`) - existing local instance, external
    SQL (CompletionOnly), or new SQL Express. Headless forces the default instance.
11. **Kestrel port selection** - confirm free ports; prompt for alternatives only on
    conflict. Skipped under Headless.
12. **Full port-conflict check** - 80/443 conflicts warn (IIS may be overwritten);
    Kestrel conflicts are a fatal safeguard.
13. **Certificate wizard** (`Run-Wizard`) - collects cert type + hostname. Skipped in PreReqOnly.
14. **Dependency install** (skipped in CompletionOnly):
    - Populate offline splats (`$dnSplat`, `$vcSplat`, `$rewriteSplat`, `$arrSplat`,
      `$sqlSplat`) - empty online, `LocalPath`/`LocalMediaPath` offline. PSP MSI:
      honor a local `-PSPUrl`, else resolve from bundle.
    - .NET 8 hosting -> VC++ -> SQL Express -> SSMS -> IIS -> URL Rewrite -> ARR.
    - SSMS offline: import layout certs (`*.cer`->Root, `*.crt`->CA) then run the
      layout bootstrapper `--quiet --norestart --wait --noWeb`.
15. **PreReqOnly exit** - banner, `exit 0`.
16. **PSP MSI install** (`Install-PSP`) - SQL params, Kestrel ports, optional service creds.
17. **Service dependency** - PSP depends on the SQL service (local SQL only).
18. **Completion tasks** (skipped in PreReqOnly):
    - Drop maintenance scripts (ACME puller for LetsEncrypt, renewer for BYOC, always
      the web.config editor) - offline-sourced from the bundle.
    - Write reverse-proxy `web.config`, unlock IIS sections, hosts entry, open 443,
      harden TLS.
    - Install cert by type: `LetsEncrypt` (ACME + renewal task), `BYOC` (PFX),
      `SelfSigned`, or `Existing` (already in the store) - all four apply through
      `Set-PspCertificate`.
    - Final completion banner (its dashed lines are parsed by the Azure image README
      generator - do not reformat).

---

## 6. Offline / air-gapped feature

### Bundle layout (`-OfflinePath`)

```
manifest.json                 SHA256 inventory + prep metadata
PSP_AutoInstall.ps1           copy of the installer (run this on the target)
README.txt                    generated operator instructions
payloads\
  dotnet-hosting-<ver>-win.exe
  vc_redist.x64.exe
  rewrite_amd64_en-US.msi
  requestRouter_amd64.msi
  PowerSyncProInstaller.msi
  SQL\Media\...               SSEI /ACTION=Download output
  SSMS\layout\...             VS offline layout (only if -IncludeSSMS)
    certificates\             layout roots + the PCA 2024 intermediate cert
scripts\
  Cert-Renewer.ps1
  WebConfig_Editor.ps1
```

### The single asset table

`Get-OfflineAssetTable` is the one source of truth. Both `-PrepareOffline` and
`-InstallOffline` iterate it, so they cannot drift. Each asset has: `Key`,
`FileName`, `SubDir`, `SourceUrl`, `Dynamic` (URL resolved at prep time, e.g.
.NET), `Special` (bespoke logic: SQL media / SSMS layout), `Optional` (SSMS).
Cert-Puller (PoshACME) is deliberately excluded - LetsEncrypt cannot run offline.

### Prepare flow (`Invoke-PrepareOffline`)

Wipes `payloads`/`scripts` fresh each run, downloads every asset (**stops on first
failure**), hashes each into the manifest, copies the script + README. SQL media
and the SSMS layout are downloaded in a **separate window** (they attach to the
console and would clobber the status output). SSMS also downloads the "Microsoft
Windows Code Signing PCA 2024" intermediate cert into the layout (see below).

### Install flow

`Test-BundleIntegrity` verifies presence + SHA256 of every required asset before
committing to a long install. `Unblock-File` clears Mark-of-the-Web across the
bundle. Installers receive local paths via splatting; the online code path is
byte-for-byte unchanged when the splats are empty.

### SSMS offline signature gotcha (important)

SSMS 22 ships as a Visual Studio installer. Installing from a layout on an
air-gapped box fails with `0x80131509 / InvalidCertificate` because the layout is
signed by the **Microsoft Windows Code Signing PCA 2024** *intermediate* cert,
which is **not** in the layout's `certificates` folder (that folder only has the
standard 2010/2011 roots, already trusted) and cannot be auto-fetched offline.
Fix (per MS `install-certificates` doc): prepare downloads that intermediate into
`layout\certificates\`; install imports layout `*.cer` -> `Root` and `*.crt` ->
`CA` before running setup. Exit code `3010` from the layout install = success,
reboot required.

---

## 7. Function reference

### Logging
- **Info / Ok / Warn / Err** - colored `Write-Host` helpers (`[*] [+] [!] [-]`).
  Accept only `$Message`; stray `-ForegroundColor` args from some callers are ignored.

### Offline support
- **Initialize-OfflinePaths** - resolves/creates bundle dir layout; sets the
  `$script:BundleDir/PayloadDir/ScriptsDir/ManifestPath` globals.
- **Get-OfflineAssetTable** - the asset inventory (see above).
- **Get-Sha256** - SHA256 of a file.
- **Write-OfflineManifest / Read-OfflineManifest** - JSON manifest I/O (ASCII).
- **Test-BundleIntegrity** - presence + hash check; optional assets warn but pass;
  directory assets are presence-only (`Sha256 = $null`).
- **Resolve-OfflineAsset** - bundle path by key. Returns `$null` for OPTIONAL assets
  absent from the manifest (bundle built without `-IncludeSSMS`) or files missing on
  disk; throws only for keys the asset table does not know (programmer error).
- **Get-DownloadToFile** - `Invoke-WebRequest` with progress suppressed and a timeout.
  EVERY download in the script carries `-TimeoutSec` (`$WebTimeoutSec` 120s for
  metadata/scripts, `$DownloadTimeoutSec` 1800s for payloads): PS 5.1 defaults to
  `-TimeoutSec 0` = wait forever, and a field install HUNG when the corporate
  firewall blackholed GitHub. When adding a download, add the timeout.
- **Resolve-DotNetHostingAsset** - latest .NET 8 hosting bundle URL/version/filename.
- **New-AssetRecord** - builds a manifest record (hash/size/relative path).
- **Write-OfflineReadme** - generates the bundle `README.txt`.
- **Invoke-PrepareOffline** - orchestrates the whole prepare run.

### Dependency installers / tests
- **Install-dotNet8Hosting** / **Test-dotNet8Hosting** - .NET 8 hosting bundle
  (`-LocalPath` for offline; test parses `dotnet --list-runtimes`).
- **Install-VCRedistributable** / **Test-VCRedistributable** - VC++ x64 (`-LocalPath`;
  test checks registry version >= `$vcVer`).
- **Install-SQLExpress** - unattended SQL Express (`-LocalMediaPath` for offline).
  Handles interactive vs non-interactive (`/QS` vs `/Q`), disables update search,
  and runs via a **SYSTEM scheduled task** in remote sessions to dodge the DPAPI
  double-hop failure.
- **Find-SsmsExe** - locates `ssms.exe` for any SSMS version (old + new layouts).
- **Install-SSMS** - silent SSMS; auto-detects bootstrapper (`vs_ssms*`, double-dash
  flags) vs old standalone (slash flags); verifies via `Find-SsmsExe`. **No `-LocalPath`**
  - offline SSMS is handled inline in the main flow via the layout.
- **Test-SSMS** - registry check with a filesystem fallback (`Find-SsmsExe`).
- **Install-IIS** / **Test-IISFeatures** - Web-Server + Web-IP-Security.
- **Install-URLRewrite** / **Test-IISUrlRewrite** - URL Rewrite MSI (`-LocalPath`;
  online picks the OS-locale MSI, offline is always en-US).
- **Install-ARR** / **Test-IISARR** - Application Request Routing + proxy enable.

### PSP + IIS config
- **Install-PSP** - downloads/uses local MSI, builds msiexec args (strips default
  instance flag, wires service account, flips `PSP_USE_LOCAL_KEY` for domain
  accounts, passes the Kestrel ports), installs, polls the service up to 60s.
- **Test-PowerSyncPro** - service Running OR MSI GUID present.
- **Get-KestrelBackendPort** - reads `Kestrel.Endpoints.Http.Url` from
  appsettings.json and regexes the trailing `:port` (the URL is `http://*:5000`
  and `*` is not a legal URI host, so `[uri]` cannot parse it). This is how
  reverse-proxy mode discovers a non-default backend port instead of assuming 5000.
- **Install-Scripts** - writes a script from `-LocalPath` (offline) / `-Encoded` /
  `-Url`, always UTF-8 no-BOM.
- **Install-WebConfig** - generates the reverse-proxy `web.config` (proxy to Kestrel,
  force HTTPS, lock to 127.0.0.1, exempt `/.well-known` for ACME) + branded 403 page.
- **Harden-TlsConfiguration** - disables SSL2/3, TLS1.0/1.1 and weak ciphers via
  SCHANNEL; enables TLS 1.2 (backs up the branch first). Reboot to apply.
- **Initialize-IIS** - unlocks handlers/modules/ipSecurity sections, restarts W3SVC.
- **Install-HostsFile** - points the frontend FQDN at 127.0.0.1 (idempotent, retries).
  Uses direct .NET File I/O, not Set-Content: security software filtering the hosts
  file handed the provider a half-usable handle in the field ("Stream was not
  readable"). Retries EVERY failure (the old code broke out of the retry loop on
  anything that was not an IOException), clears a read-only attribute up front, and
  returns a bool the caller must capture (uncaptured it printed a bare "False").

### Certificate functions

`Set-PspCertificate` is the single apply path; everything else either creates a
certificate or picks one, then calls it.

- **Set-PspCertificate** - the consolidated "certificate exists, make PSP use it"
  path: key ACL via Grant-CertPrivateKeyAccess, appsettings.json update, IIS 443
  binding. Restarts the PSP service ONLY if appsettings.json actually changed.
  `-RemoveOldSameSubject` deletes same-subject siblings - opt-in, passed by the
  PFX/self-signed wrappers (a fresh import supersedes) and NEVER by the Existing
  path (a sibling may be live elsewhere on the server). `-SkipAppSettings` for
  remote-backend proxies with no local PSP.
- **Get-CertPrivateKeyPath / Grant-CertPrivateKeyAccess** - locate the CAPI or CNG
  private-key file and grant the service account read access.
- **Install-CustomPfxCertificate** - imports the BYOC PFX, then Set-PspCertificate
  with `-RemoveOldSameSubject`.
- **Install-SelfSignedCertificate** - generates the cert, then Set-PspCertificate
  with `-RemoveOldSameSubject`. (The old ~90-line duplication with the PFX path is
  gone - both are thin wrappers now.)
- **Install-ACMECertificate** - installs Posh-ACME + runs the LetsEncrypt puller.
- **Get-BoundCertificateThumbprint** - what is bound to 443 right now. Walks EVERY
  `netsh http show sslcert` record and matches the port - taking the first
  Certificate Hash line returns WinRM's localhost cert (5986) on most servers.
- **Select-ExistingCertificate** - the Existing-type picker: enumerates
  `Cert:\LocalMachine\My`, filters out expired / no-private-key / non-server-auth
  certs, and offers the one bound to 443 as the default.
- **Resolve-CertHostname** - shared SAN/wildcard resolver (lifted out of BYOC):
  wildcard certs prompt for an FQDN validated to one-label depth; multi-SAN certs
  present a picker instead of silently taking the first name.
- **Register-CertRenewalScheduledTask** - weekly SYSTEM task for LetsEncrypt renewal.

### Helpers
- **Confirm-YesNo**, **Test-HostnameFormat**, **Test-IsPublicIPv4**, **Resolve-IPv4A**,
  **Get-PublicIPv4**, **Get-PfxSubject** (SAN/CN extraction).
- **Test-PortExternal** - external reachability via PortChecker.io / CanYouSeeMe.
- **Add/Remove-FirewallRuleForPort**, **Get-ListeningPort** (maps PID 4 to IIS sites).
- **Test-IsServer2016OrNewer**, **Add-ServiceDependency** (via `sc.exe`).
- **Test-SqlInstanceService**, **Select-SqlTarget**, **Get-LocalSqlInstances**,
  **Read-InstanceName**, **New-LocalSqlAdminsGroup**.
- **Test-AndFixCertPermissions** (CSP + CNG key ACLs), **Test-UserCredential**.

### Menu / wizard
- **Show-CertificateTypeMenu** - returns `LetsEncrypt` / `BYOC` / `SelfSigned` /
  `Existing`; suppresses LetsEncrypt when `$script:OfflineMode -eq 'Install'`
  (default shifts to BYOC). Accepts numbers or names ('existing' / 'installed').
- **Run-Wizard** - the interactive core; branches per cert type, validates hostname /
  email / DNS / port 80 (LetsEncrypt), PFX + SANs + wildcard host (BYOC), FQDN
  (self-signed), or store selection via Select-ExistingCertificate + hostname via
  Resolve-CertHostname (Existing); returns a `$CertConfig` object. An empty
  `$CertConfig` (e.g. no eligible certificate in the store) loops back to the menu
  instead of falling through.

---

## 8. Certificate handling

| Type | Requirements | What happens |
|------|--------------|--------------|
| **LetsEncrypt** | Internet, public DNS A record, port 80 open | ACME issuance via Posh-ACME puller; weekly renewal task. **Not available offline.** |
| **BYOC** | A `.pfx` with private key | Import, then Set-PspCertificate with `-RemoveOldSameSubject`. Renewer script dropped. |
| **SelfSigned** | none | Generate 1-year cert, then Set-PspCertificate with `-RemoveOldSameSubject`. May reduce functionality. |
| **Existing** | An eligible cert already in `LocalMachine\My` (private key, unexpired, server-auth) | Select-ExistingCertificate picker (443-bound cert is the default), hostname via Resolve-CertHostname, then Set-PspCertificate WITHOUT the sibling removal. No renewal machinery dropped. |

All four paths share Set-PspCertificate, which restarts the PSP service only when
appsettings.json actually changed.

---

## 9. Known issues & tech debt

Consolidated from a full review. None block current use; listed so future edits do
not "normalize" intentional oddities or miss latent bugs.

**Latent bugs**
- **`-ForegroundColor` args are silently dropped** by `Info/Ok/Warn/Err` at many
  call sites (now documented in a comment above the helpers).
- **`Register-CertRenewalScheduledTask`** ends with `Ok "..." -ForegroundColor Green`
  - the extra arg is ignored (intended as color).
- **LetsEncrypt failure block** has an `exit 1` before `$certInstalled = $false`,
  making that assignment dead code.
- **`Install-PSP`** has an unreachable trailing service-warning after an early `return`.
- **`Initialize-IIS` never checks `$LASTEXITCODE`** on its `appcmd unlock` calls, so
  a failed unlock (e.g. Web-IP-Security genuinely missing) is silent until IIS
  serves HTTP 500.19. Mitigated in practice because reverse-proxy mode installs the
  IIS stack before web.config is written (tested), but the calls themselves are
  still unchecked.

**Fixed in v1.0** (was on this list or found by the test harness - do not re-introduce)
- `$certInstalled` uninitialized: crashed under `Set-StrictMode -Version Latest` on
  an unknown cert type or failed LetsEncrypt ACL fix. Now initialized before the switch.
- `Get-BoundCertificateThumbprint` took the FIRST netsh `Certificate Hash` without
  matching the port, pre-selecting WinRM's localhost cert (5986) as "bound to 443".
- Offline installs from a bundle built without `-IncludeSSMS` died after SQL:
  `Resolve-OfflineAsset` threw on the optional `ssms` key missing from the manifest
  instead of returning `$null`. Caught by the air-gap test case.
- The ~90-line appsettings/IIS-binding duplication between the PFX and self-signed
  cert paths - consolidated into `Set-PspCertificate`.

**Naming / consistency**
- ARR online download is `requestRouter_x64.msi` while the bundle uses
  `requestRouter_amd64.msi` (noted in a comment; harmless - offline overrides it).
- `Install-IIS` mixes `Install-WindowsFeature` and the deprecated `Add-WindowsFeature`.
- User-facing typos: "Prequisites"/"Prequisite", "Sucessfully", "WebConifg",
  "sucessful". Cosmetic; not yet fixed to avoid touching operator-visible strings
  without sign-off.

**Duplication**
- The .NET hosting resolve logic exists both inline in `Install-dotNet8Hosting` and
  in `Resolve-DotNetHostingAsset` - keep in sync (offline prepare uses the helper).

**PSScriptAnalyzer warnings (pre-existing)**
- Plaintext password params (`-PSPServicePassword`, `Test-UserCredential -Password`)
  flagged; would ideally be `SecureString`/`PSCredential`.
- Unapproved verbs: `Harden-TlsConfiguration`, `Run-Wizard`.
- Assigned-but-unused: `$accountName`, `$displayList`, `$hostname`; assignment to the
  automatic `$args` variable in one spot.

**By design (do not "fix")**
- **`Test-PortExternal` hardcodes port 80** for its temp firewall rule. This is
  intentional: the function is only used to verify the LetsEncrypt HTTP-01 challenge
  path, which is always port 80. The `$Port` parameter drives the external check, not
  the temp firewall rule.

**Environment caveats**
- Offline IIS features assume Desktop Experience with intact Features-on-Demand
  (installs from local WinSxS). Server Core / stripped images would need `-Source`.
- `appsettings.json` / `web.config` writes use `-Encoding UTF8` (BOM in PS 5.1);
  tolerated but inconsistent with the no-BOM approach elsewhere.

---

## 10. Maintenance notes

- **ASCII only.** The whole file is ASCII-clean; keep it that way (PS 5.1 misreads
  UTF-8 without a BOM). No `?.`, `&&`, or ternary operators.
- **Adding an offline payload:** add one row to `Get-OfflineAssetTable`, add a
  `-LocalPath` branch to the installer, and add a splat entry in the main flow.
  Both modes pick it up automatically.
- **Parse check after edits:**
  `[System.Management.Automation.Language.Parser]::ParseFile(...)` plus an ASCII scan.
- The final completion banner's dashed delimiter lines are consumed by the Azure
  image README generator - do not reformat them.
- Changelog lives in the script header `.NOTES` block; bump `$scriptVer` too.
