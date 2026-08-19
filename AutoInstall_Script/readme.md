# PowerSyncPro Automated Installation Script

## Maintained By
Jamie Richard - jamie.richard@powersyncpro.com

## Description

This script automates the end-to-end installation of PowerSyncPro on a Windows Server, including all prerequisites. It downloads required components from Microsoft, PowerSyncPro, and the PowerSyncPro GitHub, installs and configures IIS as a reverse proxy, sets up SSL, and hardens the server's TLS configuration.

> **Full documentation:** [PowerSyncPro Knowledge Base — Automated Installation Script](https://kb.powersyncpro.com/install-and-configure/powersyncpro-automated-installation-script)

---

## Repository Contents

| File | Description |
|------|-------------|
| `PSP_AutoInstall.ps1` | Main installation script — run as Administrator on the target server |
| `Cert-Puller_PoshACME.ps1` | Requests and renews Let's Encrypt certificates via Posh-ACME. Deployed to `C:\Scripts` during installation. |
| `Cert-Renewer.ps1` | Replaces an existing BYOC certificate on a running PSP install. Deployed to `C:\Scripts` during installation. |
| `WebConfig_Editor.ps1` | Manages the IIS reverse proxy allowed IP list and rewrite FQDN. Deployed to `C:\Scripts` during installation. |

---

## Use Case

This script is intended for new PowerSyncPro installations on a dedicated Windows Server. It handles the full installation lifecycle interactively, including:

- **Standard installations** — downloads and installs all prerequisites, SQL Express, PowerSyncPro, and SSL in a single run.
- **Advanced split installations** — use `-PreReqOnly` to install prerequisites first, then manually install the PSP MSI, then use `-ReverseProxyOnly` to finish the reverse proxy, SSL setup, and hardening.
- **Reverse-proxy-only deployments** — use `-ReverseProxyOnly` to configure just the IIS reverse-proxy layer: against a PowerSyncPro already installed on the same server (the Kestrel port is discovered from `appsettings.json`), or with `-PSPBackendUrl` as a standalone proxy in front of PowerSyncPro on another server.
- **Offline / air-gapped installations** — build a bundle with `-PrepareOffline` on an internet-connected machine, copy it across, and install with `-InstallOffline` with no internet access.
- **Service account deployments** — pass `-PSPServiceUser` and `-PSPServicePassword` to install PowerSyncPro running under a specific domain or local account instead of LocalSystem.

---

## Requirements

- **Windows Server 2016 or newer** (workstation OS is not supported)
- **Run as Administrator** (only `-PrepareOffline` may run unelevated)
- Internet access to download components from Microsoft and PowerSyncPro — or a prepared offline bundle (see Offline Installation)
- **Ports 80 and 443 open** to the Internet (80 required for Let's Encrypt HTTP-01 challenge; 443 for PSP agent and UI access)
- **PowerShell execution policy must allow unsigned scripts** — run `Set-ExecutionPolicy RemoteSigned` or `Bypass` if needed
- For **Let's Encrypt certificates**: a public DNS A record must point to the server's public IP, and a contact email address is required

---

## High-Level Process

### Standard Installation (Recommended)

1. **Run the script** as Administrator on the target Windows Server.
2. **Select a SQL target** — choose an existing local instance, install a new SQL Express instance, or specify an external SQL server.
3. **Configure a certificate** — choose Let's Encrypt (ACME), bring your own PFX, or generate a self-signed certificate.
4. **Script installs automatically** — .NET 8 Hosting Bundle, VC++ Redistributables, SQL Express (if needed), SSMS, IIS with URL Rewrite and ARR, PowerSyncPro MSI, reverse proxy web.config, TLS hardening, and the selected certificate.
5. **Reboot** to apply TLS hardening changes.

### Advanced Split Installation (PreReq + ReverseProxyOnly)

Use this approach when you need to manually install the PowerSyncPro MSI (e.g. for a specific version, external SQL server, or Group Managed Service Account (gMSA)):

1. **Run prerequisites only:**
   ```powershell
   .\PSP_AutoInstall.ps1 -PreReqOnly
   ```
2. **Manually install the PowerSyncPro MSI** on the server.
3. **Complete the installation** (reverse proxy, SSL, hardening):
   ```powershell
   .\PSP_AutoInstall.ps1 -ReverseProxyOnly
   ```
   The Kestrel backend port is read from the installed `appsettings.json`, so a non-default port chosen during the MSI install is picked up automatically. (`-CompletionOnly` and `-IISOnly` still work as deprecated aliases.)

### Standalone Reverse Proxy (Separate Server)

To place an internet-facing IIS reverse proxy on its own server in front of a PowerSyncPro running elsewhere:

```powershell
.\PSP_AutoInstall.ps1 -ReverseProxyOnly -PSPBackendUrl https://psp.corp.local:5001
```

The PSP admin site is locked down by default on a standalone proxy (403 for every source; only `/Agent` and `/.well-known` published). Pass `-NoLockAdmin` to keep the localhost allow instead.

### Offline / Air-Gapped Installation

1. **Build the bundle** on any internet-connected machine (a workstation is fine; no elevation needed):
   ```powershell
   .\PSP_AutoInstall.ps1 -PrepareOffline -OfflinePath C:\PSP_Offline -IncludeSSMS
   ```
2. **Copy the bundle folder** to the air-gapped server.
3. **Install from the bundle** (integrity-verified against its SHA256 manifest first):
   ```powershell
   .\PSP_AutoInstall.ps1 -InstallOffline -OfflinePath C:\PSP_Offline
   ```

Let's Encrypt is unavailable offline — the certificate menu offers BYOC (PFX), self-signed, and existing certificates.

---

## Quick Start

### Standard Installation

```powershell
.\PSP_AutoInstall.ps1
```

### With a Service Account

```powershell
.\PSP_AutoInstall.ps1 -PSPServiceUser "DOMAIN\pspsvc" -PSPServicePassword "P@ssword123"
```

### Using a Local MSI Instead of Downloading

```powershell
.\PSP_AutoInstall.ps1 -PSPUrl "C:\Temp\PowerSyncProInstaller.msi"
```

---

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-PSPUrl` | URL or local file path for the PowerSyncPro MSI. Defaults to the current release download. |
| `-PSPServiceUser` | Optional service account to run PowerSyncPro under (e.g. `DOMAIN\User` or `.\LocalUser`). Defaults to LocalSystem. |
| `-PSPServicePassword` | Password for the service account (required if `-PSPServiceUser` is set). |
| `-PreReqOnly` | Install prerequisites only — skips PSP MSI install, certificate setup, and hardening. |
| `-ReverseProxyOnly` | Configure only the IIS reverse-proxy layer, certificate, and hardening. Local backend by default (Kestrel port read from `appsettings.json`); remote backend with `-PSPBackendUrl`. |
| `-PSPBackendUrl` | Full URL of a remote PowerSyncPro backend (e.g. `https://psp.corp.local:5001`). Makes `-ReverseProxyOnly` a standalone proxy. |
| `-NoLockAdmin` | Opts out of the standalone-proxy admin lockdown (remote backend only). |
| `-CompletionOnly` / `-IISOnly` | Deprecated aliases for `-ReverseProxyOnly`. |
| `-KestrelHttpPort` | Kestrel HTTP backend port (default 5000). |
| `-KestrelHttpsPort` | Kestrel HTTPS backend port (default 5001). |
| `-PrepareOffline` | Build an offline bundle at `-OfflinePath`, then exit. Installs nothing; may run unelevated. |
| `-InstallOffline` | Install from a prepared offline bundle. No internet access used. |
| `-OfflinePath` | Bundle directory — output for `-PrepareOffline`, source for `-InstallOffline`. Default `.\PSP_Offline`. |
| `-IncludeSSMS` | With `-PrepareOffline`, also bundle the (multi-GB) SSMS offline layout. |
| `-Headless` | Suppresses interactive prompts. Only valid with `-PreReqOnly`. Assumes the default MSSQLSERVER SQL instance. Internal use only. |

---

## What Gets Installed

| Component | Notes |
|-----------|-------|
| .NET 8 Hosting Bundle | Latest stable release, downloaded dynamically |
| VC++ Redistributable 2022 (x64) | Minimum version 14.44.35211 |
| SQL Server Express 2025 | Only installed if no existing SQL instance is selected |
| SQL Server Management Studio (SSMS) | Skipped if already installed or using an external SQL server |
| IIS (Web-Server + Web-IP-Security) | Installed if not already present |
| IIS URL Rewrite | Required for reverse proxy |
| IIS Application Request Routing (ARR) | Required for reverse proxy |
| PowerSyncPro MSI | Installed with IIS reverse proxy enabled |
| SSL Certificate | Let's Encrypt, custom PFX, or self-signed |
| TLS Hardening | Disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, and weak ciphers |

---

## Certificate Options

### Let's Encrypt (Recommended for Internet-Facing Servers)

- Port 80 must be open externally for the HTTP-01 ACME challenge.
- A public DNS A record must point to this server.
- Certificates are valid for 90 days; a weekly scheduled task (`LetsEncrypt-CertRenewal`) is created automatically to handle renewal.

### Bring Your Own Certificate (BYOC)

- Provide a PFX file with the private key included.
- Wildcard certificates are supported — you will be prompted to specify the exact FQDN for this host.

### Self-Signed

- Not recommended for production. Endpoints may need the certificate added to their Trusted Root store for full PSP functionality.

### Existing Certificate

- Uses a certificate already installed in the server's `LocalMachine\My` store — no PFX file needed.
- The certificate currently bound to port 443 is offered as the default; expired certificates and those without a private key are filtered out.
- Wildcard certificates prompt for the exact FQDN; multi-SAN certificates present a picker.
- Never deletes other certificates, including ones with the same subject.

---

## Post-Installation

### Admin Access

By default, the IIS reverse proxy restricts access to **localhost only**. Use `WebConfig_Editor.ps1` to manage the allowlist and proxy configuration:

```powershell
# View current allowed IPs and rewrite FQDN
C:\Scripts\WebConfig_Editor.ps1 -GetConfig

# Add one or more IPs or CIDR ranges
C:\Scripts\WebConfig_Editor.ps1 -AddAllowedAddresses "10.0.0.0/8", "192.168.1.50"

# Remove an IP or CIDR range
C:\Scripts\WebConfig_Editor.ps1 -RemoveAllowedAddresses "192.168.1.50"

# Update the reverse proxy rewrite domain (e.g. after a hostname change)
C:\Scripts\WebConfig_Editor.ps1 -SetFQDN "psp.newdomain.com"

# Preview changes without writing to disk
C:\Scripts\WebConfig_Editor.ps1 -AddAllowedAddresses "10.0.0.0/8" -DryRun
```

> After making changes, restart IIS for them to take effect: `iisreset /noforce`
>
> A timestamped backup of `web.config` is saved automatically before each change.

### Certificate Renewal

**Let's Encrypt:** A scheduled task (`LetsEncrypt-CertRenewal`) is created automatically and runs weekly. Renewal is skipped if the certificate has more than 30 days remaining. No manual action is normally required.

To force re-application of PSP and IIS configuration without renewing (e.g. after a reinstall):
```powershell
C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain "psp.company.com" -ContactEmail "admin@company.com" -ForcePostInstall
```

**BYOC (Bring Your Own Certificate):** When your certificate is due for renewal, run `Cert-Renewer.ps1` as Administrator. Place the new PFX in the same directory and run:
```powershell
C:\Scripts\Cert-Renewer.ps1
```
The script will scan for `.pfx` files in the current directory and prompt you to select one, or you can pass the path directly with `-PfxPath`. It updates `appsettings.json`, IIS bindings, private key ACLs, and restarts the PSP service automatically.

---

## Logs

| Script | Log Location |
|--------|-------------|
| `PSP_AutoInstall.ps1` | `C:\Temp\PSP_AutoInstall.txt` |
| `Cert-Puller_PoshACME.ps1` | `C:\Logs\LetsEncryptRenewal_<date>.txt` |
| `Cert-Renewer.ps1` | `C:\Logs\BYOCImport_<timestamp>.txt` |

---

## Limitations

- **Windows Server 2016 or newer is required.** The script will exit if run on a workstation OS or a Server version older than 2016.
- **Existing IIS configurations may be modified.** The script writes a custom `web.config` to `C:\inetpub\wwwroot`. If IIS is already in use for another purpose on this server, do not use this script.
- **A reboot is required after installation** for TLS hardening registry changes to take effect.
- **`-PreReqOnly` and `-ReverseProxyOnly` cannot be used together** (this includes the `-CompletionOnly` / `-IISOnly` aliases).
- **`-Headless` requires `-PreReqOnly`** and assumes a default `MSSQLSERVER` instance exists and is running.
- **`-ReverseProxyOnly` requires an interactive session** — the certificate menu prompts.
- **Let's Encrypt is unavailable offline.** `-InstallOffline` offers BYOC, self-signed, and existing certificates only.
- **`-PrepareOffline` cannot be combined with any install-mode flag** — it only builds the bundle, then exits.
- **Service account credentials are passed as plain text** to the MSI installer. Ensure the process is run in a secure context.
