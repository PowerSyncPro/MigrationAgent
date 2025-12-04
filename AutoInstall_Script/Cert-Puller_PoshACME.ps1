#Requires -Module Posh-ACME
#Requires -Module WebAdministration
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Obtains or renews a Let's Encrypt certificate using Posh-ACME and stores it in the Local Machine certificate store.

.DESCRIPTION
    Requests or renews a Let's Encrypt certificate via Posh-ACME.
    If a valid certificate exists and is not near expiry, it skips renewal unless -ForcePostInstall is used.
    After obtaining or validating the certificate, it updates permissions, PowerSyncPro configuration,
    IIS bindings, and restarts the PowerSyncPro service.

.NOTES
Date:           November/2025
Version:        0.3
Update:         Added -ForcePostInstall flag and hybrid key logic.
Disclaimer:     This script is provided 'AS IS' with no warranty.
Copyright (c)   2025 Declaration Software

.PARAMETER Domain
    The domain for which to request or renew the certificate.

.PARAMETER ContactEmail
    The email address for Let's Encrypt account registration.

.PARAMETER ForcePostInstall
    Forces all post-install configuration tasks to run even if the certificate is still valid.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [string]$ContactEmail,

    [Parameter(Mandatory=$false)]
    [int]$DaysBeforeExpiry = 30,

    [Parameter(Mandatory=$false)]
    [string]$StoreLocation = "Cert:\LocalMachine\My",

    [Parameter(Mandatory=$false)]
    [string]$WebRoot = "C:\inetpub\wwwroot",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\LetsEncryptRenewal_$(Get-Date -Format 'yyyyMMdd').txt",

    [Parameter(Mandatory=$false)]
    [switch]$ForcePostInstall,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)
# ------------------ Logging Functions ------------------
function Info  { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Ok    { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Warn  { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err   { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Helper Function: Grant-PrivateKeyAccess (compatible PowerShell 5–7)
# ---------------------------------------------------------------------------
function Grant-PrivateKeyAccess {
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        if (-not $Certificate.HasPrivateKey) {
            Warn "Certificate does not contain a private key. Skipping permission update."
            return $false
        }

        $keyProvInfo = $null
        $keyPath = $null

        try {
            $keyProvInfo = $Certificate.PrivateKey.CspKeyContainerInfo
        } catch {
            # .PrivateKey may be CNG-only; certutil fallback below will handle it
        }

        # For modern CNG keys, fall back to provider lookup via certutil
        if (-not $keyProvInfo) {
            $thumb = $Certificate.Thumbprint
            $keyName = (certutil -store my $thumb | Select-String 'Unique container name:' | ForEach-Object { $_ -replace '.*:\s*','' }).Trim()
            if ($keyName) {
                $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $keyName
            }
        } else {
            $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyProvInfo.UniqueKeyContainerName
        }

        if (-not $keyPath) {
            Warn "Could not resolve key path from certificate. Skipping permission update."
            return $false
        }

        if (Test-Path $keyPath) {
            $acl = Get-Acl $keyPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($User, "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $keyPath $acl
            Ok "Granted FullControl on private key to $User"
            return $true
        } else {
            Warn "Private key file not found at $keyPath"
            return $false
        }
    }
    catch {
        Err "Failed to adjust private key permissions for $User : $($_.Exception.Message)"
        return $false
    }
}



# ---------------------------------------------------------------------------
# Usage Help
# ---------------------------------------------------------------------------
if ($PSBoundParameters.Count -eq 0 -or $Help -or -not $Domain -or -not $ContactEmail) {
$usage = @'
Usage:
  .\Cert-Puller_PoshACME.ps1 -Domain <domain> -ContactEmail <email> [-ForcePostInstall] [-DaysBeforeExpiry <days>]

Description:
  Requests or renews a Let's Encrypt certificate. Use -ForcePostInstall to
  reapply PowerSyncPro and IIS configuration even if the existing cert is still valid.

Example:
  .\Cert-Puller_PoshACME.ps1 -Domain "example.com" -ContactEmail "admin@example.com" -ForcePostInstall
'@
    Write-Output $usage
    return
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
if (-not (Test-Path -Path (Split-Path $LogPath -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force | Out-Null
}
Start-Transcript -Path $LogPath -Append

try {
    $poshAcmeVersion = (Get-Module -Name Posh-ACME -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
    Info "Posh-ACME Module Version: $poshAcmeVersion"

    $renewNeeded = $true
    $existingCert = Get-ChildItem -Path $StoreLocation | Where-Object {
        ($_.Subject -like "*CN=$Domain*" -or $_.DnsNameList -contains $Domain) -and
        $_.Issuer -like "*Let's Encrypt*" -and
        $_.NotAfter -gt (Get-Date)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if ($existingCert) {
        $daysUntilExpiry = ($existingCert.NotAfter - (Get-Date)).Days
        if ($daysUntilExpiry -gt $DaysBeforeExpiry) {
            Ok "Certificate for $Domain valid until $($existingCert.NotAfter). No renewal needed."
            $renewNeeded = $false
        } else {
            Warn "Certificate for $Domain expires on $($existingCert.NotAfter). Renewal needed."
        }
    } else {
        Info "No valid certificate found for $Domain. Requesting new certificate."
    }

    if (-not $renewNeeded -and -not $ForcePostInstall) {
        Info "Skipping renewal and post-install tasks."
        Stop-Transcript
        return
    }

    # -----------------------------------------------------------------------
    # Request/Renew Certificate if Needed
    # -----------------------------------------------------------------------
    if ($renewNeeded) {
        Set-PAServer "LE_PROD"
        $account = Get-PAAccount
        if (-not $account) {
            New-PAAccount -Contact $ContactEmail -AcceptTOS -Force
        } else {
            Set-PAAccount -ID $account.ID -Contact $ContactEmail -Force
        }

        $cert = New-PACertificate $Domain -Plugin WebRoot -PluginArgs @{ WRPath = $WebRoot } -Force
        if (-not $cert) { throw "Failed to obtain/renew certificate for $Domain" }
        Ok "Successfully obtained/renewed certificate for $Domain"

        $certDetails = Get-PACertificate -MainDomain $Domain
        if (-not $certDetails) { throw "Failed to retrieve certificate details for $Domain" }

        # ---------------------------------------------------------------------------
        # Import certificate and rebind it to ensure PrivateKey is accessible
        # ---------------------------------------------------------------------------
        $importedCerts = Import-PfxCertificate -FilePath $certDetails.PfxFullChain `
            -Password $certDetails.PfxPass `
            -CertStoreLocation $StoreLocation `
            -Exportable

        if (-not $importedCerts) {
            throw "Failed to import certificate."
        }

        # Get the first thumbprint from whatever was returned
        $newThumb = ($importedCerts | Select-Object -First 1).Thumbprint
        Ok "Certificate imported to $StoreLocation (Thumbprint=$newThumb)"

        # --- Force re-load from certificate store ---
        $newCert = $null
        Start-Sleep -Seconds 1  # give Windows a moment to commit to store

        try {
            $newCert = Get-Item "Cert:\LocalMachine\My\$newThumb"
            if (-not $newCert) { throw "Certificate with Thumbprint=$newThumb not found in store." }

            # verify the key is accessible
            if (-not $newCert.HasPrivateKey) {
                Warn "Reloaded certificate has no private key reference yet, retrying..."
                Start-Sleep -Seconds 2
                $newCert = Get-Item "Cert:\LocalMachine\My\$newThumb"
            }

            if ($newCert.HasPrivateKey) {
                Ok "Reloaded certificate successfully with PrivateKey attached."
            } else {
                Warn "Reloaded certificate still missing PrivateKey; ACL updates may fail."
            }
        }
        catch {
            Err "Failed to reload certificate from store: $($_.Exception.Message)"
            throw
        }

        # Clean old certs
        # (this will now use the already reloaded $newCert)


        # Clean old certs
        $newCert = Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$Domain*" -or $_.DnsNameList -contains $Domain) -and
            $_.Issuer -like "*Let's Encrypt*"
        } | Sort-Object NotAfter -Descending | Select-Object -First 1

        if ($newCert) {
            Get-ChildItem -Path $StoreLocation | Where-Object {
                ($_.Subject -like "*CN=$Domain*" -or $_.DnsNameList -contains $Domain) -and
                $_.Issuer -like "*Let's Encrypt*" -and
                $_.Thumbprint -ne $newCert.Thumbprint
            } | ForEach-Object {
                Info "Removing old certificate Thumbprint=$($_.Thumbprint)"
                Remove-Item -Path "$StoreLocation\$($_.Thumbprint)" -Force
            }
        }

        Ok "Certificate for $Domain successfully obtained/renewed and old certificates cleaned up."
    }
    else {
        Info "Using existing certificate for post-install tasks..."
        $newCert = $existingCert
    }

}
catch {
    Err "An error occurred: $($_.Exception.Message)"
    Exit 1
}
finally {
    $challengeDir = Join-Path -Path $WebRoot -ChildPath ".well-known\acme-challenge"
    if (Test-Path -Path $challengeDir) {
        Remove-Item -Path $challengeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Post-install tasks always run if -ForcePostInstall or new cert issued
# ---------------------------------------------------------------------------
Info "Checking certificate and adding permissions to PSP Service account if necessary..."
$svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
if (-not $svc) {
    Warn "Service 'PowerSyncPro' not found. Skipping key permission check."
} else {
    $svcUser = $svc.StartName
    if ($svcUser -eq "LocalSystem") {
        Ok "PowerSyncPro is running as LocalSystem. No permissions update needed."
    } else {
        try {
            $svcUser = $svc.StartName
	    if ($svcUser -match '^\.\\') {
            	# Replace .\ with actual hostname
            	$svcUser = "$env:COMPUTERNAME\$($svcUser -replace '^\.\\','')"
	    }
	    $ntAccount = New-Object System.Security.Principal.NTAccount($svcUser)
	    $resolvedUser = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value

            $aclResult = Grant-PrivateKeyAccess -Certificate $newCert -User $resolvedUser
            if (-not $aclResult) {
                Warn "Private key ACL update failed or skipped. Will continue installation."
                $Script:PSPCertPermissionPending = $true
            }
        }
        catch {
            Write-Error "[!] LetsEncrypt install failed: Failed to adjust private key permissions for $svcUser : $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Update appsettings.json
# ---------------------------------------------------------------------------
$appSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"

try {
    if (Test-Path $appSettingsPath) {
        $json = Get-Content $appSettingsPath -Raw | ConvertFrom-Json
        $actualSubject = $newCert.GetNameInfo('SimpleName', $false)

        if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
            Warn "HTTPS endpoint not found. Creating one on port 5001."
            $json.Kestrel.Endpoints | Add-Member -MemberType NoteProperty -Name "Https" -Value @{
                Url       = "https://*:5001"
                Protocols = "Http1AndHttp2"
                Certificate = @{
                    Subject      = $actualSubject
                    Store        = "My"
                    Location     = "LocalMachine"
                    AllowInvalid = $true
                }
            }
            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $appSettingsPath -Encoding UTF8
        }
        else {
            $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
            if ($configuredSubject -ne $actualSubject) {
                Warn "Configured subject ($configuredSubject) differs from actual ($actualSubject). Updating."
                $json.Kestrel.Endpoints.Https.Certificate.Subject = $actualSubject
                $json | ConvertTo-Json -Depth 10 | Set-Content -Path $appSettingsPath -Encoding UTF8
            } else {
                Ok "appsettings.json already matches the current certificate subject."
            }
        }
    } else {
        Warn "appsettings.json not found at $appSettingsPath"
    }
}
catch {
    Write-Error "Failed to update appsettings.json: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Update IIS and Restart Service
# ---------------------------------------------------------------------------
Import-Module WebAdministration -ErrorAction Stop
$siteName   = "Default Web Site"
$newThumb   = $newCert.Thumbprint
$certObject = Get-Item "Cert:\LocalMachine\My\$newThumb"

$binding = Get-WebBinding -Name $siteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue
if ($binding) {
    Info "Updating existing HTTPS binding with cert $newThumb"
    $sslBindings = Get-ChildItem IIS:\SslBindings
    $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1
    if ($sslBinding) {
        Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
    } else {
        New-Item "IIS:\SslBindings\0.0.0.0!443" -Value $certObject -SSLFlags 0 | Out-Null
    }
} else {
    Info "No HTTPS binding found. Creating new one."
    New-WebBinding -Name $siteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
    New-Item "IIS:\SslBindings\0.0.0.0!443" -Value $certObject -SSLFlags 0 | Out-Null
}
Ok "IIS binding updated successfully."

Restart-Service -Name "PowerSyncPro" -Force
Ok "PowerSyncPro service restarted."

Stop-Transcript
