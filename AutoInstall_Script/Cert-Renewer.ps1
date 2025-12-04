#Requires -RunAsAdministrator
#Requires -Module WebAdministration

<#
.SYNOPSIS
    Imports a user-provided (BYOC) PFX certificate and applies it to PowerSyncPro + IIS.

.DESCRIPTION
    Scans for available .pfx files, allows user selection or path input, imports the cert
    into LocalMachine\My, sets ACLs for the PowerSyncPro service account, updates IIS bindings
    and appsettings.json, and restarts the PSP service. Logs output to C:\Logs.

.NOTES
    Date            October/2025
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 0.1
    Updated: Initial Release.
    Copyright (c) 2025 Declaration Software

.PARAMETER PfxPath
    Optional. Path or wildcard to a PFX file. If omitted, script searches current folder.

.PARAMETER StoreLocation
    Optional. Defaults to "Cert:\LocalMachine\My"

.PARAMETER AppSettingsPath
    Optional. Defaults to "C:\Program Files\PowerSyncPro\appsettings.json"

.PARAMETER SiteName
    Optional. Defaults to "Default Web Site"
#>

[CmdletBinding()]
param(
    [string]$PfxPath,
    [string]$StoreLocation = "Cert:\LocalMachine\My",
    [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json",
    [string]$SiteName = "Default Web Site"
)

$asciiLogo=@"
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"@

Write-Host $asciiLogo
Write-Host "`n=== PowerSyncPro BYOC Certificate Import Utility ===`n" -ForegroundColor Cyan

# --- Initialize Transcript Logging ---
try {
    $LogRoot = "C:\Logs"
    if (-not (Test-Path $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    }

    $LogFile = Join-Path $LogRoot ("BYOCImport_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Start-Transcript -Path $LogFile -Append
    Write-Host "Logging started: $LogFile" -ForegroundColor DarkGray
}
catch {
    Write-Warning "Unable to start transcript logging: $($_.Exception.Message)"
}

try {

    # --- Step 1: Locate / select PFX ---
    if (-not $PfxPath) {
        $localPfxFiles = @(Get-ChildItem -Path (Get-Location) -Filter *.pfx -File -ErrorAction SilentlyContinue)

        if ($localPfxFiles.Length -ge 1) {
            Write-Host "Found the following PFX files in the current directory:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $localPfxFiles.Length; $i++) {
                Write-Host ("[{0}] {1}" -f ($i + 1), $localPfxFiles[$i].Name)
            }

            while ($true) {
                $choice = Read-Host "Select 1-$($localPfxFiles.Length), or press Enter to type a path/wildcard"
                if ([string]::IsNullOrWhiteSpace($choice)) { break }

                [int]$sel = 0
                if ([int]::TryParse($choice, [ref]$sel) -and $sel -ge 1 -and $sel -le $localPfxFiles.Length) {
                    $PfxPath = $localPfxFiles[$sel - 1].FullName
                    break
                } else {
                    Write-Host "Invalid selection. Try again." -ForegroundColor Yellow
                }
            }
        }

        if (-not $PfxPath) {
            $typed = Read-Host "Enter full path or wildcard to the .pfx (e.g. C:\Certs\*.pfx)"
            $typed = $typed.Trim('"').Trim("'")
            $typed = [Environment]::ExpandEnvironmentVariables($typed)
            $candidates = @(Get-ChildItem -Path $typed -File -ErrorAction SilentlyContinue)

            switch ($candidates.Length) {
                0 {
                    Write-Error "No .pfx files matched '$typed'."
                    exit 1
                }
                1 {
                    $PfxPath = $candidates[0].FullName
                }
                default {
                    Write-Host "Multiple matches:" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $candidates.Length; $i++) {
                        Write-Host ("[{0}] {1}" -f ($i + 1), $candidates[$i].FullName)
                    }
                    while ($true) {
                        $choice = Read-Host "Select 1-$($candidates.Length)"
                        [int]$sel = 0
                        if ([int]::TryParse($choice, [ref]$sel) -and $sel -ge 1 -and $sel -le $candidates.Length) {
                            $PfxPath = $candidates[$sel - 1].FullName
                            break
                        } else {
                            Write-Host "Invalid selection. Try again." -ForegroundColor Yellow
                        }
                    }
                }
            }
        }
    }

    # Normalize & validate
    try {
        $PfxPath = (Resolve-Path -LiteralPath $PfxPath -ErrorAction Stop).Path
    } catch {
        Write-Error "File not found: $PfxPath"
        exit 1
    }

    Write-Host "`nUsing certificate file: $PfxPath" -ForegroundColor Cyan

    # --- Step 2: Prompt for password ---
    $SecurePassword = Read-Host "Enter password for the PFX file" -AsSecureString

    # --- Step 3: Import into store ---
    Write-Host "`nImporting certificate..." -ForegroundColor Cyan
    try {
        $imported = Import-PfxCertificate -FilePath $PfxPath `
            -Password $SecurePassword `
            -CertStoreLocation $StoreLocation `
            -Exportable
        if (-not $imported) { throw "Import failed." }
        $newCert = $imported | Sort-Object NotAfter -Descending | Select-Object -First 1
        Write-Host "Imported certificate: $($newCert.Subject)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import certificate: $($_.Exception.Message)"
        exit 1
    }

    # --- Step 4: Update PSP service key ACL ---
    Write-Host "`nUpdating PowerSyncPro private key ACL..." -ForegroundColor Cyan
    $svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
    if ($svc) {
        $svcUser = $svc.StartName
        if ($svcUser -ne "LocalSystem") {
            try {
                $provInfo = $newCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $provInfo
                if (Test-Path $keyPath) {
                    $acl = Get-Acl $keyPath
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($svcUser, "FullControl", "Allow")
                    $acl.SetAccessRule($rule)
                    Set-Acl -Path $keyPath -AclObject $acl
                    Write-Host "Granted FullControl on private key to $svcUser" -ForegroundColor Green
                }
            } catch {
                Write-Warning "Failed to adjust private key permissions: $($_.Exception.Message)"
            }
        } else {
            Write-Host "Service runs as LocalSystem, no ACL change needed."
        }
    } else {
        Write-Warning "PowerSyncPro service not found."
    }

    # --- Step 5: Update appsettings.json ---
    if (Test-Path $AppSettingsPath) {
        Write-Host "`nUpdating appsettings.json..." -ForegroundColor Cyan
        try {
            $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json
            $actualSubject = $newCert.GetNameInfo('SimpleName', $false)

            if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                Write-Host "Adding HTTPS endpoint configuration..." -ForegroundColor Yellow
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
            } else {
                $json.Kestrel.Endpoints.Https.Certificate.Subject = $actualSubject
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
            Write-Host "appsettings.json updated with $actualSubject." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to update appsettings.json: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "appsettings.json not found at $AppSettingsPath"
    }

    # --- Step 6: Bind to IIS ---
    Write-Host "`nUpdating IIS HTTPS binding..." -ForegroundColor Cyan
    Import-Module WebAdministration -ErrorAction Stop
    $thumb = $newCert.Thumbprint
    $certObject = Get-Item "Cert:\LocalMachine\My\$thumb"
    $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

    if ($binding) {
        $sslBindings = Get-ChildItem IIS:\SslBindings
        $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1
        if ($sslBinding) {
            Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
            Write-Host "Updated existing binding with cert $thumb" -ForegroundColor Green
        } else {
            New-Item "IIS:\SslBindings\0.0.0.0!443" -Value $certObject -SSLFlags 0 | Out-Null
            Write-Host "Created new binding on port 443" -ForegroundColor Green
        }
    } else {
        New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
        New-Item "IIS:\SslBindings\0.0.0.0!443" -Value $certObject -SSLFlags 0 | Out-Null
        Write-Host "Created HTTPS binding for $SiteName" -ForegroundColor Green
    }

    # --- Step 7: Restart PSP service ---
    try {
        Restart-Service -Name "PowerSyncPro" -Force -ErrorAction Stop
        Write-Host "`nPowerSyncPro service restarted successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to restart PowerSyncPro: $($_.Exception.Message)"
    }

    Write-Host "`n=== BYOC Certificate Import Completed Successfully ===" -ForegroundColor Cyan

}
finally {
    try {
        Stop-Transcript | Out-Null
        Write-Host "`nTranscript saved to $LogFile" -ForegroundColor DarkGray
    } catch {}
}
