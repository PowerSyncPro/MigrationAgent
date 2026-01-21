<#
.DESCRIPTION
    The script will install PowerSyncPro on a Windows Server, including all prerequisites.
    This script will download various content from Microsoft, PowerSyncPro, and the PowerSyncPro Github.
 
.NOTES
    Date            January/2026
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 0.2
    Updated : 9th January, 2026 - Added logic to handle installing with existing SQL instances on system, SQL Express 2025, fixed a bug where VC++ install would cause script failure. JRR
    Updated : 20th January, 2026 - Added logic to split the script in half and allow for PreReqOnly and Completion only modes.
    Copyright (c) 2025 Declaration Software
#>

#Requires -RunAsAdministrator
param (
    # Sets the URL for PowerSyncPro Download - Will accept a file path (e.g. C:\Temp\PowerSyncProInstaller.msi) if you want to feed in a specific version, etc.
    [string]$PSPUrl = "https://downloads.powersyncpro.com/current/PowerSyncProInstaller.msi",

    # Account / Password to Install PSP as.  If not set the installer will use LocalSystem.
    # Optional Service Account Name (e.g. DOMAIN\User or .\LocalUser)
    [string]$PSPServiceUser = $null,

    # Optional Service Account Password (plain text for MSI use)
    [string]$PSPServicePassword = $null,
    
    # Run Prereqs Only, don't install PowerSyncPro (Advanced Installs Only)
    # --> Sets up pre-requisite software (including SQL, etc)
    [switch]$PreReqOnly = $false,

    # Run completion only - for after manually installing PSP (Advanced Installs Only)
    # --> Completes SSL Setup, Hardens Server, Installs Certificate
    [switch]$CompletionOnly = $false
)

Set-StrictMode -Version Latest

# General Variables
$scriptVer = "v0.2"

$tempDir = "C:\Temp" # Temporary Directory for Downloads, etc.
$LogPath = "C:\Temp\PSP_AutoInstall.txt" # Logging Location

# .Net 8 Hosting Platform Variables
# Meta Data URL, link to the latest .net releases in JSON
$metadataUrl = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"

# VC Redistributable Variables
$vcDownloadURL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# SQL 2025 Bootstrapper / Downloader
$SQLBootstrapperUrl = "https://download.microsoft.com/download/7ab8f535-7eb8-4b16-82eb-eca0fa2d38f3/SQL2025-SSEI-Expr.exe"
# SQL Suite Management Studio
$SsmsUrl = "https://aka.ms/ssmsfullsetup"

# IIS URL Rewrite
$RewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
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
function Info  { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Ok    { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Warn  { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err   { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }
# ------------------ Installation and Requirements Checks ------------------
function Install-dotNet8Hosting {
# -----------------------
# Download and install the latest stable .NET 8 Hosting Bundle (Windows)
# -----------------------
  param(
    [string]$metadataUrl,
    [string]$tempDir
    )

  Info "Installing latest stable .NET 8 Hosting Bundle...."
  
  Info "Fetching release metadata from $metadataUrl ..."
  $releases = Invoke-RestMethod $metadataUrl

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
  Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

  Info "Running Hosting Bundle installer silently..."
  Start-Process $installerPath -ArgumentList "/quiet /norestart" -Wait

  Ok ".Net 8 Hosting Bundle $version installation complete!"
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
    [string]$TempDir
  )

  $ErrorActionPreference = "Stop"

  Info "Installing Microsoft Visual C++ Redistributables (x64)..."

  # Ensure download directory exists
  if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

  $installer = Join-Path $TempDir "vc_redist.x64.exe"

  Info "Downloading VC++ Redistributable (x64) from $DownloadURL ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $DownloadURL -OutFile $installer

  Info "Downloaded vc_redist.x64.exe to $installer"

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
        [string]$SQLAdminsGroup = $null
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

    foreach ($d in @($DownloadDir, $MediaDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # Download bootstrapper
    $bootstrapperExe = Join-Path $DownloadDir "SQL-SSEI-Expr.exe"
    Info ("Downloading SQL Server Express bootstrapper from {0} ..." -f $BootstrapperUrl)
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $BootstrapperUrl -OutFile $bootstrapperExe
    Info ("Downloaded bootstrapper to {0}" -f $bootstrapperExe)

    # Download full install media
    Info "Fetching installation media..."
    $bootstrapperCmd = "`"$bootstrapperExe`" /ACTION=Download /MEDIAPATH=`"$MediaDir`" /QUIET"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-Command",$bootstrapperCmd -Verb RunAs -Wait

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
    $SqlArgs = @(
        "/ENU=True",
        "/ROLE=AllFeatures_WithDefaults",
        "/ACTION=Install",
        "/FEATURES=SQLENGINE,REPLICATION",
        "/USEMICROSOFTUPDATE=True",
        "/UpdateSource=MU",
        ("/INSTANCENAME={0}" -f $InstanceName),
        $sysAdminsArg,
        "/TCPENABLED=1",
        "/IACCEPTSQLSERVERLICENSETERMS",
        "/QS"
    )

    # Execute installer
    Start-Process -FilePath $setupExe.FullName -ArgumentList $SqlArgs -Verb RunAs -Wait

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
function Install-SSMS {
  param(
  [string]$SsmsUrl,
  [string]$tempDir
  )
  # -----------------------
  # Download / Install SQL Studio Management Suite
  # -----------------------

  $DownloadDir = "$tempDir\SSMS"

  $ErrorActionPreference = "Stop"

  Info "Installing SQL Server Management Studio (SMSS)..."

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  $ssmsInstaller = Join-Path $DownloadDir "SSMS-Setup-ENU.exe"

  Info "Downloading SSMS installer from $SsmsUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $SsmsUrl -OutFile $ssmsInstaller

  Info "Downloaded SSMS installer to $ssmsInstaller"

  # Step 1: Run SSMS silent install (elevated)
  Info "Installing SSMS silently..."
  $proc = Start-Process -FilePath $ssmsInstaller `
      -ArgumentList "/install", "/quiet", "/norestart", "/log", "$DownloadDir\SSMS-Install.log" `
      -Verb RunAs -Wait -PassThru

  if ($proc.ExitCode -ne 0) {
      throw "SSMS install failed with exit code $($proc.ExitCode). See log at $DownloadDir\SSMS-Install.log"
  }

  # Step 2: Verify SSMS installation
  $possiblePaths = @(
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 21\Common7\IDE\ssms.exe",
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\ssms.exe",
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\ssms.exe"
  )

  $ssmsExe = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

  if (-not $ssmsExe) {
      Warn "SSMS executable not found in the expected paths. Please check the install log: $DownloadDir\SSMS-Install.log"
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
    else {
        Warn "SQL Server Management Studio (SSMS) is not installed." -ForegroundColor Red
        return $false
    }
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
    [string]$RewriteUrl,
    [string]$tempDir
  )
  # -----------------------
  # Install URL Rewrite
  # -----------------------

  Info "Installing IIS URL Rewrite Functionality..."
  $DownloadDir = "$tempDir\URLRewrite"

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  $installer = Join-Path $DownloadDir "rewrite_amd64_en-US.msi"

  Info "Downloading IIS URL Rewrite MSI from $RewriteUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $RewriteUrl -OutFile $installer

  Info "Downloaded to $installer"

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
        [string]$tempDir
    )

    Info "Installing IIS Advanced Request Routing (ARR)..."

    $DownloadDir = Join-Path $tempDir "ARR"

    # Ensure download directory exists
    if (-not (Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    $installer = Join-Path $DownloadDir "requestRouter_x64.msi"

    # 1. Install ARR if missing
    if (-not $ARRInstalled) {
        Info "Downloading ARR 3.0 from $ArrUrl ..."
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ArrUrl -OutFile $installer

        Info "Downloaded ARR to $installer"

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
        Import-Module WebAdministration -ErrorAction Stop

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
      Invoke-WebRequest -Uri $PSPUrl -OutFile $Installer -UseBasicParsing
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
            # Account is domain-based, not local — disable local key usage
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

        [string]$Url
    )

    try {
        $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile

        # Ensure the folder exists
        if (-not (Test-Path $TargetFolder)) {
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }

        $ChildScript = $null

        if ($Encoded) {
            Info "Decoding Base64 content..."
            $Bytes = [Convert]::FromBase64String($Encoded)
            $ChildScript = [System.Text.Encoding]::UTF8.GetString($Bytes)
        }
        elseif ($Url) {
            Info "Downloading script from $Url ..."
            try {
                $ChildScript = (Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop).Content
            }
            catch {
                throw "Failed to download script from $Url. Error: $($_.Exception.Message)"
            }
        }
        else {
            throw "You must specify either -Encoded or -Url."
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
function Install-WebConfig {
    param(
        [string]$FrontendHost,
        [string]$TargetFolder,
        [string]$TargetFile
    )

    # Build paths
    $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile
    $ForbiddenTargetFolder = Join-Path -Path $TargetFolder -ChildPath "CustomErrors"
    $ForbiddenTarget = Join-Path -Path $ForbiddenTargetFolder -ChildPath "forbidden.html"

    # Construct the Frontend URL
    $FrontendUrl = "https://$FrontendHost/"

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
          <action type="Rewrite" url="http://localhost:5000/{R:1}" />
        </rule>
      </rules>
      <outboundRules>
        <rule name="PowerSyncProReverseProxyOutboundRule1" preCondition="PowerSyncProResponseIsHtml">
          <match filterByTags="A, Form, Img" pattern="^http(s)?://localhost:5000/(.*)" />
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

    # Write web.config
    $WebConfig | Out-File -FilePath $TargetPath -Encoding UTF8 -Force
    Ok "Full web.config written to $TargetPath with backend $FrontendUrl"

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
        - Keeps TLS 1.2 (and TLS 1.3, if supported)
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

    try {
        $HostsContent = Get-Content $HostsPath -ErrorAction Stop
    }
    catch {
        Err "Failed to read hosts file: $($_.Exception.Message)"
        return $false
    }

    # Strip out existing entries for this host only
    $FilteredHosts = $HostsContent | Where-Object {
        $_ -notmatch "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)"
    }

    # Add new entry only if it isn't already present
    if (-not ($FilteredHosts -match "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)")) {
        $FilteredHosts += $HostsEntry
        Info "Adding hosts entry: $HostsEntry"
    }
    else {
        Warn "Hosts entry already exists: $HostsEntry"
    }

    # Retry mechanism for writing
    $success = $false
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $FilteredHosts | Set-Content -Path $HostsPath -Encoding ASCII -ErrorAction Stop
            Ok "Hosts file updated successfully."
            $success = $true
            break
        }
        catch [System.IO.IOException] {
            Warn "Attempt ${i} of ${MaxRetries}: Hosts file in use. Retrying in ${RetryDelaySeconds} second(s)..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        catch {
            Warn "Unexpected error while updating hosts file: $($_.Exception.Message)"
            break
        }
    }

    if (-not $success) {
        Warn "Failed to update hosts file after $MaxRetries attempts. Entry not added for $FrontendHost."
        return $false
    }
}
# ------------------ Certificate Functions ------------------
function Install-ACMECertificate{
  param(
    [string]$FrontendHost,
    [string]$ContactEmail
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
  & C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain $FrontendHost -ContactEmail $ContactEmail
}
function Install-CustomPfxCertificate {
    <#
    .SYNOPSIS
        Imports a user-provided PFX certificate and updates PowerSyncPro + IIS configs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"
    )

    try {
        Info "Importing PFX from $PfxPath..."
        $imported = Import-PfxCertificate -FilePath $PfxPath `
            -Password $Password `
            -CertStoreLocation $StoreLocation `
            -Exportable

        if (-not $imported) { throw "Failed to import PFX certificate." }

        $newCert = $imported[0]
        $actualSubject = $newCert.GetNameInfo('SimpleName', $false)
        Ok "Imported cert: $actualSubject Thumbprint=$($newCert.Thumbprint)"

        # Remove old certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$actualSubject*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Info "Removing old certificate Thumbprint=$($_.Thumbprint)"
            Remove-Item -Path "$StoreLocation\$($_.Thumbprint)" -Force
        }

        # Fix private key ACLs for PSP service
        $svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
        if ($svc) {
            $svcUser = $svc.StartName
            if ($svcUser -ne "LocalSystem") {
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($svcUser)
                    $resolvedUser = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value

                    $keyProvInfo = $newCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                    $keyPath = Join-Path $machineKeysPath $keyProvInfo

                    if (Test-Path $keyPath) {
                        $acl = Get-Acl $keyPath
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($resolvedUser, "FullControl", "Allow")
                        $acl.SetAccessRule($accessRule)
                        Set-Acl -Path $keyPath -AclObject $acl
                        Ok "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Warn "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        try {
            if (Test-Path $AppSettingsPath) {
                $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

                if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                    Warn "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
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
                    Ok "Created HTTPS endpoint in appsettings.json"
                } else {
                    $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                    if ($configuredSubject -ne $actualSubject) {
                        Warn "Configured cert subject ($configuredSubject) does not match new cert ($actualSubject). Updating automatically."
                        $json.Kestrel.Endpoints.Https.Certificate.Subject = $actualSubject
                    } else {
                        Info "appsettings.json already matches current certificate subject."
                    }
                }

                $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
                Ok "Updated appsettings.json successfully."
            } else {
                Warn "appsettings.json not found at $AppSettingsPath"
            }
        }
        catch {
            Warn "Failed to update appsettings.json: $($_.Exception.Message)"
        }

        # Update IIS binding (defensive logic)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Info "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Info "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Warn "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Warn "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Info "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Ok "Restarted PowerSyncPro service."
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
}
function Install-SelfSignedCertificate {
    <#
    .SYNOPSIS
        Generates and installs a self-signed certificate for a given FQDN
        and updates PowerSyncPro + IIS configs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DnsName,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"
    )

    try {
        Info "Creating self-signed certificate for $DnsName..."

        # Generate self-signed cert
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

        # Remove old self-signed certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$DnsName*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Info "Removing old certificate Thumbprint=$($_.Thumbprint)"
            Remove-Item -Path "$StoreLocation\$($_.Thumbprint)" -Force
        }

        # Fix private key ACLs for PSP service
        $svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
        if ($svc) {
            $svcUser = $svc.StartName
            if ($svcUser -ne "LocalSystem") {
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($svcUser)
                    $resolvedUser = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value

                    $keyProvInfo = $newCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                    $keyPath = Join-Path $machineKeysPath $keyProvInfo

                    if (Test-Path $keyPath) {
                        $acl = Get-Acl $keyPath
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($resolvedUser, "FullControl", "Allow")
                        $acl.SetAccessRule($accessRule)
                        Set-Acl -Path $keyPath -AclObject $acl
                        Ok "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Warn "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        if (Test-Path $AppSettingsPath) {
            $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

            if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                Warn "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
                $json.Kestrel.Endpoints | Add-Member -MemberType NoteProperty -Name "Https" -Value @{
                    Url       = "https://*:5001"
                    Protocols = "Http1AndHttp2"
                    Certificate = @{
                        Subject      = $DnsName
                        Store        = "My"
                        Location     = "LocalMachine"
                        AllowInvalid = $true
                    }
                }
                Ok "Created HTTPS endpoint in appsettings.json"
            } else {
                $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                if ($configuredSubject -ne $DnsName) {
                    Warn "Configured cert subject ($configuredSubject) does not match new cert ($DnsName). Updating automatically."
                    $json.Kestrel.Endpoints.Https.Certificate.Subject = $DnsName
                } else {
                    Info "appsettings.json already matches the current certificate subject."
                }
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
            Ok "Updated appsettings.json successfully."
        } else {
            Warn "appsettings.json not found at $AppSettingsPath"
        }

        # Update IIS binding (defensive version)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Info "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Info "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Warn "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Warn "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Info "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Ok "Restarted PowerSyncPro service."
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
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
            Import-Module WebAdministration -ErrorAction Stop
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
        Finds the most recent certificate matching the domain in the LocalMachine store,
        determines the associated private key path, and grants the specified user
        FullControl permissions.  Works for both modern CNG and legacy CSP keys.

    .PARAMETER Domain
        The CN or DNS name of the certificate.

    .PARAMETER User
        The account to grant FullControl to (e.g., 'PSP-MISSOURI\pspsvc').

    .PARAMETER StoreLocation
        The certificate store location. Default: Cert:\LocalMachine\My
    #>

    param(
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$User,
        [string]$StoreLocation = "Cert:\LocalMachine\My"
    )

    try {
        # --- Locate most recent cert for this domain (issuer agnostic) ---
        $cert = Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$Domain*" -or $_.DnsNameList -contains $Domain)
        } | Sort-Object NotAfter -Descending | Select-Object -First 1

        if (-not $cert) {
            Warn "No certificate found for $Domain in $StoreLocation."
            return $false
        }

        Info "Found certificate for $Domain (Thumbprint: $($cert.Thumbprint))"

        if (-not $cert.HasPrivateKey) {
            Warn "Certificate does not have a private key association."
            return $false
        }

        # --- Determine key path ---
        $keyPath = $null

        try {
            # Try legacy CryptoAPI provider first
            $keyProvInfo = $cert.PrivateKey.CspKeyContainerInfo
            if ($keyProvInfo) {
                $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" `
                                     $keyProvInfo.UniqueKeyContainerName
            }
        } catch {
            # Ignore; CNG keys will be handled below
        }

        # Fallback for CNG keys (modern ACME-issued certs)
        if (-not $keyPath) {
            $thumb = $cert.Thumbprint
            $keyName = (certutil -store my $thumb |
                        Select-String 'Unique container name:' |
                        ForEach-Object { $_ -replace '.*:\s*','' }).Trim()
            if ($keyName) {
                $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $keyName
            }
        }

        if (-not $keyPath) {
            Warn "Could not resolve private key path for $Domain. Skipping ACL update."
            return $false
        }

        if (-not (Test-Path $keyPath)) {
            Warn "Private key file not found at $keyPath"
            return $false
        }

        # --- Apply ACL ---
        Info "Applying FullControl permissions for $User on $keyPath"
        $acl = Get-Acl $keyPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($User, "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl
        Ok "Granted FullControl on private key to $User"

        return $true
    }
    catch {
        Err "Error fixing private key permissions for $Domain : $($_.Exception.Message)"
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
# ------------------ Menu & UI ------------------
function Show-CertificateTypeMenu {
    Clear-Host 2>$null
    Write-Host $asciiLogo -ForegroundColor Cyan
    Write-Host "PowerSyncPro Automated Installation Script - $scriptVer"
    Write-Host ""
    Write-Host "Which type of certificate would you like to use for this installation?" -ForegroundColor Cyan
    Write-Host ""
    $options = @(
        @{ Key = '1'; Name = 'LetsEncrypt'; Desc = 'ACME via DNS Verification' }
        @{ Key = '2'; Name = 'BYOC';        Desc = 'Bring Your Own Certificate (PFX with Private Keys Required)' }
        @{ Key = '3'; Name = 'SelfSigned';  Desc = 'Generate a Self-Signed Certificate (May cause loss of functionality)' }
    )
    foreach ($o in $options) {
        Write-Host ("  [{0}] {1} - {2}" -f $o.Key, $o.Name, $o.Desc)
    }
    Write-Host ""
    Write-Host "  (Press Enter for default: 1 = LetsEncrypt; or type the name, e.g., 'byoc'. Type Q to quit.)"
    Write-Host ""

    while ($true) {
        $raw = Read-Host "Select 1-3, name, or Q"
        $raw = if ([string]::IsNullOrWhiteSpace($raw)) { '1' } else { $raw.Trim() }
        switch -regex ($raw) {
            '^(1|letsencrypt)$' { return 'LetsEncrypt' }
            '^(2|byoc|bring.*)$' { return 'BYOC' }
            '^(3|self.*)$' { return 'SelfSigned' }
            '^(q|quit|exit)$' {
                                throw "User cancelled the wizard."
                            }
            default { Write-Host "Invalid selection. Try again." -ForegroundColor Yellow }
        }
    }
}
# ------------------ Wizard Core ------------------
function Run-Wizard {
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

            # --- Detect wildcards ---
            $WildcardFqdns = @($CertFqdns | Where-Object { $_.StartsWith('*.') })
            $ResolvedHostname = $null
            $ChosenWildcard   = $null

            if ($WildcardFqdns.Count -gt 1) {
                Warn "Multiple wildcard domains detected:"
                for ($i=0; $i -lt $WildcardFqdns.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i+1), $WildcardFqdns[$i])
                }
                while ($true) {
                    $choice = Read-Host "Select which wildcard root to use (1-$($WildcardFqdns.Count))"
                    if ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $WildcardFqdns.Count) {
                        $ChosenWildcard = $WildcardFqdns[$choice-1]
                        break
                    }
                    Warn "Invalid choice. Please enter a number between 1 and $($WildcardFqdns.Count)."
                }
            } elseif ($WildcardFqdns.Count -eq 1) {
                $ChosenWildcard = $WildcardFqdns[0]
            }

            # --- Handle wildcard resolution ---
            if ($ChosenWildcard) {
                $wildRoot = $ChosenWildcard.Substring(2)
                Warn ("Detected wildcard certificate for: {0}" -f $wildRoot)
                while ($true) {
                    $ResolvedHostname = Read-Host ("Enter the specific FQDN for this host (must be exactly one label under {0}, e.g. host.{0})" -f $wildRoot)
                    if ([string]::IsNullOrWhiteSpace($ResolvedHostname)) { Warn "Hostname cannot be empty."; continue }
                    $ResolvedHostname = $ResolvedHostname.Trim()
                    if (-not (Test-HostnameFormat -Name $ResolvedHostname)) { Warn "Invalid hostname format. Please enter a valid FQDN."; continue }

                    $hostDots = ($ResolvedHostname -split '\.').Count
                    $rootDots = ($wildRoot -split '\.').Count
                    $endsOk   = $ResolvedHostname.ToLower().EndsWith("." + $wildRoot.ToLower())
                    $oneLevel = ($hostDots -eq ($rootDots + 1))

                    if ($endsOk -and $oneLevel) {
                        Ok ("Hostname {0} is valid for wildcard {1}" -f $ResolvedHostname, $ChosenWildcard)
                        break
                    } else {
                        Warn ("{0} is not valid for wildcard {1}. Must add exactly one label under {2}." -f $ResolvedHostname, $ChosenWildcard, $wildRoot)
                    }
                }
            } else {
                # No wildcard found — just pick the first SAN / CN
                $ResolvedHostname = $CertFqdns[0]
            }

            # --- Final config object ---
            $CertConfig = [PSCustomObject]@{
                Type              = 'BYOC'
                PfxPath           = $PfxPath
                PfxPass           = $PfxPass
                CertFqdns         = $CertFqdns
                ChosenWildcard    = $ChosenWildcard
                Hostname          = $ResolvedHostname
                WildcardValidated = [bool]$ChosenWildcard
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
    }

    return $CertConfig
}
# -------------------------------------------------
# Menu / Script Actions / Logic
# Initialize logging

# Register exit cleanup handler
#Start Transcription
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

    # Evaluate CLI Flags
    # Eval Prerequisite / CLI Flags Flags
    if ($PreReqOnly -and $CompletionOnly) {
        Err "You cannot run both Prequisites and Completion at the same time... Exiting."
        exit 1
    }

    # Cannot use the PSPServiceUser / PSPServicePassword flags with the PreReqOnly or CompletionOnly flags.
    if ( ($PreReqOnly -or $CompletionOnly) -and
     (-not [string]::IsNullOrWhiteSpace($PSPServiceUser) -or
      -not [string]::IsNullOrWhiteSpace($PSPServicePassword)) ) {
        Err "-PreReq and -Completion Flags are not compatible with Service Accounts... Exiting."
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
        Info "After manually installing the MSI, you can complete the certificate installation and hardening using the -CompletionOnly flag."
        Start-Sleep 5
    }

    # Notify that the script will be run in Completion Only Mode, we will do everything *after* the PSP installation.
    if ($CompletionOnly) {
        Info "Script is running in Completion Only mode, PowerSyncPro should be already installed and running..."
        Info "Completing hardening and certificate installation on server."
        # Make sure PSP is running - we cannot complete the install if it isn't yet installed.
        if (-not (Test-PowerSyncPro)) {
            Warn "PowerSyncPro Service is not running on this system.  You cannot complete the installation if PowerSyncPro is not installed and running."
            exit 1
        }

        # Determine the SQL instance that was used for the previous PSP install.
        Info "Collecting SQL Information for existing PowerSyncPro installation..."
        # Get all Installed Instances
        $instances = @(Get-LocalSqlInstances)
        # Ask user to select an instance (or no instance)
        $SqlServices = Select-SqlTarget -Instances $instances -CompletionOnly $true
        $ExternalServerInUse = $SqlServices.ExternalServerInUse
        $SqlInstance = $SqlServices.InstanceName

        if (-not $ExternalServerInUse) {
            Info "Running completion with $SqlInstance.Name as assumed SQL Instance for existing installation..."
        }
        else {
            Info "Running completion assuming an external SQL server is in use."
        }
    }

    # Service Account Tasks - Only if not in PreReq / Completion Only Mode
    if (-not $PreReqOnly -and -not $CompletionOnly) {

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

    # Run a bunch of stuff if not in Completion Only mode....
    if (-not $CompletionOnly) {
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

        # Choose SQL Target Database Instance
        $SqlAddress  = "localhost"
        $SqlPort     = "1433"
        $SqlDatabase = "PowerSyncProDB"

        $InstallSqlExpress = $false

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

        # Test if Ports we require during the installation are in-use.  Bail out if conflicts occur.
        # Define which ports to check
        $checkPorts = 80,443,5000,5001
        $noConflicts = $false

        # Retrieve all listeners
        $listeners = Get-ListeningPort -Port $checkPorts
        $listeners = @($listeners)

        # Filter to only active listeners
        $active = @($listeners | Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })

        if ($active.Count -eq 0) {
            Ok "No conflicts detected. All required ports are available."
            $noConflicts = $true
        }

        # Separate groups
        if (-not $noConflicts){
            $reverseProxyConflicts = $active | Where-Object { $_.Port -in 80,443 }
            $kestrelConflicts      = $active | Where-Object { $_.Port -in 5000,5001 }

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

        # Kestrel backend port conflicts
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
    switch ("$PreReqOnly|$CompletionOnly") {

        "True|False" {
            # -PreReqOnly was specified
            Info "Beginning install of PowerSyncPro dependencies..."
            break
        }

        "False|True" {
            # -CompletionOnly was specified
            Info "Completing PowerSyncPro Certificate Installation and Hardening..."
            Info "Using a $CertType Certificate with a Hostname of $FrontendHost..."
            break
        }

        "False|False" {
            # Neither flag was specified (normal full install)
            Info "Beginning install of PowerSyncPro dependencies and application...."
            Info "Using a $CertType Certificate with a Hostname of $FrontendHost..."
        }
    }

    # If were not in CompletionOnly Mode, install the dependencies...
    if (-not $CompletionOnly){
        if (-not (Test-dotNet8Hosting -RequiredVersions $DotNetVer)) {
            Install-dotNet8Hosting -metadataUrl $metadataUrl -tempDir $tempDir 
        }

        if (-not (Test-VCRedistributable -RequiredVersion $vcVer)){
            Install-VCRedistributable -DownloadURL $vcDownloadURL -TempDir $tempDir
        }

        # Install SQL Express only if the user selected "Install new SQL Express"
        if ($InstallSqlExpress) {

            Info ("Installing SQL Express instance '{0}'..." -f $SqlInstance)

            if (-not [string]::IsNullOrWhiteSpace($PSPServiceUser)) {
                $SQLAdminsGroup = New-LocalSqlAdminsGroup -ServiceUser $PSPServiceUser
                Install-SQLExpress -BootstrapperUrl $SQLBootstrapperUrl -tempDir $tempDir `
                                -InstanceName $SqlInstance -SQLAdminsGroup $SQLAdminsGroup
            }
            else {
                Install-SQLExpress -BootstrapperUrl $SQLBootstrapperUrl -tempDir $tempDir `
                                -InstanceName $SqlInstance
            }
        }

        # Install SSMS if not installed and we are not using an external server.
        if (-not (Test-SSMS) -and -not $ExternalServerInUse){
            Install-SSMS -SsmsUrl $SsmsUrl -tempDir $tempDir
        }

        # Test IIS and other functions are installed.
        Info "Checking current IIS Status on system..."
        $features = Test-IISFeatures
        Install-IIS -IISInstalled $features.IISInstalled -WebIPInstalled $features.WebIPInstalled

        # Install IIS Dependencies
        # Install IIS URL Rewrite
        if(-not (Test-IISUrlRewrite)){
        Install-URLRewrite -RewriteUrl $RewriteUrl -tempDir $tempDir
        }

        # Install and Activate IIS ARR (Advanced Request Routing)
        $arrStatus = Test-IISARR
        Install-ARR -ARRInstalled $arrStatus.ARRInstalled -ARRActivated $arrStatus.ARRActivated -ArrUrl $ArrUrl -tempDir $tempDir
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

    # Install PSP if we are not in PreReq or Completion Mode
    if (-not $PreReqOnly -and -not $CompletionOnly) {
        # Install PSP, choose proper database for installation type.
        Info ("Installing PowerSyncPro using SQL instance '{0}'..." -f $SqlInstance)
        if ($UseServiceAccount -eq $true) {
            Install-PSP -PSPUrl $PSPUrl -tempDir $TempDir -SqlAddress $SqlAddress -SqlPort $SqlPort `
                        -SqlInstance $SqlInstance -SqlDatabase $SqlDatabase -FrontendHost $FrontendHost `
                        -PSPServiceUser $PSPServiceUser -PSPServicePassword $PSPServicePassword
        }
        else {
            Install-PSP -PSPUrl $PSPUrl -tempDir $TempDir -SqlAddress $SqlAddress -SqlPort $SqlPort `
                        -SqlInstance $SqlInstance -SqlDatabase $SqlDatabase -FrontendHost $FrontendHost
        }
    }

    # Setup Service Dependencies in Completion Only Mode
    # If Script is in Completion Only ($CompletionOnly) or Normal mode and if we are not using an external server (-not $ExternalServerInUse)
    if (-not $PreReqOnly -and -not $ExternalServerInUse) {
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
        # ACME Cert Puller - if doing a LetsEncrypt Certificate
        if ($CertType -eq "LetsEncrypt"){
            Info "Installing ACME / LetsEncrypt Certificate Tool `($CertPullerScriptName`) to $ScriptFolder"
            Install-Scripts -TargetFile $CertPullerScriptName -TargetFolder $ScriptFolder -URL $CertPullerURL
        }

        # Cert Renewer - if doing a BYOC Certificate Install
        if ($CertType -eq "BYOC"){
            Info "Installing Certificate Renewal Tool `($CertRenewerScriptName`) to $ScriptFolder"
            Install-Scripts -TargetFile $CertRenewerScriptName -TargetFolder $ScriptFolder -URL $CertRenewerURL
        }
    
        # WebConfig Editor Tool
        Info "Installing Web.Config Editor Tool `($WebConfigScriptName`) to $ScriptFolder"
        Install-Scripts -TargetFile $WebConfigScriptName -TargetFolder $ScriptFolder -URL $WebConfigScriptURL

        # Install Custom WebConifg
        Info "Installing Customized $WebConfigName to $WebConfigFolder"
        Install-WebConfig -FrontendHost $FrontendHost -TargetFolder $WebConfigFolder -TargetFile $WebConfigName

        # Setup IIS and Unlock Required Sections
        Info "Unlocking configuration section for web.config..."
        Initialize-IIS

        # Add Frontend Host to local Hosts File
        Info "Editing Hosts file to add entry for $FrontendHost pointing to 127.0.0.1..."
        Install-HostsFile -FrontendHost $FrontendHost

        # Add Firewall Rule for Port 443
        Info "Opening Port 443 on Firewall for IIS..."
        Add-FirewallRuleForPort -Port 443

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
                    Install-ACMECertificate -FrontendHost $FrontendHost -ContactEmail $CertConfig.Email

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
                    Install-CustomPfxCertificate -PfxPath $CertConfig.PfxPath -Password $CertConfig.PfxPass
                    $certInstalled = $true
                } catch {
                    Warn "BYOC certificate install failed: $($_.Exception.Message)"
                    $certInstalled = $false
                }
            }
            'SelfSigned' {
                try{
                    Info "Installation tasks completed, installing self-signed certificate for $FrontendHost..."
                    Install-SelfSignedCertificate -DnsName $FrontendHost
                    $certInstalled = $true
                } catch {
                    Warn "Self Signed certificate install failed: $($_.Exception.Message)"
                    $certInstalled = $false
                }
            }
            default {
                Warn "Unknown certificate type: $CertType - Certificate has not been installed.  Please contact support."
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

                default {
                    Write-Host "Unknown certificate type $CertType - no troubleshooting guidance available. Contact Support." -ForegroundColor Yellow
                }
            }
        }

        # Complete.
        Write-Host "`n"
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
        }
        Write-Host "`n"
        Write-Host "Admin access to PSP via the Reverse Proxy - e.g. https://$FrontendHost has been restricted to localhost only." -ForegroundColor Cyan
        Write-Host "You can modify hosts which are allowed to access the HTTPS Reverse Proxy by running C:\Scripts\WebConfig_Editor.ps1."
        Write-Host "This restriction does not apply on https://$FrontendHost/Agent which is used for the PSP Migration Agent."
        Write-Host "`n"
        Write-Host "You can now access PowerSyncPro at https://$FrontendHost/ from this system." -ForegroundColor Yellow
        Write-Host "The default password is admin / 123qwe, please change it." -ForegroundColor Yellow
        Write-Host "`n"
        Write-Host "We recommend you reboot your server before using PowerSyncPro." -ForegroundColor Yellow
        Write-Host "If you need additional support or assistance:"
        Write-Host "PowerSyncPro Knowledge Base: https://kb.powersyncpro.com/"
        Write-Host "Open a ticket at https://tickets.powersyncpro.com/."
        Write-Host "`n"
        Write-Host "Congrats!" -ForegroundColor Green
        Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
    }
    
}
catch {
    Write-Error "Unhandled error: $($_.Exception.Message)"
}
finally{
    Stop-Transcript
}