<#
.DESCRIPTION
    The script checks for PowerSyncPro installation prerequisites 
 
.NOTES
    Date            November/2024
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 1.0
#>

Clear-Host

# Menu for selecting installation purpose
Write-Host "PLEASE SELECT YOUR POWERSYNCPRO SERVER INSTALLATION PURPOSE:" -ForegroundColor Cyan
Write-Host "1. DIRECTORY SYNCHRONISATION"
Write-Host "2. MIGRATION AGENT"
Write-Host "3. BOTH OF THE ABOVE"

# Capture user input
$selection = Read-Host -Prompt "Enter the number corresponding to your choice (1, 2, or 3)"

# Function to get system information
function Get-SystemInfo {
    try {
        # Get the number of virtual CPUs (logical processors)
        $systemInfo = Get-WmiObject -Class Win32_ComputerSystem
        $numVirtualCpus = $systemInfo.NumberOfLogicalProcessors

        # Get total installed RAM in GB
        $ramInfo = Get-WmiObject -Class Win32_ComputerSystem
        $totalRamGB = [math]::round($ramInfo.TotalPhysicalMemory / 1GB, 2)

        # Get data drives and free space
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } # Only local hard drives
        $driveInfo = $drives | Select-Object DeviceID, @{Name="FreeSpaceGB";Expression={[math]::round($_.FreeSpace / 1GB, 2)}}, @{Name="SizeGB";Expression={[math]::round($_.Size / 1GB, 2)}}

        # Output the results
        Write-Host "System Information:" -ForegroundColor Cyan
        Write-Host "----------------------"
        Write-Host "Number of Virtual CPUs: $numVirtualCpus" -ForegroundColor Green
        Write-Host "Total RAM: $totalRamGB GB" -ForegroundColor Green
        Write-Host "Data Drives and Free Space:"
        $driveInfo | ForEach-Object {
            Write-Host "$($_.DeviceID) - Free Space: $($_.FreeSpaceGB) GB of $($_.SizeGB) GB" -ForegroundColor Yellow
        }
        Write-Host "----------------------"
    }
    catch {
        Write-Host "Error retrieving system information: $_" -ForegroundColor Red
        Write-Host "----------------------"
    }
}


# Function to check if the machine is domain-joined or part of a workgroup
function Check-DomainOrWorkgroup {
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem

    if ($computerSystem.Domain) {
        Write-Host "Domain join information:" -ForegroundColor Cyan
        Write-Host "This machine is domain-joined to: $($computerSystem.Domain)" -ForegroundColor Green
        Write-Host "----------------------"
    } else {
        Write-Host "Domain join information:" -ForegroundColor Cyan
        Write-Host "This machine is part of a workgroup. Workgroup: $($computerSystem.Workgroup)" -ForegroundColor Red
        Write-Host "----------------------"
    }
}


# Function to check installed software with version handling
function Check-InstalledSoftware {
    param(
        [string]$SoftwareName,
        [string]$RequiredVersion = $null
    )

    $installedSoftware = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                         Get-ItemProperty |
                         Where-Object { $_.DisplayName -like "*$SoftwareName*" } |
                         Select-Object DisplayName, DisplayVersion

    if ($installedSoftware) {
        foreach ($software in $installedSoftware) {
            $installedVersion = $software.DisplayVersion -replace '[^0-9\.]', '' # Clean version string
            if ([string]::IsNullOrWhiteSpace($installedVersion)) {
                Write-Host "$SoftwareName is installed but version information is unavailable." -ForegroundColor Yellow
            }
            elseif ($RequiredVersion -and [version]$installedVersion -lt [version]$RequiredVersion) {
                Write-Host "$SoftwareName is installed (version $installedVersion) but does not meet the required version ($RequiredVersion or later)." -ForegroundColor Red
            } else {
                Write-Host "$SoftwareName is installed (version $installedVersion)." -ForegroundColor Green
            }
            return $true
        }
    }

    Write-Host "$SoftwareName is not installed." -ForegroundColor Red
    return $false
}


# Check Windows Server Version
function Check-WindowsServerVersion {
    param(
        [string]$RequiredBuild = "14393" # Build 14393 corresponds to Windows Server 2016
    )

    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    $buildNumber = ($osVersion -split '\.')[2]

    if ([version]$osVersion -lt [version]"10.0.$RequiredBuild") {
        Write-Host "Windows Server version $osVersion does not meet the required build ($RequiredBuild or later)." -ForegroundColor Red
    } else {
        Write-Host "Windows Server version $osVersion meets the requirement (build $RequiredBuild or later)." -ForegroundColor Green
    }
}

# Function to check SQL Server version
function Check-SQLServer {
    # Path to SQL Server registry entry
    $key = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    $instances = Get-ChildItem -Path $key -ErrorAction SilentlyContinue

    if ($instances) {
        foreach ($instance in $instances) {
            $setupKey = "$($instance.PSPath)\Setup"
            $sqlVersion = (Get-ItemProperty -Path $setupKey -ErrorAction SilentlyContinue).Version

            if ($sqlVersion) {
                # If the version is a simple year format, e.g. "2019", append ".0.0.0"
                if ($sqlVersion -match '^\d{4}$') {
                    $sqlVersion = "$sqlVersion.0.0.0"  # Add sub-version to ensure it's a valid version string
                }

                Write-Host "SQL Server version: $sqlVersion" -ForegroundColor Green
                return
            }
        }
    }

    Write-Host "SQL Server is not installed." -ForegroundColor Red
    Write-Host "You could download SQL Express 2022 here: https://go.microsoft.com/fwlink/p/?linkid=2216019&clcid=0x409&culture=en-us&country=us"
}

# Function to check installed .NET ASP.NET Core Runtimes
function Check-ASPNETCoreRuntimes {
    param(
        [string[]]$RequiredVersions = @("8")
    )

    Write-Host "Checking for .NET ASP.NET Core Runtimes..." -ForegroundColor Cyan

    # Run 'dotnet --list-runtimes' to get installed runtimes
    try {
        $runtimes = & dotnet --list-runtimes
    }
    catch {
        Write-Host "Failed to execute 'dotnet' command." -ForegroundColor Red
        return
    }

    # List of installed runtimes
    $installedRuntimes = @()
    if ($runtimes) {
        $installedRuntimes = $runtimes -match "Microsoft\.AspNetCore\.App\s+[0-9]+\.[0-9]+\.[0-9]+" | ForEach-Object { $_.Trim() }
        Write-Host "Installed .NET ASP.NET Core Runtimes:" -ForegroundColor Cyan
        $installedRuntimes | ForEach-Object { Write-Host "$_ (Installed)" }
    } else {
        Write-Host "No .NET ASP.NET Core runtimes found." -ForegroundColor Red
    }

    # Check for required versions
    foreach ($version in $RequiredVersions) {
        $found = $false
        foreach ($runtime in $installedRuntimes) {
            if ($runtime -like "*$version*") {
                Write-Host "ASP.NET Core Runtime version $version is installed." -ForegroundColor Green
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "ASP.NET Core Runtime version $version is not installed." -ForegroundColor Red
            Write-Host "You could download ASP.NET Core Runtime 8.x HOSTING BUNDLE here: https://dotnet.microsoft.com/en-us/download/dotnet/8.0"
        }
    }
}


# Check for Visual C++ Redistributables
function Check-VisualCPlusPlusRedistributables {
    $installedSoftware = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                         Get-ItemProperty |
                         Where-Object { $_.DisplayName -like "*Visual C++*" } |
                         Select-Object DisplayName, DisplayVersion

    if ($installedSoftware) {
        Write-Host "Microsoft Visual C++ Redistributables are installed:" -ForegroundColor Green
        foreach ($software in $installedSoftware) {
            Write-Host " - $($software.DisplayName) (Version $($software.DisplayVersion))"
        }
    } else {
        Write-Host "Microsoft Visual C++ Redistributables are not installed." -ForegroundColor Red
        Write-Host "You could download Microsoft Visual C++ Redistributables here: https://aka.ms/vs/17/release/vc_redist.x64.exe" 
    }
}


function Run-ConnectivityTests {
    # Connectivity tests
    Write-Host "Starting connectivity tests..." -ForegroundColor Cyan

    # Check localhost ports
    $localhostPorts = @(443, 5000, 5001)
    Write-Host "Checking ports 443, 5000, and 5001 on localhost..."
    foreach ($port in $localhostPorts) {
        $result = Test-NetConnection -ComputerName "localhost" -Port $port
        if ($result.TcpTestSucceeded) {
            Write-Host "Port $port on localhost is OPEN." -ForegroundColor Green
        } else {
            Write-Host "Port $port on localhost is CLOSED." -ForegroundColor Red
        }
    }

    # Ask how many domains to test connectivity to
    $domainCount = [int](Read-Host "How many ACTIVE DIRECTORY Domains would you like to test connectivity to? Enter 0 for none")
    if ($domainCount -gt 0) {
        for ($i = 1; $i -le $domainCount; $i++) {
            Write-Host "Testing connectivity to Domain $i of $domainCount..."
            $domainController = Read-Host "Enter the FQDN of the Active Directory Domain Controller for domain $i"

            # Test port 389 on the Domain Controller
            Write-Host "Testing connectivity to $domainController on port 389..."
            $result = Test-NetConnection -ComputerName $domainController -Port 389
            if ($result.TcpTestSucceeded) {
                Write-Host "Port 389 on $domainController is OPEN." -ForegroundColor Green
            } else {
                Write-Host "Port 389 on $domainController is CLOSED." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No domains selected for testing. Skipping Active Directory connectivity tests." -ForegroundColor Yellow
    }

    # Hardcoded FQDNs for Microsoft 365 tenant entry points
    $tenantFQDNs = @(
        "account.activedirectory.windowsazure.com",
        "accounts.accesscontrol.windows.net",
        "adminwebservice.microsoftonline.com",
        "api.passwordreset.microsoftonline.com",
        "autologon.microsoftazuread-sso.com",
        "becws.microsoftonline.com",
        "ccs.login.microsoftonline.com",
        "clientconfig.microsoftonline-p.net",
        "companymanager.microsoftonline.com",
        "device.login.microsoftonline.com",
        "graph.microsoft.com",
        "graph.windows.net",
        "login.microsoft.com",
        "login.microsoftonline.com",
        "login.microsoftonline-p.com",
        "login.windows.net",
        "logincert.microsoftonline.com",
        "loginex.microsoftonline.com",
        "login-us.microsoftonline.com",
        "nexus.microsoftonline-p.com",
        "passwordreset.microsoftonline.com",
        "provisioningapi.microsoftonline.com"
    )

    Write-Host "Testing connectivity to generic M365 tenant entry points..."
    $successCount = 0
    $failureCount = 0

    foreach ($fqdn in $tenantFQDNs) {
        $result = Test-NetConnection -ComputerName $fqdn -Port 443
        if ($result.TcpTestSucceeded) {
            $successCount++
        } else {
            Write-Host "Port 443 on $fqdn is CLOSED." -ForegroundColor Red
            $failureCount++
        }
    }

    # Display summary
    if ($successCount -eq $tenantFQDNs.Count) {
        Write-Host "Port 443 to all generic M365 tenant entry points is OPEN." -ForegroundColor Green
    } elseif ($failureCount -eq $tenantFQDNs.Count) {
        Write-Host "Port 443 connection to all generic M365 tenant entry points FAILED." -ForegroundColor Red
    } else {
        Write-Host "Port 443 connection to generic M365 tenant entry points is LIMITED." -ForegroundColor Yellow
    }

    Write-Host "Connectivity tests completed." -ForegroundColor Cyan
}


# Main script logic
if ($selection -eq "1") {
    # Run only the specified checks
    Write-Host "You selected: DIRECTORY SYNCHRONISATION" -ForegroundColor Green
    # Main script logic
$PrerequisiteSoftware = @(
    @{ Name = "Windows Server"; Function = "Check-WindowsServerVersion"; Version = "14393" },
    @{ Name = "SQL Server" ; Function = "Check-SQLServer" ; Version = "2019" },
    @{ Name = "SQL Server Management Studio" },
    @{ Name = ".NET ASP.NET Core Runtimes" ; Function = "Check-ASPNETCoreRuntimes"; Versions = @("8") },
    @{ Name = "Microsoft Visual C++ Redistributables"; Function = "Check-VisualCPlusPlusRedistributables" }
)

foreach ($software in $PrerequisiteSoftware) {
    $name = $software.Name
    $function = $software.Function
    $version = $software.Version
    $versions = $software.Versions

    Write-Host "Checking for $name..." -ForegroundColor Yellow

    if ($function) {
        if ($versions) {
            Invoke-Command -ScriptBlock ([scriptblock]::Create($function)) -ArgumentList $versions
        } else {
            Invoke-Command -ScriptBlock ([scriptblock]::Create($function)) -ArgumentList $version
        }
    } else {
        Check-InstalledSoftware -SoftwareName $name -RequiredVersion $version| Out-Null
    }

    Write-Host "----------------------------------------" -ForegroundColor Gray
}

    Run-ConnectivityTests
}
elseif ($selection -eq "2" -or $selection -eq "3") {
    # Run the whole script
    Write-Host "You selected: MIGATION AGENT OR BOTH OF THE ABOVE" -ForegroundColor Green

    # Main script logic
$PrerequisiteSoftware = @(
    @{ Name = "Windows Server"; Function = "Check-WindowsServerVersion"; Version = "14393" },
    @{ Name = "SQL Server" ; Function = "Check-SQLServer" ; Version = "2019" },
    @{ Name = "SQL Server Management Studio" },
    @{ Name = ".NET ASP.NET Core Runtimes" ; Function = "Check-ASPNETCoreRuntimes"; Versions = @("8") },
    @{ Name = "Microsoft Visual C++ Redistributables"; Function = "Check-VisualCPlusPlusRedistributables" },
    @{ Name = "IIS" },
    @{ Name = "URL Rewrite" },
    @{ Name = "Microsoft Application Request Routing" }
)

foreach ($software in $PrerequisiteSoftware) {
    $name = $software.Name
    $function = $software.Function
    $version = $software.Version
    $versions = $software.Versions

    Write-Host "Checking for $name..." -ForegroundColor Yellow

    if ($function) {
        if ($versions) {
            Invoke-Command -ScriptBlock ([scriptblock]::Create($function)) -ArgumentList $versions
        } else {
            Invoke-Command -ScriptBlock ([scriptblock]::Create($function)) -ArgumentList $version
        }
    } else {
        Check-InstalledSoftware -SoftwareName $name -RequiredVersion $version| Out-Null
    }

    Write-Host "----------------------------------------" -ForegroundColor Gray
}

    Run-ConnectivityTests
}
else {
    Write-Host "Invalid selection. Please run the script again and select a valid option." -ForegroundColor Red
}
 
