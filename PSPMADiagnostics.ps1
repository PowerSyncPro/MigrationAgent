<#
.SYNOPSIS
Collects PowerSyncPro Migration Agent workstation diagnostics and zips the results.

.DESCRIPTION
This script gathers a broad set of workstation diagnostics useful for PowerSyncPro support analysis.
It writes the results to a timestamped folder under C:\Users\Public\Documents\PowerSyncPro and then creates a ZIP archive.

Collected items include:
- Hostname / FQDN
- Hosts file entries matching the PSP URL host from registry
- Domain / workgroup status
- Entra join / Workplace join / MDM status via dsregcmd
- PowerSyncPro Migration Agent service status
- IP configuration
- WinHTTP / proxy information
- Windows OS version
- Firewall state
- Free disk space
- PSP Migration Agent EXE file version
- Folder listing of C:\ProgramData\Declaration Software
- Full copy of C:\ProgramData\Declaration Software into the diagnostics output so it is included in the ZIP
- Recursive registry dumps for:
  - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ
  - HKLM:\SOFTWARE\Microsoft\Enrollments
  - HKLM:\SOFTWARE\Declaration Software\Migration Agent
- Ping / nslookup / Test-NetConnection of the PSP MA URL host from registry
- Network adapter / profile / WLAN info
- Heuristic detection of endpoint protection tools
- Microsoft Defender state
- gpresult /r
- Local machine certificates (My / Root / CA)
- Application event log export
- Last 10 Application log entries from source "PowerSyncPro Migration Agent"
- MDM event log exports for:
  - Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin
  - Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational
- Local user profile names / SIDs / paths

.NOTES
- Run elevated where possible.
- Designed to be simple for end users to run without parameters.

.Version
- first version (v5 from internal) 24th April 2026
#>

$ErrorActionPreference = 'Continue'

# ----------------------------------------------------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------------------------------------------------
$Now = Get-Date
$TimeStamp = $Now.ToString('yyyy-MM-dd_HHmmss')
$ComputerName = $env:COMPUTERNAME

$BasePath = 'C:\Users\Public\Documents\PowerSyncPro'
if (-not (Test-Path $BasePath)) {
    New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
}

$OutputFolder = Join-Path $BasePath "$($ComputerName)_PSP_Diagnostics_$TimeStamp"
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$SummaryFile = Join-Path $OutputFolder "00_Summary.txt"
$ZipFile = Join-Path $BasePath "$($ComputerName)_PSP_Diagnostics_$TimeStamp.zip"

# ----------------------------------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------------------------------
function Write-Section {
    param(
        [string]$Title,
        [string[]]$Lines
    )

    Add-Content -Path $SummaryFile -Value ""
    Add-Content -Path $SummaryFile -Value ("=" * 100)
    Add-Content -Path $SummaryFile -Value $Title
    Add-Content -Path $SummaryFile -Value ("=" * 100)

    if ($Lines) {
        $Lines | ForEach-Object { Add-Content -Path $SummaryFile -Value $_ }
    }
}

function Run-CommandToFile {
    param(
        [string]$FilePath,
        [scriptblock]$ScriptBlock
    )

    try {
        & $ScriptBlock | Out-File -FilePath $FilePath -Encoding UTF8 -Width 5000
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $FilePath -Encoding UTF8
    }
}

function Get-FileVersionSafe {
    param(
        [string]$Path
    )

    try {
        if (Test-Path $Path) {
            return (Get-Item $Path).VersionInfo.FileVersion
        }
        return $null
    }
    catch {
        return $null
    }
}

function Get-FqdnSafe {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain -and $cs.Domain) {
            return "$($env:COMPUTERNAME).$($cs.Domain)"
        }

        try {
            return [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        }
        catch {
            return $env:COMPUTERNAME
        }
    }
    catch {
        return $env:COMPUTERNAME
    }
}

function Get-PspUrlInfo {
    $regPath = 'HKLM:\SOFTWARE\Declaration Software\Migration Agent'
    try {
        $url = (Get-ItemProperty -Path $regPath -ErrorAction Stop).URL
        if ([string]::IsNullOrWhiteSpace($url)) {
            return [PSCustomObject]@{
                Url  = $null
                Host = $null
            }
        }

        $uri = [System.Uri]$url
        return [PSCustomObject]@{
            Url  = $url
            Host = $uri.Host
        }
    }
    catch {
        return [PSCustomObject]@{
            Url  = $null
            Host = $null
        }
    }
}

function Get-RegistryTreeDump {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $lines = @()

    try {
        if (-not (Test-Path $Path)) {
            return @("Registry path not found: $Path")
        }

        $rootKey = Get-Item -Path $Path -ErrorAction Stop
        $childKeys = @(Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue)
        $allKeys = @($rootKey) + $childKeys

        foreach ($key in $allKeys) {
            $lines += ("-" * 100)
            $lines += "Key: $($key.Name)"
            $lines += "PSPath: $($key.PSPath)"

            try {
                $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                $visibleProps = $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }

                if ($visibleProps) {
                    foreach ($prop in $visibleProps) {
                        $value = $prop.Value
                        if ($value -is [array]) {
                            $value = ($value -join '; ')
                        }
                        $lines += "{0} = {1}" -f $prop.Name, $value
                    }
                }
                else {
                    $lines += "(No visible values)"
                }
            }
            catch {
                $lines += "ERROR reading values: $($_.Exception.Message)"
            }

            $lines += ""
        }

        return $lines
    }
    catch {
        return @("ERROR reading registry tree $Path : $($_.Exception.Message)")
    }
}


function Format-SafeDateTime {
    param(
        $Value,
        [string]$Format = 'yyyy-MM-dd HH:mm:ss'
    )

    try {
        if ($null -eq $Value) {
            return $null
        }

        if ($Value -is [datetime]) {
            return $Value.ToString($Format)
        }

        $stringValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($stringValue)) {
            return $null
        }

        try {
            return ([Management.ManagementDateTimeConverter]::ToDateTime($stringValue)).ToString($Format)
        }
        catch {
            try {
                return ([datetime]::Parse($stringValue)).ToString($Format)
            }
            catch {
                return $stringValue
            }
        }
    }
    catch {
        return [string]$Value
    }
}

function Find-SecurityProducts {
    $patterns = @(
        'CrowdStrike','Carbon Black','Cb Defense','SentinelOne','Defender','Cylance',
        'Sophos','Symantec','Trend Micro','McAfee','Trellix','ESET','Bitdefender',
        'Malwarebytes','Palo Alto','Cortex','Falcon','Deep Security','Webroot'
    )

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $services = Get-Service | Where-Object {
            $name = $_.Name
            $display = $_.DisplayName
            foreach ($pattern in $patterns) {
                if ($name -match [regex]::Escape($pattern) -or $display -match [regex]::Escape($pattern)) { return $true }
            }
            return $false
        }

        foreach ($svc in $services) {
            $results.Add([PSCustomObject]@{
                Source = 'Service'
                Name   = $svc.Name
                Detail = "$($svc.DisplayName) | Status=$($svc.Status)"
            })
        }
    }
    catch {}

    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $procName = $_.ProcessName
            foreach ($pattern in $patterns) {
                if ($procName -match [regex]::Escape($pattern)) { return $true }
            }
            return $false
        }

        foreach ($proc in $procs) {
            $results.Add([PSCustomObject]@{
                Source = 'Process'
                Name   = $proc.ProcessName
                Detail = "Id=$($proc.Id)"
            })
        }
    }
    catch {}

    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $uninstallPaths) {
        try {
            $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
                $dn = $_.DisplayName
                if ([string]::IsNullOrWhiteSpace($dn)) { return $false }

                foreach ($pattern in $patterns) {
                    if ($dn -match [regex]::Escape($pattern)) { return $true }
                }
                return $false
            }

            foreach ($app in $apps) {
                $results.Add([PSCustomObject]@{
                    Source = 'InstalledApp'
                    Name   = $app.DisplayName
                    Detail = $app.DisplayVersion
                })
            }
        }
        catch {}
    }

    $results | Sort-Object Source, Name -Unique
}

function Export-CertificateStore {
    param(
        [Parameter(Mandatory)]
        [string]$StorePath,
        [Parameter(Mandatory)]
        [string]$CsvPath,
        [Parameter(Mandatory)]
        [string]$TxtPath
    )

    try {
        if (Test-Path $StorePath) {
            $certs = Get-ChildItem -Path $StorePath -ErrorAction Stop | Select-Object `
                PSParentPath,
                Thumbprint,
                Subject,
                Issuer,
                FriendlyName,
                NotBefore,
                NotAfter,
                HasPrivateKey,
                SerialNumber,
                SignatureAlgorithm,
                Version

            $certs | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            $certs | Format-Table -AutoSize | Out-File -FilePath $TxtPath -Encoding UTF8 -Width 5000
        }
        else {
            "Certificate store not found: $StorePath" | Out-File -FilePath $TxtPath -Encoding UTF8
        }
    }
    catch {
        "ERROR exporting certificate store $StorePath : $($_.Exception.Message)" | Out-File -FilePath $TxtPath -Encoding UTF8
    }
}

# ----------------------------------------------------------------------------------------------------------------------
# Start summary
# ----------------------------------------------------------------------------------------------------------------------
"PowerSyncPro Migration Diagnostics" | Out-File -FilePath $SummaryFile -Encoding UTF8
"Generated: $Now" | Add-Content -Path $SummaryFile
"ComputerName: $ComputerName" | Add-Content -Path $SummaryFile
"OutputFolder: $OutputFolder" | Add-Content -Path $SummaryFile

# ----------------------------------------------------------------------------------------------------------------------
# Gather key facts first
# ----------------------------------------------------------------------------------------------------------------------
$cs = $null
$os = $null
$fqdn = $env:COMPUTERNAME
$domainStatus = $null
$domainName = $null
$pspExe = 'C:\Program Files\Declaration Software\PSP MA\DeclarationSoftware.PowerSyncPro.MigrationAgent.exe'
$pspVersion = $null
$pspUrlInfo = $null
$pspServiceSummary = $null
$cDriveFreeGb = $null
$pingSummary = $null
$tnc443Summary = $null
$tnc5000Summary = $null
$dsregFile = Join-Path $OutputFolder "01_dsregcmd_status.txt"

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $fqdn = Get-FqdnSafe
    $domainStatus = if ($cs.PartOfDomain) { "DomainJoined" } else { "WORKGROUP" }
    $domainName = if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }
}
catch {}

$pspVersion = Get-FileVersionSafe -Path $pspExe
$pspUrlInfo = Get-PspUrlInfo

Run-CommandToFile -FilePath $dsregFile -ScriptBlock { cmd /c 'dsregcmd /status' }

try {
    $pspSvc = Get-Service | Where-Object {
        $_.Name -match 'PowerSyncPro|Declaration' -or $_.DisplayName -match 'PowerSyncPro|Declaration'
    } | Select-Object -First 1

    if ($pspSvc) {
        $pspStartMode = (Get-CimInstance Win32_Service -Filter "Name='$($pspSvc.Name)'" -ErrorAction SilentlyContinue).StartMode
        $pspServiceSummary = "Name=$($pspSvc.Name) | DisplayName=$($pspSvc.DisplayName) | Status=$($pspSvc.Status) | Started=$([string]($pspSvc.Status -eq 'Running')) | StartType=$pspStartMode"
    }
    else {
        $pspServiceSummary = "No matching PowerSyncPro / Declaration service found."
    }
}
catch {
    $pspServiceSummary = "ERROR: $($_.Exception.Message)"
}

try {
    $cDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if ($cDrive) {
        $cDriveFreeGb = [math]::Round($cDrive.FreeSpace / 1GB, 2)
    }
}
catch {}

try {
    if ($pspUrlInfo.Host) {
        $pingOk = Test-Connection -ComputerName $pspUrlInfo.Host -Count 1 -Quiet -ErrorAction SilentlyContinue
        $pingSummary = if ($pingOk) { "PingSuccess" } else { "PingFailed" }

        $tnc443 = Test-NetConnection -ComputerName $pspUrlInfo.Host -Port 443 -WarningAction SilentlyContinue
        $tnc5000 = Test-NetConnection -ComputerName $pspUrlInfo.Host -Port 5000 -WarningAction SilentlyContinue

        $tnc443Summary = if ($tnc443.TcpTestSucceeded) { "True" } else { "False" }
        $tnc5000Summary = if ($tnc5000.TcpTestSucceeded) { "True" } else { "False" }
    }
    else {
        $pingSummary = "No PSP URL host found"
        $tnc443Summary = "No PSP URL host found"
        $tnc5000Summary = "No PSP URL host found"
    }
}
catch {
    $pingSummary = "Ping test error: $($_.Exception.Message)"
    $tnc443Summary = "Test-NetConnection error"
    $tnc5000Summary = "Test-NetConnection error"
}

# ----------------------------------------------------------------------------------------------------------------------
# Key Findings
# ----------------------------------------------------------------------------------------------------------------------
$dsregQuick = @()
try {
    $dsregQuick = Get-Content $dsregFile | Where-Object {
        $_ -match 'AzureAdJoined' -or
        $_ -match 'DomainJoined' -or
        $_ -match 'WorkplaceJoined' -or
        $_ -match 'DeviceId' -or
        $_ -match 'TenantName' -or
        $_ -match 'TenantId' -or
        $_ -match 'MdmUrl' -or
        $_ -match 'AzureAdPrt'
    }
}
catch {}

Write-Section -Title "Key Findings" -Lines @(
    "Hostname: $env:COMPUTERNAME"
    "FullyQualifiedHostname: $fqdn"
    "DomainJoinStatus: $domainStatus"
    "DomainOrWorkgroupName: $domainName"
    "WindowsVersion: $($os.Version)"
    "BuildNumber: $($os.BuildNumber)"
    "PSPService: $pspServiceSummary"
    "PSPMigrationAgentExeExists: $(Test-Path $pspExe)"
    "PSPMigrationAgentFileVersion: $pspVersion"
    "PSPRegistryUrl: $($pspUrlInfo.Url)"
    "PSPRegistryUrlHost: $($pspUrlInfo.Host)"
    "PSPRegistryUrlHostPing: $pingSummary"
    "PSPPort443TcpTestSucceeded: $tnc443Summary"
    "PSPPort5000TcpTestSucceeded: $tnc5000Summary"
    "CDriveFreeGB: $cDriveFreeGb"
) + $dsregQuick

# ----------------------------------------------------------------------------------------------------------------------
# Host / Domain / OS
# ----------------------------------------------------------------------------------------------------------------------
try {
    Write-Section -Title "Host / Domain / OS" -Lines @(
        "Hostname: $env:COMPUTERNAME"
        "FullyQualifiedHostname: $fqdn"
        "DomainJoinStatus: $domainStatus"
        "DomainOrWorkgroupName: $domainName"
        "Manufacturer: $($cs.Manufacturer)"
        "Model: $($cs.Model)"
        "WindowsCaption: $($os.Caption)"
        "WindowsVersion: $($os.Version)"
        "BuildNumber: $($os.BuildNumber)"
        "InstallDate: $(Format-SafeDateTime -Value $os.InstallDate)"
        "LastBootUpTime: $(Format-SafeDateTime -Value $os.LastBootUpTime)"
    )
}
catch {
    Write-Section -Title "Host / Domain / OS" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# Hosts file - PSP host entries only
# ----------------------------------------------------------------------------------------------------------------------
$hostsPath = 'C:\Windows\System32\drivers\etc\hosts'

try {
    if ($pspUrlInfo.Host) {
        $hostMatches = @()

        if (Test-Path $hostsPath) {
            $hostMatches = Get-Content $hostsPath | Where-Object {
                $_ -match [regex]::Escape($pspUrlInfo.Host)
            }
        }

        if ($hostMatches.Count -gt 0) {
            Write-Section -Title "Hosts File - PSP Host Entries" -Lines @(
                "PSPRegistryUrl: $($pspUrlInfo.Url)"
                "PSPRegistryUrlHost: $($pspUrlInfo.Host)"
                ""
                "Matching hosts file entries:"
            ) + $hostMatches
        }
        else {
            Write-Section -Title "Hosts File - PSP Host Entries" -Lines @(
                "PSPRegistryUrl: $($pspUrlInfo.Url)"
                "PSPRegistryUrlHost: $($pspUrlInfo.Host)"
                ""
                "No matching hosts file entries found."
            )
        }
    }
    else {
        Write-Section -Title "Hosts File - PSP Host Entries" -Lines @(
            "No valid PSP URL host found in registry, so hosts file could not be filtered."
        )
    }
}
catch {
    Write-Section -Title "Hosts File - PSP Host Entries" -Lines @(
        "ERROR: $($_.Exception.Message)"
    )
}

# ----------------------------------------------------------------------------------------------------------------------
# PSP service
# ----------------------------------------------------------------------------------------------------------------------
try {
    $svcCandidates = Get-Service | Where-Object {
        $_.Name -match 'PowerSyncPro|Declaration' -or $_.DisplayName -match 'PowerSyncPro|Declaration'
    }

    if ($svcCandidates) {
        $svcLines = foreach ($svc in $svcCandidates) {
            $startMode = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).StartMode
            "$($svc.Name) | $($svc.DisplayName) | Status=$($svc.Status) | StartType=$startMode"
        }
    }
    else {
        $svcLines = @("No matching PowerSyncPro / Declaration service found.")
    }

    Write-Section -Title "PowerSyncPro / Declaration Services" -Lines $svcLines
}
catch {
    Write-Section -Title "PowerSyncPro / Declaration Services" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# IP Config / networking
# ----------------------------------------------------------------------------------------------------------------------
Run-CommandToFile -FilePath (Join-Path $OutputFolder "02_ipconfig_all.txt") -ScriptBlock { ipconfig /all }
Run-CommandToFile -FilePath (Join-Path $OutputFolder "03_route_print.txt") -ScriptBlock { route print }
Run-CommandToFile -FilePath (Join-Path $OutputFolder "04_net_adapters.txt") -ScriptBlock {
    Get-NetAdapter | Sort-Object Status, Name | Format-Table -AutoSize Name, InterfaceDescription, Status, MacAddress, LinkSpeed, ifIndex
}
Run-CommandToFile -FilePath (Join-Path $OutputFolder "05_net_connection_profiles.txt") -ScriptBlock {
    Get-NetConnectionProfile | Format-Table -AutoSize Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
}
Run-CommandToFile -FilePath (Join-Path $OutputFolder "06_wlan_interfaces.txt") -ScriptBlock { netsh wlan show interfaces }
Run-CommandToFile -FilePath (Join-Path $OutputFolder "07_wlan_networks.txt") -ScriptBlock { netsh wlan show networks mode=bssid }

# ----------------------------------------------------------------------------------------------------------------------
# Proxy / WinHTTP / PAC
# ----------------------------------------------------------------------------------------------------------------------
Run-CommandToFile -FilePath (Join-Path $OutputFolder "08_netsh_winhttp_proxy.txt") -ScriptBlock { netsh winhttp show proxy }
Run-CommandToFile -FilePath (Join-Path $OutputFolder "09_wininet_proxy_current_user.txt") -ScriptBlock {
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect
}
Run-CommandToFile -FilePath (Join-Path $OutputFolder "10_wininet_proxy_local_machine.txt") -ScriptBlock {
    if (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings') {
        Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
            Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect
    }
    else {
        "HKLM Internet Settings path not present."
    }
}

# ----------------------------------------------------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------------------------------------------------
Run-CommandToFile -FilePath (Join-Path $OutputFolder "11_firewall_profiles.txt") -ScriptBlock {
    Get-NetFirewallProfile | Format-Table -AutoSize Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules
}

# ----------------------------------------------------------------------------------------------------------------------
# Disk space
# ----------------------------------------------------------------------------------------------------------------------
try {
    $diskLines = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $sizeGB = [math]::Round($_.Size / 1GB, 2)
        $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
        "$($_.DeviceID) | SizeGB=$sizeGB | FreeGB=$freeGB"
    }
    Write-Section -Title "Disk Space" -Lines $diskLines
}
catch {
    Write-Section -Title "Disk Space" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# PSP Migration Agent EXE version
# ----------------------------------------------------------------------------------------------------------------------
Write-Section -Title "PowerSyncPro Migration Agent File Version" -Lines @(
    "Path: $pspExe"
    "Exists: $(Test-Path $pspExe)"
    "FileVersion: $pspVersion"
)

# ----------------------------------------------------------------------------------------------------------------------
# Declaration Software folder listing + file copy
# ----------------------------------------------------------------------------------------------------------------------
$DeclarationSourcePath = 'C:\ProgramData\Declaration Software'
$DeclarationBackupPath = Join-Path $OutputFolder "12_DeclarationSoftware_Files"

Run-CommandToFile -FilePath (Join-Path $OutputFolder "12_programdata_declaration_software_listing.txt") -ScriptBlock {
    if (Test-Path $DeclarationSourcePath) {
        Get-ChildItem $DeclarationSourcePath -Recurse -Force |
            Select-Object FullName, Length, CreationTime, LastWriteTime, Attributes
    }
    else {
        "Path not found: $DeclarationSourcePath"
    }
}

try {
    if (Test-Path $DeclarationSourcePath) {
        Copy-Item -Path $DeclarationSourcePath -Destination $DeclarationBackupPath -Recurse -Force
    }
}
catch {
    "ERROR copying Declaration Software files: $($_.Exception.Message)" |
        Out-File -FilePath (Join-Path $OutputFolder "12_DeclarationSoftware_Copy_Error.txt") -Encoding UTF8
}

# ----------------------------------------------------------------------------------------------------------------------
# Registry dumps
# ----------------------------------------------------------------------------------------------------------------------
(Get-RegistryTreeDump -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ') |
    Out-File -FilePath (Join-Path $OutputFolder "13_registry_CDJ_recursive.txt") -Encoding UTF8

(Get-RegistryTreeDump -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD') |
    Out-File -FilePath (Join-Path $OutputFolder "14_registry_CDJ_AAD.txt") -Encoding UTF8

(Get-RegistryTreeDump -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments') |
    Out-File -FilePath (Join-Path $OutputFolder "15_registry_Enrollments_recursive.txt") -Encoding UTF8

(Get-RegistryTreeDump -Path 'HKLM:\SOFTWARE\Declaration Software\Migration Agent') |
    Out-File -FilePath (Join-Path $OutputFolder "16_registry_PSP_MigrationAgent_recursive.txt") -Encoding UTF8

try {
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" (Join-Path $OutputFolder "13_registry_CDJ.reg") /y | Out-Null
}
catch {}

try {
    reg export "HKLM\SOFTWARE\Microsoft\Enrollments" (Join-Path $OutputFolder "15_registry_Enrollments.reg") /y | Out-Null
}
catch {}

try {
    reg export "HKLM\SOFTWARE\Declaration Software\Migration Agent" (Join-Path $OutputFolder "16_registry_PSP_MigrationAgent.reg") /y | Out-Null
}
catch {}

# ----------------------------------------------------------------------------------------------------------------------
# PSP URL host ping / nslookup / Test-NetConnection
# ----------------------------------------------------------------------------------------------------------------------
if ($pspUrlInfo.Host) {
    Write-Section -Title "PSP URL Host Resolution" -Lines @(
        "Resolved URL from registry: $($pspUrlInfo.Url)"
        "Resolved host from registry URL: $($pspUrlInfo.Host)"
        "PingSummary: $pingSummary"
        "Port443TcpTestSucceeded: $tnc443Summary"
        "Port5000TcpTestSucceeded: $tnc5000Summary"
    )

    Run-CommandToFile -FilePath (Join-Path $OutputFolder "17_ping_psp_host.txt") -ScriptBlock { ping $pspUrlInfo.Host }
    Run-CommandToFile -FilePath (Join-Path $OutputFolder "18_nslookup_psp_host.txt") -ScriptBlock { nslookup $pspUrlInfo.Host }
    Run-CommandToFile -FilePath (Join-Path $OutputFolder "19_test_net_connection_443.txt") -ScriptBlock {
        Test-NetConnection -ComputerName $pspUrlInfo.Host -Port 443
    }
    Run-CommandToFile -FilePath (Join-Path $OutputFolder "20_test_net_connection_5000.txt") -ScriptBlock {
        Test-NetConnection -ComputerName $pspUrlInfo.Host -Port 5000
    }
}
else {
    Write-Section -Title "PSP URL Host Resolution" -Lines @("No valid URL found in HKLM:\SOFTWARE\Declaration Software\Migration Agent\URL")
}

# ----------------------------------------------------------------------------------------------------------------------
# User profiles
# ----------------------------------------------------------------------------------------------------------------------
try {
    $profiles = Get-CimInstance Win32_UserProfile | Select-Object `
        SID,
        LocalPath,
        Loaded,
        Special,
        LastUseTime

    $profiles | Export-Csv -Path (Join-Path $OutputFolder "21_user_profiles.csv") -NoTypeInformation -Encoding UTF8

    $profileLines = foreach ($profile in $profiles | Sort-Object LocalPath) {
        "SID=$($profile.SID) | LocalPath=$($profile.LocalPath) | Loaded=$($profile.Loaded) | Special=$($profile.Special) | LastUseTime=$($profile.LastUseTime)"
    }

    Write-Section -Title "User Profiles" -Lines $profileLines
}
catch {
    Write-Section -Title "User Profiles" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# Endpoint protection heuristics
# ----------------------------------------------------------------------------------------------------------------------
try {
    $securityProducts = Find-SecurityProducts
    if ($securityProducts) {
        $securityProducts |
            Export-Csv -Path (Join-Path $OutputFolder "22_detected_security_products.csv") -NoTypeInformation -Encoding UTF8

        $secLines = $securityProducts | ForEach-Object {
            "$($_.Source) | $($_.Name) | $($_.Detail)"
        }
    }
    else {
        $secLines = @("No obvious endpoint protection products detected by heuristic scan.")
    }

    Write-Section -Title "Detected Endpoint Protection / Security Products" -Lines $secLines
}
catch {
    Write-Section -Title "Detected Endpoint Protection / Security Products" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# Defender state
# ----------------------------------------------------------------------------------------------------------------------
Run-CommandToFile -FilePath (Join-Path $OutputFolder "23_defender_status.txt") -ScriptBlock {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus | Format-List *
    }
    else {
        "Get-MpComputerStatus is not available on this device."
    }
}

# ----------------------------------------------------------------------------------------------------------------------
# gpresult /r
# ----------------------------------------------------------------------------------------------------------------------
Run-CommandToFile -FilePath (Join-Path $OutputFolder "24_gpresult_r.txt") -ScriptBlock {
    cmd /c 'gpresult /r'
}

# ----------------------------------------------------------------------------------------------------------------------
# Certificates
# ----------------------------------------------------------------------------------------------------------------------
Export-CertificateStore -StorePath 'Cert:\LocalMachine\My' `
    -CsvPath (Join-Path $OutputFolder "25_certificates_LocalMachine_My.csv") `
    -TxtPath (Join-Path $OutputFolder "25_certificates_LocalMachine_My.txt")

Export-CertificateStore -StorePath 'Cert:\LocalMachine\Root' `
    -CsvPath (Join-Path $OutputFolder "26_certificates_LocalMachine_Root.csv") `
    -TxtPath (Join-Path $OutputFolder "26_certificates_LocalMachine_Root.txt")

Export-CertificateStore -StorePath 'Cert:\LocalMachine\CA' `
    -CsvPath (Join-Path $OutputFolder "27_certificates_LocalMachine_CA.csv") `
    -TxtPath (Join-Path $OutputFolder "27_certificates_LocalMachine_CA.txt")

# ----------------------------------------------------------------------------------------------------------------------
# Application event logs
# ----------------------------------------------------------------------------------------------------------------------
try {
    $appEvents = Get-WinEvent -LogName Application -ErrorAction Stop

    $appEvents |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
        Export-Csv -Path (Join-Path $OutputFolder "28_ApplicationLog_AllEntries.csv") -NoTypeInformation -Encoding UTF8

    wevtutil epl Application (Join-Path $OutputFolder "28_ApplicationLog_AllEntries.evtx")

    Write-Section -Title "Application Event Log Export" -Lines @(
        "CSV: 28_ApplicationLog_AllEntries.csv"
        "EVTX: 28_ApplicationLog_AllEntries.evtx"
        "EntriesExported: $($appEvents.Count)"
    )
}
catch {
    Write-Section -Title "Application Event Log Export" -Lines @("ERROR: $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# PSP MA last 10 event log entries
# ----------------------------------------------------------------------------------------------------------------------
try {
    $pspEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'PowerSyncPro Migration Agent'
    } -ErrorAction Stop | Select-Object -First 10

    if ($pspEvents) {
        $pspEvents |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv -Path (Join-Path $OutputFolder "29_PSP_MA_Last10Events.csv") -NoTypeInformation -Encoding UTF8

        $pspEventLines = foreach ($event in $pspEvents) {
            "TimeCreated: $($event.TimeCreated)"
            "Id: $($event.Id)"
            "Level: $($event.LevelDisplayName)"
            "Provider: $($event.ProviderName)"
            "Message: $($event.Message)"
            ("-" * 80)
        }

        Write-Section -Title "Last 10 Application Events - PowerSyncPro Migration Agent" -Lines $pspEventLines
    }
    else {
        Write-Section -Title "Last 10 Application Events - PowerSyncPro Migration Agent" -Lines @("No events found for provider 'PowerSyncPro Migration Agent'.")
    }
}
catch {
    Write-Section -Title "Last 10 Application Events - PowerSyncPro Migration Agent" -Lines @("No events found or provider unavailable. $($_.Exception.Message)")
}

# ----------------------------------------------------------------------------------------------------------------------
# MDM / DeviceManagement-Enterprise-Diagnostics-Provider logs
# ----------------------------------------------------------------------------------------------------------------------
$MdmLogNames = @(
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin',
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
)

foreach ($logName in $MdmLogNames) {
    $safeName = ($logName -replace '[\\\/: ]', '_')

    try {
        $events = Get-WinEvent -LogName $logName -ErrorAction Stop

        $events |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
            Export-Csv -Path (Join-Path $OutputFolder "$safeName.csv") -NoTypeInformation -Encoding UTF8

        wevtutil epl $logName (Join-Path $OutputFolder "$safeName.evtx")

        Write-Section -Title "MDM Log Export - $logName" -Lines @(
            "CSV: $safeName.csv"
            "EVTX: $safeName.evtx"
            "EntriesExported: $($events.Count)"
        )
    }
    catch {
        Write-Section -Title "MDM Log Export - $logName" -Lines @(
            "ERROR: $($_.Exception.Message)"
        )
    }
}

# ----------------------------------------------------------------------------------------------------------------------
# Final ZIP
# ----------------------------------------------------------------------------------------------------------------------
try {
    if (Test-Path $ZipFile) {
        Remove-Item $ZipFile -Force
    }

    Compress-Archive -Path (Join-Path $OutputFolder '*') -DestinationPath $ZipFile -Force

    Write-Section -Title "ZIP Output" -Lines @(
        "ZipPath: $ZipFile"
    )
}
catch {
    Write-Section -Title "ZIP Output" -Lines @("ERROR creating ZIP: $($_.Exception.Message)")
}

Write-Host ""
Write-Host "Diagnostics collection complete." -ForegroundColor Green
Write-Host "Folder: $OutputFolder" -ForegroundColor Yellow
Write-Host "ZIP:    $ZipFile" -ForegroundColor Yellow
