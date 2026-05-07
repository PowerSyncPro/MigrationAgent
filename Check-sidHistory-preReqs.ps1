<#
.DESCRIPTION
    The script detects the proper configuration of prerequisites required to migrate sidHistory with PowerSyncPro.

.NOTES
    Disclaimer:     This script is provided 'AS IS'. No warranty is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: v2.11
    Date:  4 May 2026

Overview:
    This version enhances reliability, evidence collection, and operational clarity for sidHistory migration prerequisite validation using PowerSyncPro.

.SYNOPSIS
    Retrieves and displays the current state of advanced audit policy settings for sidHistory migration prerequisites.

.RELEASE NOTES

#>

# ----------------------
# PowerShell Version Check
# ----------------------
# This must be the first executable code in the script. It uses only syntax
# that is compatible with PowerShell 2.0 and later so that the check itself
# is guaranteed to run on any host that can parse the script header.
if ($PSVersionTable.PSVersion -lt [Version]"4.0") {
    Write-Host ""
    Write-Host "ERROR: This script requires Windows PowerShell 4.0 or later." -ForegroundColor Red
    Write-Host ("       Detected PowerShell version: {0}" -f $PSVersionTable.PSVersion) -ForegroundColor Red
    Write-Host ""
    Write-Host "Please upgrade Windows PowerShell to 4.0 or later before re-running this script." -ForegroundColor Yellow
    Write-Host "Windows Management Framework 5.1 (which includes Windows PowerShell 5.1, and" -ForegroundColor Yellow
    Write-Host "satisfies the 4.0 minimum) is available from Microsoft:" -ForegroundColor Yellow
    Write-Host "  https://www.microsoft.com/download/details.aspx?id=54616" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# ----------------------
# Banner
# ----------------------

$asciiLogo=@"
 ____                        ____                   ____
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/
                                   |___/
"@
Write-Host $asciiLogo -ForegroundColor Yellow
Write-Host "This script only reads current configuration to identify that the prerequisites for sidHistory migration have been met." -ForegroundColor Cyan
Write-Host "This script does not make any changes to the environment." -ForegroundColor Cyan
Write-Host ""

# ----------------------
# Evidence Pack helpers
# ----------------------
function Get-EvidenceDir {
    $root = $PSScriptRoot
    if (-not $root) { $root = (Get-Location).Path }
    $dir = Join-Path $root "Evidence"
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    return $dir
}

function Get-ComputerFqdn {
    try { return ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName } catch { return $env:COMPUTERNAME }
}

function Export-EnvironmentSnapshot {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][string]$Context = "Unknown"
    )

    try {
        $computer = Get-ComputerFqdn
        $now      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        $domain = $null
        $forest = $null
        try { $domain = Get-ADDomain -ErrorAction Stop } catch {}
        try { $forest = Get-ADForest -ErrorAction Stop } catch {}

        $lastBoot = $null
        try { $lastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch {}

        $tcpip = $null
        $tcpipStr = ""
        try {
            $v = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "TcpipClientSupport" -ErrorAction Stop
            $tcpip = $v.TcpipClientSupport
            $tcpipStr = [string]$tcpip
        } catch {
            $tcpipStr = "NotFound"
        }

        $obj = [PSCustomObject]@{
            CapturedAt             = $now
            Context                = $Context
            ComputerName           = $computer
            DomainDnsRoot          = $(if ($domain) { $domain.DNSRoot } else { "" })
            DomainNetBIOS          = $(if ($domain) { $domain.NetBIOSName } else { "" })
            DomainDN               = $(if ($domain) { $domain.DistinguishedName } else { "" })
            PDCEmulator            = $(if ($domain) { $domain.PDCEmulator } else { "" })
            RIDMaster              = $(if ($domain) { $domain.RIDMaster } else { "" })
            InfrastructureMaster    = $(if ($domain) { $domain.InfrastructureMaster } else { "" })
            ForestName             = $(if ($forest) { $forest.Name } else { "" })
            ForestRootDomain       = $(if ($forest) { $forest.RootDomain } else { "" })
            ForestDomains          = $(if ($forest) { ($forest.Domains -join ";") } else { "" })
            ForestGlobalCatalogs    = $(if ($forest) { ($forest.GlobalCatalogs -join ";") } else { "" })
            LastBootUpTime         = $(if ($lastBoot) { $lastBoot } else { "" })
            TcpipClientSupport     = $tcpipStr
        }

        $obj | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host "Environment snapshot export: PASSED -> $Path" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Environment snapshot export: FAILED ($($_.Exception.Message))" -ForegroundColor Red
        return $false
    }
}

function Export-AuditPolicySnapshot {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )

    try {
        $raw = auditpol /get /category:* /r 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            Write-Host "Audit snapshot export: FAILED (no output from auditpol)" -ForegroundColor Red
            return $false
        }

        $rows = $raw | ConvertFrom-Csv -ErrorAction SilentlyContinue
        if (-not $rows) {
            $txtPath = [System.IO.Path]::ChangeExtension($Path, ".txt")
            (auditpol /get /category:* 2>$null) | Out-File -FilePath $txtPath -Encoding UTF8
            Write-Host "Audit snapshot export: PARTIAL (CSV parse failed). Saved TXT instead: $txtPath" -ForegroundColor Yellow
            return $true
        }

        $computer  = Get-ComputerFqdn
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        $rows | ForEach-Object {
            $_ | Add-Member -NotePropertyName ComputerName -NotePropertyValue $computer -Force
            $_ | Add-Member -NotePropertyName CapturedAt   -NotePropertyValue $timestamp -Force
            $_
        } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

        Write-Host "Audit snapshot export: PASSED -> $Path" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Audit snapshot export: FAILED ($($_.Exception.Message))" -ForegroundColor Red
        return $false
    }
}

# ----------------------
# Optional evidence export prompt
# ----------------------
function Save-EvidenceIfRequested {
    param(
        [Parameter(Mandatory=$true)][string]$Context,         # filename token: SourcePDCe / TargetPDCe / PSP
        [Parameter(Mandatory=$true)][string]$ContextDisplay,  # label used inside Export-EnvironmentSnapshot
        [bool]$IncludeAuditSnapshot = $false
    )

    $resp = Read-Host "Save test results to log files? Results will be saved to a 'sidHistoryEvidence' folder in the script directory. (Y/N, default: N)"
    if ($resp -notmatch '^(?i)y(es)?$') {
        Write-Host "Test results were not saved." -ForegroundColor Yellow
        return
    }

    $evidenceDir = Get-EvidenceDir
    $stamp       = Get-Date -Format "yyyyMMdd_HHmmss"

    if ($IncludeAuditSnapshot) {
        $auditCsvPath = Join-Path $evidenceDir ("AuditPolicySnapshot_{0}_{1}_{2}.csv" -f $Context, $env:COMPUTERNAME, $stamp)
        Export-AuditPolicySnapshot -Path $auditCsvPath | Out-Null
    }

    $envCsvPath = Join-Path $evidenceDir ("EnvironmentSnapshot_{0}_{1}_{2}.csv" -f $Context, $env:COMPUTERNAME, $stamp)
    Export-EnvironmentSnapshot -Path $envCsvPath -Context $ContextDisplay | Out-Null
}

function Show-RpcDynamicPortGuidance {
    param(
        [Parameter(Mandatory=$true)][string]$TargetFqdn
    )

    Write-Host "RPC Dynamic Port Guidance (Informational)" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Host "You tested TCP 135 (RPC Endpoint Mapper). Many RPC operations also require dynamic high ports." -ForegroundColor Yellow
    Write-Host "Typical Windows dynamic RPC range is TCP 49152-65535 (unless restricted by policy)." -ForegroundColor Yellow
    Write-Host "If firewalls exist between PSP and $TargetFqdn, ensure this range (or your restricted range) is allowed." -ForegroundColor Yellow
}

# ----------------------
# Core Helpers
# ----------------------

function Resolve-DomainServer {
    <#
      Attempts to turn a user-supplied "DOMAIN" portion from DOMAIN\Username into a suitable -Server value.
      Best effort:
        - If it looks like DNS already (contains a dot), use as-is.
        - Else try Get-ADDomain -Identity <netbios> to obtain DNSRoot.
        - Else fallback to the original value (may still work in some environments).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainToken
    )

    if ($DomainToken -match '\.') { return $DomainToken }

    try {
        $d = Get-ADDomain -Identity $DomainToken -ErrorAction Stop
        return $d.DNSRoot
    }
    catch {
        Write-Host "Warning: Could not resolve NetBIOS domain '$DomainToken' to a DNS domain. Will try using '$DomainToken' as -Server." -ForegroundColor Yellow
        return $DomainToken
    }
}

function Get-PDCeRole {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $pdcEmulator = $domain.PDCEmulator
        $currentComputer = Get-ComputerFqdn

        $passed = $currentComputer -ieq $pdcEmulator
        if ($passed) {
            Write-Host "PDCe Test: PASSED" -ForegroundColor Green
        } else {
            Write-Host "PDCe Test: FAILED" -ForegroundColor Red
            Write-Host "Current machine ($currentComputer) is not the PDC emulator ($pdcEmulator)." -ForegroundColor Red
        }
        return $passed
    }
    catch {
        Write-Host "PDCe Test: FAILED" -ForegroundColor Red
        Write-Host "Error retrieving domain information: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-LastReboot {
    try {
        (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    }
    catch {
        Write-Host "Error retrieving last reboot time: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-SourceGroupCheck {
    try {
        $netBiosName = (Get-ADDomain).NetBIOSName
        $groupName = $netBiosName + '$$$'

        # Retrieve the group and include GroupScope so we can validate it is Domain Local
        $group = Get-ADGroup `
            -Filter { Name -eq $groupName } `
            -SearchBase (Get-ADDomain).DistinguishedName `
            -SearchScope Subtree `
            -Properties GroupScope `
            -ErrorAction Stop

        if (-not $group) {
            Write-Host "Group Check: FAILED" -ForegroundColor Red
            Write-Host "Expected group $groupName was not found." -ForegroundColor Red
            return $false
        }

        # Validate the group is Domain Local
        if ($group.GroupScope -ne 'DomainLocal') {
            Write-Host "Group Check: FAILED" -ForegroundColor Red
            Write-Host "Group '$groupName' exists but is not a Domain Local group. Detected scope: '$($group.GroupScope)'." -ForegroundColor Red
            return $false
        }

        $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop

        if ($members.Count -gt 0) {
            Write-Host "Group Check: FAILED" -ForegroundColor Red
            Write-Host "Group '$groupName' has members." -ForegroundColor Red
            return $false
        }

        Write-Host "Group Check: PASSED" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Group Check: FAILED" -ForegroundColor Red
        Write-Host "Error checking group: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}


function Get-TcpipClientSupport {
    try {
        $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        $regValue = "TcpipClientSupport"

        $value = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction Stop

        if ($value.$regValue -ne 1) {
            Write-Host "TcpipClientSupport test: FAILED" -ForegroundColor Red
            Write-Host "Registry value '$regValue' is not set to 1." -ForegroundColor Red
            return $false
        }

        $lastReboot = Get-LastReboot
        if ($null -eq $lastReboot) {
            Write-Host "TcpipClientSupport test: PASSED (with warning)" -ForegroundColor Yellow
            Write-Host "Unable to retrieve last reboot time. If TcpipClientSupport was set recently, a reboot may still be required." -ForegroundColor Yellow
            return $true
        }

        $daysSinceReboot = (Get-Date) - $lastReboot
        if ($daysSinceReboot.TotalDays -gt 7) {
            Write-Host "TcpipClientSupport test: PASSED (with warning)" -ForegroundColor Yellow
            Write-Host "This server has not been rebooted in $($daysSinceReboot.TotalDays.ToString('N0')) days." -ForegroundColor Yellow
            Write-Host "If 'TcpipClientSupport' was changed recently, reboot is required for it to take effect." -ForegroundColor Yellow
            return $true
        }

        Write-Host "TcpipClientSupport test: PASSED" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "TcpipClientSupport test: FAILED" -ForegroundColor Red
        Write-Host "Error checking TcpipClientSupport: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ----------------------
# Connectivity tests
# ----------------------
function Test-Port {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][int]$Port,
        [Parameter(Mandatory=$true)][string]$Label
    )

    $originalProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $test = Test-NetConnection -ComputerName $ComputerName -Port $Port -ErrorAction Stop
        if ($test.TcpTestSucceeded) {
            Write-Host "$Label test (TCP $Port): PASSED" -ForegroundColor Green
            return $true
        } else {
            Write-Host "$Label test (TCP $Port): FAILED" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "$Label test (TCP $Port): FAILED" -ForegroundColor Red
        return $false
    }
    finally {
        $ProgressPreference = $originalProgress
    }
}

function Test-AdConnectivityProfile {
    param(
        [Parameter(Mandatory=$true)][string]$TargetFqdn
    )

    $results = [ordered]@{
        DnsPassed   = $false
        Rpc135      = $false
        Smb445      = $false
        Ldap389     = $false
        Ldaps636    = $false
        Kerberos88  = $false
    }

    # DNS
    try {
        Resolve-DnsName $TargetFqdn -ErrorAction Stop | Out-Null
        Write-Host "DNS Test: PASSED" -ForegroundColor Green
        $results.DnsPassed = $true
    } catch {
        Write-Host "DNS Test: FAILED" -ForegroundColor Red
        $results.DnsPassed = $false
    }

    # Core ports
    $results.Rpc135     = Test-Port -ComputerName $TargetFqdn -Port 135 -Label "RPC Endpoint Mapper"
    $results.Smb445     = Test-Port -ComputerName $TargetFqdn -Port 445 -Label "SMB"
    $results.Ldap389    = Test-Port -ComputerName $TargetFqdn -Port 389 -Label "LDAP"
    $results.Ldaps636   = Test-Port -ComputerName $TargetFqdn -Port 636 -Label "LDAPS"
    $results.Kerberos88 = Test-Port -ComputerName $TargetFqdn -Port 88  -Label "Kerberos"

    Show-RpcDynamicPortGuidance -TargetFqdn $TargetFqdn

    # Helpful interpretation (doesn't change pass/fail):
    if ($results.Ldaps636 -eq $false) {
        Write-Host "Note: LDAPS (636) being blocked isn't always fatal unless your environment/tooling requires LDAPS specifically." -ForegroundColor Yellow
    }

    return $results
}


function Test-PSPTGTIDHistoryConnectivity {
    param(
        [Parameter(Mandatory=$true)][string]$SourceFqdn
    )

    $rpcPassed = Test-Port -ComputerName $SourceFqdn -Port 135 -Label "RPC Endpoint Mapper"
    $smbPassed = Test-Port -ComputerName $SourceFqdn -Port 445 -Label "SMB"

    Show-RpcDynamicPortGuidance -TargetFqdn $SourceFqdn

    return @{
        RpcPassed = $rpcPassed
        SmbPassed = $smbPassed
    }
}

function Test-RpcHighPortConnectivity {
    param(
        [Parameter(Mandatory=$true)][string]$SourceFqdn,
        [int]$ProgressSeconds = 30
    )

    Write-Host "RPC High Port Test (Dynamic RPC / TCP 49152-65535)" -ForegroundColor Cyan
    Write-Host ("-" * 52) -ForegroundColor Cyan

    # Check rpcping availability
    $rpcpingCmd = Get-Command "rpcping.exe" -ErrorAction SilentlyContinue
    if (-not $rpcpingCmd) {
        Write-Host "RPC High Port Test: SKIPPED" -ForegroundColor Yellow
        Write-Host "rpcping.exe was not found in the system PATH." -ForegroundColor Yellow
        Write-Host "Ensure this server has RSAT or Windows Support Tools installed." -ForegroundColor Yellow
        return "Skipped"
    }

    Write-Host "rpcping.exe found: $($rpcpingCmd.Source)" -ForegroundColor Cyan
    Write-Host "Running 3 successive rpcping tests to $SourceFqdn ..." -ForegroundColor Cyan
    Write-Host "Each test contacts the RPC Endpoint Mapper (TCP 135) and connects via a dynamically" -ForegroundColor Cyan
    Write-Host "allocated high port - the same path used by sidHistory migration." -ForegroundColor Cyan

    $rpcpingSource = $rpcpingCmd.Source
    $allPassed     = $true

    for ($run = 1; $run -le 3; $run++) {

        $job = Start-Job -ScriptBlock {
            param($server, $exe)
            $output = & $exe -s $server -t ncacn_ip_tcp 2>&1
            [PSCustomObject]@{
                Output   = ($output | Out-String).Trim()
                ExitCode = $LASTEXITCODE
            }
        } -ArgumentList $SourceFqdn, $rpcpingSource

        # Progress bar for this run
        $barWidth = 30
        $elapsed  = 0

        while ($elapsed -lt $ProgressSeconds) {
            $done    = Wait-Job -Job $job -Timeout 1
            $elapsed++
            $filled  = [Math]::Min([int](($elapsed / $ProgressSeconds) * $barWidth), $barWidth)
            $bar     = ("#" * $filled) + ("." * ($barWidth - $filled))
            Write-Host "`r  Run $run / 3  [$bar] ${elapsed}s  " -NoNewline -ForegroundColor Cyan
            if ($done) { break }
        }

        if ($job.State -eq 'Running') {
            Write-Host "`r  Run $run / 3  [##############################] still running...  " -NoNewline -ForegroundColor Yellow
            Wait-Job -Job $job | Out-Null
        }

        Write-Host ""

        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force | Out-Null

        if ($null -eq $result) {
            Write-Host "  Run $run : FAILED  (no result received from job)" -ForegroundColor Red
            $allPassed = $false
        }
        else {
            $passed = ($result.ExitCode -eq 0) -or ($result.Output -imatch "Completed\s+\d+\s+call")
            if ($passed) {
                Write-Host ("  Run {0} : PASSED  - {1}" -f $run, $result.Output) -ForegroundColor Green
            }
            else {
                Write-Host ("  Run {0} : FAILED  - {1}" -f $run, $result.Output) -ForegroundColor Red
                $allPassed = $false
            }
        }
    }

    if ($allPassed) {
        Write-Host "RPC High Port Test: PASSED" -ForegroundColor Green
        Write-Host "All 3 rpcping runs confirmed dynamic RPC high-port connectivity to $SourceFqdn." -ForegroundColor Green
    }
    else {
        Write-Host "RPC High Port Test: FAILED" -ForegroundColor Red
        Write-Host "One or more rpcping runs failed. Verify TCP 49152-65535 is permitted from this server to $SourceFqdn." -ForegroundColor Red
    }

    return $allPassed
}

function Test-PSPsidHistoryConnectivity {
    $fqdn = Read-Host "Enter the FQDN of the Target PDCe Server:"

    # DNS test
    try {
        Resolve-DnsName $fqdn -ErrorAction Stop | Out-Null
        Write-Host "DNS Test: PASSED" -ForegroundColor Green
        $dnsPassed = $true
    } catch {
        Write-Host "DNS Test: FAILED" -ForegroundColor Red
        $dnsPassed = $false
    }

    $rpcPassed = Test-Port -ComputerName $fqdn -Port 135 -Label "RPC Endpoint Mapper"
    $smbPassed = Test-Port -ComputerName $fqdn -Port 445 -Label "SMB"

    Show-RpcDynamicPortGuidance -TargetFqdn $fqdn

    return @{
        DnsPassed = $dnsPassed
        RpcPassed = $rpcPassed
        SmbPassed = $smbPassed
    }
}

# ----------------------
# Service account permission checks
# ----------------------
function Get-SourceAccountPermissions {
    $username = Read-Host "Please type the username of the SOURCE PSP service account (DOMAIN\Username or UserPrincipalName user@domain.com), or ENTER to skip"
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "Account Permissions: SKIPPED" -ForegroundColor Yellow
        return "Skipped"
    }

    try {
        # Accept either DOMAIN\Username or user@domain.com (UPN)
        $server      = $null
        $domainToken = $null
        $user        = $null

        if ($username -match '\\') {
            # DOMAIN\Username
            $parts = $username -split '\\', 2
            if ($parts.Length -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
            }

            $domainToken = $parts[0]
            $sam         = $parts[1]
            $server      = Resolve-DomainServer -DomainToken $domainToken

            # For DOMAIN\Username, -Identity with sAMAccountName is reliable
            $user = Get-ADUser -Identity $sam -Server $server -ErrorAction Stop
        }
        elseif ($username -match '@') {
            # user@domain.com (UPN)
            $parts = $username -split '@', 2
            if ($parts.Length -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
            }

            $domainToken = $parts[1] # UPN suffix
            $server      = Resolve-DomainServer -DomainToken $domainToken

            # NOTE: -Identity does NOT reliably resolve UPN. Use a filter query instead.
            $safeUpn = $username.Replace("'", "''")
            $user = Get-ADUser -Filter "UserPrincipalName -eq '$safeUpn'" -Server $server -ErrorAction Stop

            if (-not $user) {
                throw "Cannot find an AD user with userPrincipalName '$username' on server '$server'."
            }
            if ($user.Count -gt 1) {
                throw "Multiple AD users matched userPrincipalName '$username' on server '$server'."
            }
        }
        else {
            throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
        }

        $sid = $user.SID.Value

        # Look up well-known privileged groups by SID rather than name. Group
        # sAMAccountNames may be localized in non-English domains, so name-based
        # lookups can fail. Well-known SIDs are language-independent.
        #   RID 512 = Domain Admins
        #   RID 519 = Enterprise Admins (forest root domain only)
        #   S-1-5-32-544 = BUILTIN\Administrators (fixed, not domain-scoped)
        $domainObj = Get-ADDomain -Server $server -ErrorAction Stop
        $domainSid = $domainObj.DomainSID.Value
        $wellKnownGroupSids = @(
            "$domainSid-512",
            "$domainSid-519",
            "S-1-5-32-544"
        )

        $isAdmin = $false
        foreach ($groupSid in $wellKnownGroupSids) {
            try {
                $members = Get-ADGroupMember -Identity $groupSid -Server $server -Recursive -ErrorAction Stop |
                    Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
                if ($members -contains $sid) { $isAdmin = $true; break }
            }
            catch { }
        }

        if ($isAdmin) {
            Write-Host "Account Permissions: PASSED" -ForegroundColor Green
            return "Passed"
        }

        Write-Host "Account Permissions: FAILED" -ForegroundColor Red
        return "Failed"
    }
    catch {
        Write-Host "Account Permissions: FAILED" -ForegroundColor Red
        Write-Host "Error checking account permissions: $($_.Exception.Message)" -ForegroundColor Red
        return "Failed"
    }
}
function Get-TargetAccountPermissions {
    $username = Read-Host "Please type the username of the TARGET PSP service account (DOMAIN\Username or UserPrincipalName user@domain.com), or ENTER to skip"
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "Account Permissions: SKIPPED" -ForegroundColor Yellow
        Write-Host "Service Account SAM/UPN test: SKIPPED" -ForegroundColor Yellow
        return @{ Permissions = "Skipped"; SamUpn = "Skipped" }
    }

    try {
        # Accept either DOMAIN\Username or user@domain.com (UPN)
        $server      = $null
        $domainToken = $null
        $user        = $null

        if ($username -match '\\') {
            # DOMAIN\Username
            $parts = $username -split '\\', 2
            if ($parts.Length -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
            }

            $domainToken = $parts[0]
            $sam         = $parts[1]
            $server      = Resolve-DomainServer -DomainToken $domainToken

            # For DOMAIN\Username, -Identity with sAMAccountName is reliable
            $user = Get-ADUser -Identity $sam -Server $server -ErrorAction Stop -Properties userPrincipalName
        }
        elseif ($username -match '@') {
            # user@domain.com (UPN)
            $parts = $username -split '@', 2
            if ($parts.Length -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
            }

            $domainToken = $parts[1] # UPN suffix
            $server      = Resolve-DomainServer -DomainToken $domainToken

            # NOTE: -Identity does NOT reliably resolve UPN. Use a filter query instead.
            $safeUpn = $username.Replace("'", "''")
            $user = Get-ADUser -Filter "UserPrincipalName -eq '$safeUpn'" -Server $server -ErrorAction Stop -Properties userPrincipalName

            if (-not $user) {
                throw "Cannot find an AD user with userPrincipalName '$username' on server '$server'."
            }
            if ($user.Count -gt 1) {
                throw "Multiple AD users matched userPrincipalName '$username' on server '$server'."
            }
        }
        else {
            throw "Invalid format. Expected DOMAIN\Username or user@domain.com."
        }

        # --- Service Account SAM/UPN test ---
        $upn = $user.userPrincipalName
        $upnLeft = ""
        if ($upn -match '^(.+)@') { $upnLeft = $matches[1] }

        $samUpnPassed = $user.sAMAccountName -eq $upnLeft
        if ($samUpnPassed) {
            Write-Host "Service Account SAM/UPN test: PASSED" -ForegroundColor Green
        }
        else {
            Write-Host "Service Account SAM/UPN test: FAILED" -ForegroundColor Red
            Write-Host "The sAMAccountName must match the left part of the userPrincipalName value for the service account." -ForegroundColor Red
        }

        $sid = $user.SID.Value

        # Get user's group SIDs (from the domain you queried the user from)
        $groupSids = Get-ADPrincipalGroupMembership -Identity $user -Server $server |
            Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value

        $allSids = @($sid) + $groupSids

        # Check membership in required groups in *current* target domain (where script is run).
        # Look up by well-known SID rather than name, since group sAMAccountNames may be
        # localized in non-English domains.
        #   RID 512 = Domain Admins
        #   RID 519 = Enterprise Admins (forest root domain only)
        $targetDomain    = Get-ADDomain
        $targetServer    = $targetDomain.DNSRoot
        $targetDomainSid = $targetDomain.DomainSID.Value
        $wellKnownGroupSids = @(
            "$targetDomainSid-512",
            "$targetDomainSid-519"
        )

        $isAdmin = $false
        foreach ($groupSid in $wellKnownGroupSids) {
            try {
                $members = Get-ADGroupMember -Identity $groupSid -Server $targetServer -Recursive -ErrorAction Stop |
                    Select-Object -ExpandProperty SID | Select-Object -ExpandProperty Value
                if ($members -contains $sid) { $isAdmin = $true; break }
            }
            catch { }
        }

        $permissionsPassed = $false
        if ($isAdmin) {
            Write-Host "Account Permissions: PASSED" -ForegroundColor Green
            $permissionsPassed = $true
        }
        else {
            # Check for Migrate SID History (ExtendedRight GUID) or GenericAll on the domain root ACL
            $domainDN       = (Get-ADDomain).DistinguishedName
            $sidHistoryGuid = [Guid]"ba33815a-4f93-4c76-87f3-57574bff8109"
            $acl            = Get-Acl "AD:$domainDN"

            $hasPermission = $false
            foreach ($access in $acl.Access) {
                try {
                    $identitySid = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if (-not ($allSids -contains $identitySid)) { continue }
                    if ($access.AccessControlType -ne 'Allow') { continue }

                    $hasRight =
                        (
                            (($access.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) -and
                            ($access.ObjectType -eq $sidHistoryGuid)
                        ) -or
                        (
                            (($access.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0)
                        )

                    if ($hasRight) { $hasPermission = $true; break }
                }
                catch { }
            }

            if ($hasPermission) {
                Write-Host "Account Permissions: PASSED" -ForegroundColor Green
                $permissionsPassed = $true
            }
            else {
                Write-Host "Account Permissions: FAILED" -ForegroundColor Red
            }
        }

        return @{
            Permissions = $(if ($permissionsPassed) { "Passed" } else { "Failed" })
            SamUpn      = $(if ($samUpnPassed)      { "Passed" } else { "Failed" })
        }
    }
    catch {
        Write-Host "Account Permissions: FAILED" -ForegroundColor Red
        Write-Host "Service Account SAM/UPN test: FAILED" -ForegroundColor Red
        Write-Host "Error checking account permissions: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Permissions = "Failed"; SamUpn = "Failed" }
    }
}

# ----------------------
# Audit policy checks (advanced subcategories only)
# ----------------------
function Get-ADAuditPolicies {

    $advancedSubcategories = [ordered]@{
        "Account Management" = @(
            "Application Group Management",
            "Computer Account Management",
            "Distribution Group Management",
            "Other Account Management Events",
            "Security Group Management",
            "User Account Management"
        )
        "DS Access" = @(
            "Detailed Directory Service Replication",
            "Directory Service Access",
            "Directory Service Changes",
            "Directory Service Replication"
        )
    }

    $advancedDesiredSettings = @{}
    foreach ($group in $advancedSubcategories.Keys) {
        foreach ($subcat in $advancedSubcategories[$group]) {
            if ($group -eq "Account Management") {
                $advancedDesiredSettings[$subcat] = @{ Success = "Enabled"; Failure = "Enabled" }
            } else {
                $advancedDesiredSettings[$subcat] = @{ Success = "Enabled" }
            }
        }
    }

    function Get-AuditPolicy {
        param(
            [Parameter(Mandatory=$true)][string]$Name
        )

        function Convert-InclusionToFlags {
            param([string]$InclusionSetting)

            if (-not $InclusionSetting) { return $null }
            $s = $InclusionSetting.Trim()

            switch ($s) {
                "No Auditing"         { return 0 }
                "Success"             { return 1 }
                "Failure"             { return 2 }
                "Success and Failure" { return 3 }
                default               { return $null }
            }
        }

        try {
            # Attempt 1: CSV-style report output (/r)
            $csvOutput = auditpol /get /subcategory:"$Name" /r 2>$null
            if ($LASTEXITCODE -eq 0 -and $csvOutput) {
                $data = $csvOutput | ConvertFrom-Csv -ErrorAction SilentlyContinue
                if ($data -and $data.Count -ge 1) {
                    $row = $data | Where-Object { $_."Subcategory" -eq $Name } | Select-Object -First 1
                    if (-not $row) { $row = $data | Select-Object -First 1 }

                    $inclusionStr = $row."Inclusion Setting"
                    $flags = Convert-InclusionToFlags -InclusionSetting $inclusionStr

                    if ($flags -ne $null) {
                        return @{
                            Name      = $Name
                            Success   = if (($flags -band 1) -eq 1) { "Enabled" } else { "Disabled" }
                            Failure   = if (($flags -band 2) -eq 2) { "Enabled" } else { "Disabled" }
                            Inclusion = $inclusionStr
                        }
                    }
                }
            }

            # Attempt 2: Plain text parsing fallback
            $txt = auditpol /get /subcategory:"$Name" 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $txt) { return $null }

            $line = $txt | Where-Object { $_ -match [regex]::Escape($Name) } | Select-Object -First 1
            if (-not $line) { return $null }

            $m = [regex]::Match($line, '(No Auditing|Success and Failure|Success|Failure)\s*$')
            if (-not $m.Success) { return $null }

            $inclusionStr = $m.Groups[1].Value
            $flags = Convert-InclusionToFlags -InclusionSetting $inclusionStr
            if ($flags -eq $null) { return $null }

            return @{
                Name      = $Name
                Success   = if (($flags -band 1) -eq 1) { "Enabled" } else { "Disabled" }
                Failure   = if (($flags -band 2) -eq 2) { "Enabled" } else { "Disabled" }
                Inclusion = $inclusionStr
            }
        }
        catch {
            return $null
        }
    }

    $allPassed = $true

    Write-Host "Audit Policy Configuration Status" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "Default Domain Controllers Policy | Computer Configuration | Policies | Windows Settings | Security Settings | Advanced Audit Policy Configuration | Audit Policies" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor Yellow

    foreach ($group in $advancedSubcategories.Keys) {
        Write-Host $group -ForegroundColor Yellow

        foreach ($subcat in $advancedSubcategories[$group]) {
            $policy = Get-AuditPolicy -Name $subcat

            if ($policy) {
                Write-Host "Audit $subcat" -ForegroundColor Cyan

                $desired = $advancedDesiredSettings[$subcat]

                $matchSuccess = ($policy.Success -eq $desired.Success)
                $matchFailure = $true
                if ($desired.ContainsKey('Failure')) {
                    $matchFailure = ($policy.Failure -eq $desired.Failure)
                }

                $match = $matchSuccess -and $matchFailure
                if (-not $match) { $allPassed = $false }

                $successText = "Success: $($policy.Success)"
                if ($policy.Success -eq $desired.Success) {
                    Write-Host $successText -ForegroundColor Green
                } else {
                    Write-Host "$successText (Desired: $($desired.Success))" -ForegroundColor Red
                }

                if ($desired.ContainsKey('Failure')) {
                    $failureText = "Failure: $($policy.Failure)"
                    if ($policy.Failure -eq $desired.Failure) {
                        Write-Host $failureText -ForegroundColor Green
                    } else {
                        Write-Host "$failureText (Desired: $($desired.Failure))" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Audit $subcat" -ForegroundColor Cyan
                Write-Host "Unable to retrieve policy" -ForegroundColor Red
                $allPassed = $false
            }
        }
    }

    Write-Host ("=" * 60) -ForegroundColor Green
    return $allPassed
}

# ----------------------
# Summary
# ----------------------
function Display-Summary {
    param([hashtable]$results)

    $maxLength = 0
    foreach ($key in $results.Keys) {
        if ($key.Length -gt $maxLength) { $maxLength = $key.Length }
    }
    $maxLength += 2

    $border = "+" + ("-" * ($maxLength + 8)) + "+"
    Write-Host ""
    Write-Host "Summary" -ForegroundColor Green
    Write-Host $border -ForegroundColor Green

    foreach ($key in $results.Keys) {
        $status =
            if ($results[$key] -eq "Passed") { "PASSED" }
            elseif ($results[$key] -eq "Failed") { "FAILED" }
            elseif ($results[$key] -eq "Skipped") { "SKIPPED" }
            else { if ($results[$key]) { "PASSED" } else { "FAILED" } }

        $color = if ($status -eq "PASSED") { "Green" } elseif ($status -eq "FAILED") { "Red" } else { "Yellow" }
        $paddedKey = $key.PadRight($maxLength)
        Write-Host "| $paddedKey| $status" -ForegroundColor $color
    }

    Write-Host $border -ForegroundColor Green
    Write-Host ""
}

# ----------------------
# Main menu loop
# ----------------------
do {
    Write-Host "Please select the location from which you are running this sidHistory prereq check script." -ForegroundColor Cyan
    Write-Host "NOTE: This script must be ran from all 3 locations listed below to complete the PreReq check." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1.) This script is being ran on the PSP Server or Target Remote Agent (PSP Connectivity & Network Prereq Test)"
    Write-Host "2.) This script is being ran on the TARGET PDC Emulator"
    Write-Host "3.) This script is being ran on the SOURCE PDC Emulator"
    Write-Host "4.) Exit"
    Write-Host ""
    $choice = Read-Host "Enter your choice (1-4)"

    switch ($choice) {

        "1" {
            Write-Host "PSP Server or Remote Agent tests" -ForegroundColor Green
            Write-Host ("=" * 60) -ForegroundColor Green

            $fqdn = Read-Host "Enter the FQDN of the Target PDCe Server:"
            $profile = Test-AdConnectivityProfile -TargetFqdn $fqdn

            $rpcHighPassed = Test-RpcHighPortConnectivity -SourceFqdn $fqdn

            $summaryResults = [ordered]@{
                "DNS Test"                     = $profile.DnsPassed
                "Kerberos Test (TCP 88)"        = $profile.Kerberos88
                "LDAP Test (TCP 389)"           = $profile.Ldap389
                "LDAPS Test (TCP 636)"          = $profile.Ldaps636
                "RPC Endpoint Test (TCP 135)"   = $profile.Rpc135
                "SMB Test (TCP 445)"            = $profile.Smb445
                "RPC High Port Test"            = $rpcHighPassed
            }

            Display-Summary -results $summaryResults
            Save-EvidenceIfRequested -Context "PSP" -ContextDisplay "PSP Server/Remote Agent"
        }

        "2" {
            Write-Host "Target PDCe tests" -ForegroundColor Green
            Write-Host ("=" * 60) -ForegroundColor Green
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            $pdcPassed    = Get-PDCeRole
            $sourceFqdn   = Read-Host "Enter the FQDN of the SOURCE PDC Emulator"
            $connectivity = Test-PSPTGTIDHistoryConnectivity -SourceFqdn $sourceFqdn
            $rpcPassed    = $connectivity.RpcPassed
            $smbPassed    = $connectivity.SmbPassed

            $rpcHighPassed = Test-RpcHighPortConnectivity -SourceFqdn $sourceFqdn

            $accountResults     = Get-TargetAccountPermissions
            $accountPermissions = $accountResults.Permissions
            $samUpn             = $accountResults.SamUpn

            Write-Host ("=" * 60) -ForegroundColor Green
            $auditPassed = Get-ADAuditPolicies

            $summaryResults = [ordered]@{
                "PDCe Test"                    = $pdcPassed
                "RPC Endpoint Test (TCP 135)"   = $rpcPassed
                "SMB Test (TCP 445)"            = $smbPassed
                "RPC High Port Test"            = $rpcHighPassed
                "Account Permissions"           = $accountPermissions
                "Service Account SAM/UPN test"  = $samUpn
                "Audit Policy Test"             = $auditPassed
            }

            Display-Summary -results $summaryResults
            Save-EvidenceIfRequested -Context "TargetPDCe" -ContextDisplay "Target PDCe" -IncludeAuditSnapshot:$true
        }

        "3" {
            Write-Host "Source PDCe tests" -ForegroundColor Green
            Write-Host ("=" * 60) -ForegroundColor Green
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            $pdcPassed          = Get-PDCeRole
            $groupPassed        = Get-SourceGroupCheck
            $tcpipPassed        = Get-TcpipClientSupport
            $accountPermissions = Get-SourceAccountPermissions
            $auditPassed        = Get-ADAuditPolicies

            $summaryResults = [ordered]@{
                "Group Check"                  = $groupPassed
                "Account Permissions"          = $accountPermissions
                "Audit Policy Test"            = $auditPassed
                "PDCe Test"                    = $pdcPassed
                "TcpipClientSupport Test"      = $tcpipPassed
            }

            Display-Summary -results $summaryResults
            Save-EvidenceIfRequested -Context "SourcePDCe" -ContextDisplay "Source PDCe" -IncludeAuditSnapshot:$true
        }

        "4" {
            Write-Host "Exiting script." -ForegroundColor Cyan
        }

        default {
            Write-Host "Invalid choice. Please enter 1, 2, 3, or 4." -ForegroundColor Red
            Write-Host ""
        }
    }

} while ($choice -ne "4")
