param(
    [string]$ConfigPath = "C:\inetpub\wwwroot\web.config",

    [string[]]$AddAllowedAddresses,
    [string[]]$RemoveAllowedAddresses,

    [string]$SetFQDN,
    [switch]$GetConfig,

    [switch]$AsJson,
    [switch]$DryRun
)

# Load XML
[xml]$xml = Get-Content $ConfigPath
$ipSecurityNode = $xml.configuration.'system.webServer'.security.ipSecurity

# --- CIDR Conversion with /32 default and graceful error handling ---
function Convert-CIDRToIPMask {
    param([string]$CIDR)

    # If user entered just an IP, assume /32
    if ($CIDR -notmatch "/") { $CIDR += "/32" }

    if ($CIDR -notmatch "^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$") {
        Write-Host "Error: Invalid IP or CIDR format: $CIDR" -ForegroundColor Red
        return $null
    }

    $ipStr = $Matches[1]
    $prefix = [int]$Matches[3]

    # Validate IP octets
    $octets = $ipStr.Split('.') | ForEach-Object { [int]$_ }
    if ($octets | Where-Object { $_ -lt 0 -or $_ -gt 255 }) {
        Write-Host "Error: Invalid IP address: $ipStr" -ForegroundColor Red
        return $null
    }

    if ($prefix -lt 0 -or $prefix -gt 32) {
        Write-Host "Error: Invalid CIDR prefix length: $prefix" -ForegroundColor Red
        return $null
    }

    $maskBits = ("1" * $prefix).PadRight(32, "0")
    $maskBytes = @()
    foreach ($i in 0..3) {
        $maskBytes += [Convert]::ToInt32($maskBits.Substring($i*8,8),2)
    }
    $mask = [System.Net.IPAddress]::new($maskBytes)

    return @{
        IPAddress = $ipStr
        SubnetMask = $mask.ToString()
    }
}

# Convert subnet mask back to prefix length
function SubnetMaskToPrefix {
    param([string]$SubnetMask)
    $bytes = $SubnetMask.Split('.') | ForEach-Object { [Convert]::ToString([int]$_,2).PadLeft(8,'0') }
    $binary = ($bytes -join '')
    return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

# --- IP Management ---
function Show-AllowedIPs { $ipSecurityNode.add | ForEach-Object { @{ IPAddress = $_.ipAddress; SubnetMask = $_.subnetMask } } }

function Add-AllowedIP {
    param([string]$CIDR)
    $result = Convert-CIDRToIPMask $CIDR
    if (-not $result) { return $false }

    $IPAddress = $result.IPAddress
    $SubnetMask = $result.SubnetMask
    $prefix = SubnetMaskToPrefix $SubnetMask

    $exists = $ipSecurityNode.add | Where-Object { $_.ipAddress -eq $IPAddress -and $_.subnetMask -eq $SubnetMask }
    if (-not $exists) {
        if ($DryRun) {
            Write-Host "DryRun: Would add IP $IPAddress/$prefix" -ForegroundColor Cyan
        } else {
            $newIP = $xml.CreateElement("add")
            $newIP.SetAttribute("ipAddress", $IPAddress)
            $newIP.SetAttribute("subnetMask", $SubnetMask)
            $newIP.SetAttribute("allowed", "true")
            $ipSecurityNode.AppendChild($newIP) | Out-Null
            Write-Host "Added IP $IPAddress/$prefix" -ForegroundColor Green
        }
        return $true
    } else {
        Write-Host "IP $IPAddress/$prefix already exists" -ForegroundColor Yellow
        return $false
    }
}

function Remove-AllowedIP {
    param([string]$CIDR)
    $result = Convert-CIDRToIPMask $CIDR
    if (-not $result) { return $false }

    $IPAddress = $result.IPAddress
    $SubnetMask = $result.SubnetMask
    $prefix = SubnetMaskToPrefix $SubnetMask

    $node = $ipSecurityNode.add | Where-Object { $_.ipAddress -eq $IPAddress -and $_.subnetMask -eq $SubnetMask }
    if ($node) {
        if ($DryRun) {
            Write-Host "DryRun: Would remove IP $IPAddress/$prefix" -ForegroundColor Cyan
        } else {
            $ipSecurityNode.RemoveChild($node) | Out-Null
            Write-Host "Removed IP $IPAddress/$prefix" -ForegroundColor Green
        }
        return $true
    } else {
        Write-Host "IP $IPAddress/$prefix not found" -ForegroundColor Yellow
        return $false
    }
}

# --- FQDN Management ---
function Get-FQDN { ($xml.configuration.'system.webServer'.rewrite.outboundRules.rule | Where-Object { $_.name -eq "PowerSyncProReverseProxyOutboundRule1" }).action.value -replace 'https://([^/]+)/.*','$1' }

function Set-FQDN {
    param([string]$NewDomain)
    $rule = $xml.configuration.'system.webServer'.rewrite.outboundRules.rule | Where-Object { $_.name -eq "PowerSyncProReverseProxyOutboundRule1" }
    $oldDomain = $rule.action.value -replace 'https://([^/]+)/.*','$1'

    if ($oldDomain -ne $NewDomain) {
        if ($DryRun) {
            Write-Host "DryRun: Would update rewrite domain from $oldDomain to $NewDomain" -ForegroundColor Cyan
        } else {
            $rule.action.value = $rule.action.value -replace "https://[^/]+/", "https://$NewDomain/"
            Write-Host "Updated rewrite domain from $oldDomain to $NewDomain" -ForegroundColor Green
        }
        return $true
    } else {
        Write-Host "Rewrite domain is already $NewDomain" -ForegroundColor Yellow
        return $false
    }
}

# --- Save Config with Backup and IIS Reminder ---
function Save-Config {
    if ($DryRun) { 
        Write-Host "DryRun enabled: web.config would be updated and backed up" -ForegroundColor Cyan
        return 
    }

    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $backup = "$ConfigPath.$timestamp"
    Rename-Item -Path $ConfigPath -NewName $backup
    $xml.Save($ConfigPath)
    Write-Host "web.config updated successfully" -ForegroundColor Cyan
    Write-Host "Backup saved as $backup" -ForegroundColor DarkCyan
    Write-Host "Reminder: Restart IIS for changes to take effect:" -ForegroundColor Yellow
    Write-Host "    iisreset /noforce" -ForegroundColor Yellow
}

# --- Populate current config before any changes ---
$output = @{
    AllowedIPs = Show-AllowedIPs
    RewriteFQDN = Get-FQDN
}

# --- CLI Operations ---
$changed = $false
$ranAnyAction = $false

if ($GetConfig) { $ranAnyAction = $true }

if ($AddAllowedAddresses) { 
    foreach ($cidr in $AddAllowedAddresses) { 
        if (Add-AllowedIP -CIDR $cidr) { $changed = $true } 
    } 
    $ranAnyAction = $true 
}

if ($RemoveAllowedAddresses) { 
    foreach ($cidr in $RemoveAllowedAddresses) { 
        if (Remove-AllowedIP -CIDR $cidr) { $changed = $true } 
    } 
    $ranAnyAction = $true 
}

if ($SetFQDN) { 
    if (Set-FQDN -NewDomain $SetFQDN) { $changed = $true } 
    $ranAnyAction = $true 
}

# Refresh output after any changes
if ($changed) {
    $output.AllowedIPs = Show-AllowedIPs
    $output.RewriteFQDN = Get-FQDN
}

# Save changes
if ($changed -and -not $DryRun) { Save-Config }
elseif ($changed -and $DryRun) { Write-Host "DryRun: no changes saved" -ForegroundColor Cyan }

# Output results
if ($AsJson) {
    $output | ConvertTo-Json -Depth 3
}
else {
    Write-Host "Allowed IPs:"
    $output.AllowedIPs | ForEach-Object { 
        $prefix = SubnetMaskToPrefix $_.SubnetMask
        Write-Host "  $($_.IPAddress)/$prefix"
    }
    Write-Host "Rewrite FQDN: $($output.RewriteFQDN)"

    # Show available flags if no action was requested
    if (-not $ranAnyAction) {
        Write-Host "`nAvailable flags:" -ForegroundColor Cyan
        Write-Host "  -GetConfig               # Show current IPs and FQDN"
        Write-Host "  -AddAllowedAddresses     # Add IP(s) in CIDR or plain IP (defaults to /32)"
        Write-Host "  -RemoveAllowedAddresses  # Remove IP(s) in CIDR or plain IP"
        Write-Host "  -SetFQDN <domain>        # Set new rewrite domain"
        Write-Host "  -DryRun                  # Show what would change without modifying web.config"
        Write-Host "  -AsJson                  # Output in JSON format"
    }
}
