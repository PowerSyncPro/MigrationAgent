<#                                                                                           
 mmmmm       mmmm              mmm   mm    mmmm    mmmmmmmm            mm    mm    mmmm    mmmmmmmm 
 ##"""##    ##""##             ###   ##   ##""##   """##"""            ##    ##  m#""""#   ##"""""" 
 ##    ##  ##    ##            ##"#  ##  ##    ##     ##               ##    ##  ##m       ##       
 ##    ##  ##    ##            ## ## ##  ##    ##     ##               ##    ##   "####m   #######  
 ##    ##  ##    ##            ##  #m##  ##    ##     ##               ##    ##       "##  ##       
 ##mmm##    ##mm##             ##   ###   ##mm##      ##               "##mm##"  #mmmmm#"  ##mmmmmm 
 """""       """"              ""   """    """"       ""                 """"     """""    """""""" 
                                                                                                    
                                                                                                    
                                                                                                    
 mmmmmmmm  mmmmmm       mm      mmmmmm   mmm   mm   mmmmmm   mmm   mm     mmmm                      
 """##"""  ##""""##    ####     ""##""   ###   ##   ""##""   ###   ##   ##""""#                     
    ##     ##    ##    ####       ##     ##"#  ##     ##     ##"#  ##  ##                           
    ##     #######    ##  ##      ##     ## ## ##     ##     ## ## ##  ##  mmmm                     
    ##     ##  "##m   ######      ##     ##  #m##     ##     ##  #m##  ##  ""##                     
    ##     ##    ##  m##  ##m   mm##mm   ##   ###   mm##mm   ##   ###   ##mmm##                     
    ""     ""    """ ""    ""   """"""   ""   """   """"""   ""   """     """"                      
                                                                                                    
                                                                                                    
                                                                                                    
   mmmm    mmm   mm  mm       mmm    mmm                                                            
  ##""##   ###   ##  ##        ##m  m##                                                             
 ##    ##  ##"#  ##  ##         ##mm##                                                              
 ##    ##  ## ## ##  ##          "##"                                                               
 ##    ##  ##  #m##  ##           ##                                                                
  ##mm##   ##   ###  ##mmmmmm     ##                                                                
   """"    ""   """  """"""""     ""                                                                
#>

#Requires -RunAsAdministrator

# Run PowerShell as Administrator


$base = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path $base -Force | Out-Null

New-ItemProperty -Path $base -Name HideFirstRunExperience -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $base -Name AutoImportAtFirstRun -PropertyType DWord -Value 4 -Force | Out-Null
New-ItemProperty -Path $base -Name DefaultBrowserSettingEnabled -PropertyType DWord -Value 0 -Force | Out-Null
New-ItemProperty -Path $base -Name DefaultBrowserSettingsCampaignEnabled -PropertyType DWord -Value 0 -Force | Out-Null

New-ItemProperty -Path $base -Name RestoreOnStartup -PropertyType DWord -Value 4 -Force | Out-Null

# Startup URLs: easiest + most robust is the numbered subkey values
$urlsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs"
New-Item -Path $urlsKey -Force | Out-Null
New-ItemProperty -Path $urlsKey -Name "1" -PropertyType String -Value "http://localhost:5000" -Force | Out-Null

New-ItemProperty -Path $base -Name ShowHomeButton -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $base -Name HomepageLocation -PropertyType String -Value "http://localhost:5000" -Force | Out-Null
New-ItemProperty -Path $base -Name HomepageIsNewTabPage -PropertyType DWord -Value 0 -Force | Out-Null

Stop-Process -Name msedge -Force -ErrorAction SilentlyContinue



# PowerShell Script to Generate RDCMan .rdg File with Encrypted Credentials
# This script creates a .rdg file for Remote Desktop Connection Manager (RDCMan)
# Credentials are hardcoded here as placeholders—replace with your actual values.
# Note: Encrypted passwords use DPAPI (CryptProtectData) and are base64-encoded, matching RDCMan's format.
# They will only work on THIS machine under THIS user account due to DPAPI being user/machine-specific.
# For a training environment that will be destroyed, this is fine, but NEVER use in production.

# Load the required assembly for ProtectedData (fixes the type not found error)
if ($PSVersionTable.PSVersion.Major -ge 6) {
    # For PowerShell 7+ (Core)
    Add-Type -Path "$PSHome\System.Security.Cryptography.ProtectedData.dll"
} else {
    # For Windows PowerShell 5
    Add-Type -AssemblyName System.Security
}

# Define the 4 credentials (username/password/domain pairs; domain can be '.' for local)
$credentials = @{
    "Cred1" = @{ UserName = "trn.user"; Password = 'IL0veP0wer$yncPr0!'; Domain = "PSPTarget.local" }
    "Cred2" = @{ UserName = "trn.user"; Password = 'IL0veP0wer$yncPr0!'; Domain = "PSPSource.local" }
    "Cred3" = @{ UserName = "trn.da"; Password = "uoYBP4IgZ7n8M#hU"; Domain = "PSPTarget.local" }
    "Cred4" = @{ UserName = "trn.da"; Password = "Oz#5VqCE5esrvIQ5"; Domain = "PSPSource.local" }
    "Cred5" = @{ UserName = "trn.local"; Password = "y9r3M%UHG3Ocd8Qc"; Domain = "." }
    "Cred6" = @{ UserName = "unknown"; Password = "unknown"; Domain = "PSPSource.local" }
}
$serverName = $env:COMPUTERNAME # Or use [System.Environment]::MachineName
# Match trailing digits
if ($serverName -match '\d+$') {
    $trailingNumber = $Matches[0]
    $randomChars=$trailingNumber
}
# Define the 6 machines with their display names, connection addresses (IP or hostname), and assigned credential keys
# Assign credentials to machines (example mapping: adjust as needed)
$machines = @(
    @{ DisplayName = "SRC$randomChars-da"; Address = "192.168.249.8"; CredKey = "Cred4" }
    @{ DisplayName = "TRG$randomChars-da"; Address = "192.168.249.9"; CredKey = "Cred3" } # Shares Cred1
    @{ DisplayName = "PSPRA$randomChars-da"; Address = "192.168.249.5"; CredKey = "Cred3" }
    @{ DisplayName = "WSTN1$randomChars-local"; Address = "192.168.249.11"; CredKey = "Cred5" }
    @{ DisplayName = "WSTN2$randomChars-local"; Address = "192.168.249.21"; CredKey = "Cred5" } # Shares Cred2
    @{ DisplayName = "WSTN1$randomChars-user-source"; Address = "192.168.249.11"; CredKey = "Cred2" }
    @{ DisplayName = "WSTN2$randomChars-user-source"; Address = "192.168.249.21"; CredKey = "Cred2" } # Shares Cred2
    @{ DisplayName = "WSTN1$randomChars-user-target"; Address = "192.168.249.11"; CredKey = "Cred1" }
    @{ DisplayName = "WSTN2$randomChars-user-target"; Address = "192.168.249.21"; CredKey = "Cred1" } # Shares Cred2
    @{ DisplayName = "WSTN1$randomChars-custom"; Address = "192.168.249.11"; CredKey = "Cred6" }
    @{ DisplayName = "WSTN2$randomChars-custom"; Address = "192.168.249.21"; CredKey = "Cred6" } # Shares Cred2
)
# Output file path for the .rdg file (change if needed)
$rdgFilePath = "C:\binaries\PSPEnvironment.rdg" # e.g., "C:\Temp\MyRDCMan.rdg"
# Function to encrypt password in RDCMan-compatible format (DPAPI + Base64)
function Encrypt-PasswordForRDCMan {
    param ([string]$PlainPassword)
    if ([string]::IsNullOrEmpty($PlainPassword)) { return "" }
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($PlainPassword)
    $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Convert]::ToBase64String($encryptedBytes)
}
# Build the XML content
$xmlContent = @'
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.7" schemaVersion="3">
  <file>
    <credentialsProfiles />
    <properties>
      <expanded>True</expanded>
      <name>My RDCMan File</name>
    </properties>
    <group>
      <properties>
        <expanded>True</expanded>
        <name>PSP-TRN-</name>
      </properties>
'@
# Add each server to the XML
foreach ($machine in $machines) {
    $displayName = $machine.DisplayName
    $address = $machine.Address
    $serverXml = @"
      <server>
        <properties>
          <comment />
          <displayName>$displayName</displayName>
          <name>$address</name>
        </properties>

"@

    if ($machine.CredKey -and $credentials.ContainsKey($machine.CredKey)) {
        $cred = $credentials[$machine.CredKey]
        $userName = $cred.UserName
        $domain = $cred.Domain
        $encryptedPassword = Encrypt-PasswordForRDCMan -PlainPassword $cred.Password
        $serverXml += @"
        <logonCredentials inherit="None">
          <profileName scope="Local">Custom</profileName>
          <userName>$userName</userName>
          <password>$encryptedPassword</password>
          <domain>$domain</domain>
        </logonCredentials>
        <remoteDesktop inherit="None">
          <sameSizeAsClientArea>True</sameSizeAsClientArea>
          <fullScreen>False</fullScreen>
          <colorDepth>24</colorDepth>
        </remoteDesktop>

"@
    }

    $serverXml += @"
      </server>
"@

    $xmlContent += $serverXml
}
# Close the group and file tags
$xmlContent += @'
    </group>
  </file>
</RDCMan>
'@
# Write the XML to the file
$xmlContent | Out-File -FilePath $rdgFilePath -Encoding utf8
Write-Output "RDG file generated at $rdgFilePath with encrypted credentials for all machines."
