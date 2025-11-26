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
                                                                                                    
                                                                                            
.DESCRIPTION
    The script created the PowerSyncPro Entra ID app with all permissions related to Migration Agent and Directory Syncronisation
    The script is for training only reffer to the script without -"training" in the name for the production script"
 
.PARAMETERS
    -TenantID: Accepts a tenant ID GUID (e.g. abcdef12-3456-7890-1234-56789abcdef0)
    -RedirectURI: Accepts a Redirect URL for PowerSyncPro Authentication - defaults to http://localhost:5000/redirect
#>

param(
    # Tenant ID parameter, if the user doesn't define this it will prompt for it.
    [Parameter(Mandatory = $false)]
    [string]$TenantID,

    # Set optional redirect URI, this should not be changed unless you are administering PSP from outside the local server
    [Parameter(Mandatory = $false)]
    [string]$RedirectURI = "http://localhost:5000/redirect"
)

# Define application details
$charSet = (48..57) + (65..90) + (97..122)
$randomChars = -join ($charSet | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$appName = "PowerSyncPro Training Dirsync and MA - training $randomChars"
$termsOfServiceUrl = "https://downloads.powersyncpro.com/current/Declaration-Software-End-User-License-Agreement.pdf"
$homepageurl = "https://powersyncpro.com/"
$PrivacyStatementUrl  = "https://powersyncpro.com/privacy-policy/"
$SupportUrl = "https://kb.powersyncpro.com"
$requiredPermissions = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Organization.Read.All","User.Read")

$asciiLogo="
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"


function Test-MicrosoftGraphModule {
    <#
    .SYNOPSIS
        Ensures Microsoft.Graph is installed and up to date.
    .DESCRIPTION
        Checks the installed version of Microsoft.Graph, installs if missing,
        updates if below the required version, and advises restart after update.
    .PARAMETER MinimumVersion
        The minimum version of Microsoft.Graph required (default: 2.28.0).
    .PARAMETER Scope
        Scope for installation (default: AllUsers).
    .EXAMPLE
        Test-MicrosoftGraphModule -MinimumVersion 2.28.0
    #>
    [CmdletBinding()]
    param(
        [version]$MinimumVersion = [version]"2.28.0",
        [ValidateSet("AllUsers","CurrentUser")]
        [string]$Scope = "AllUsers"
    )

    Write-Host -ForegroundColor Cyan "Checking Microsoft.Graph module (minimum required: $MinimumVersion)..."

    try {
        $installed = Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue
    } catch {
        $installed = $null
    }

    try {
        $galleryModule = Find-Module -Name Microsoft.Graph -ErrorAction Stop
        $latestVersion = $galleryModule.Version
    } catch {
        Write-Warning "Unable to query PowerShell Gallery. Proceeding with installed version only."
        $latestVersion = $null
    }

    $updatePerformed = $false

    if (-not $installed) {
        Write-Host "Microsoft.Graph not installed. Installing latest (>= $MinimumVersion)..."
        Install-Module -Name Microsoft.Graph -Scope $Scope -Force -AllowClobber -MinimumVersion $MinimumVersion
        $updatePerformed = $true
    }
    elseif ($installed.Version -lt $MinimumVersion) {
        Write-Host "Installed version $($installed.Version) is less than required $MinimumVersion. Updating..."
        Uninstall-Module -Name Microsoft.Graph -AllVersions -Force
        Install-Module -Name Microsoft.Graph -Scope $Scope -Force -AllowClobber -MinimumVersion $MinimumVersion
        $updatePerformed = $true
    }
    else {
        Write-Host "Microsoft.Graph $($installed.Version) is installed (meets requirement)."
    }

    if ($updatePerformed) {
        Write-Host "Microsoft.Graph was updated or installed. Please restart your PowerShell session to load the new version cleanly." -ForegroundColor Yellow
        exit 0
    }
}

# Start Script Logic

# Check if the Microsoft.Graph module is installed
Test-MicrosoftGraphModule -MinimumVersion "2.28.0"

# Import Required Modules
Write-Host "Importing Required Modules..."
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement

Write-Host $asciiLogo
Write-Host "You should only use this if you're a student in the powersyncpro training."
Write-Host ""
Write-Host "Use this script to create the app registration for all features in PowerSyncPro"
Write-Host "Do not close this window until you have copied the App secret which will be produced at the end."

Write-Host -ForegroundColor Cyan "Creating App registration in your tenant called '$appName'"
Write-Host "`n"

# If TenantID wasn’t provided, prompt for it
if (-not $TenantID -or [string]::IsNullOrWhiteSpace($TenantID)) {
    Write-Host -ForegroundColor Cyan "Enter the ID of the tenant you wish PowerSyncPro to connect to:"
    Write-Host -ForegroundColor Cyan "we have entered this for you."
    Write-Host -ForegroundColor Cyan ""
    Write-Host -ForegroundColor Cyan "bf94a801-31a5-43eb-a9b3-3f2bf1ad3f9e"
    Write-Host -ForegroundColor Cyan ""
    #$TenantID = Read-Host
    $tenantID = "bf94a801-31a5-43eb-a9b3-3f2bf1ad3f9e"
}

$currentgraphconnection = get-mgcontext
if($currentgraphconnection -and $currentgraphconnection.tenantid -ne $tenantID){
    Write-Host -ForegroundColor Cyan "Wrong tenant connected, disconnecting Graph"
    Disconnect-MgGraph -InformationAction SilentlyContinue
        }else{
            Write-Host -ForegroundColor Cyan "Connecting to '$tenantID'"
            Connect-MgGraph -Scopes $requiredPermissions -TenantId $tenantID -NoWelcome
}

$NewGraphConnection = get-mgcontext

#Checking to see if we have all permissions, sometimes previous sessions can persist. 
if(($requiredPermissions | Where-Object { $_ -notin @($NewGraphConnection.Scopes) }) -gt 0){Write-Output "Not all permissions were granted to Graph";exit}

#Checking if the account is federated. 
$user = Get-MgUser -UserId $NewGraphConnection.Account
$upn = $user.UserPrincipalName
$domain = $upn.Split("@")[1]
$domainConfig = Get-MgDomain -DomainId $domain

if ($domainConfig.AuthenticationType -eq "Federated") {
    Write-Host "FYI This account is federated. " -ForegroundColor Red
} else {
    Write-Host "FYI: This account is not federated."  -ForegroundColor Green
}

Write-Host "`n"
Write-Host "Whilst creating the app registration should succeed using any GA, when you create a bulk enrolement token" -ForegroundColor Green
Write-Host "(BPRT) for workstation to become Entra Joined (Cloud Native) at that point you will need to use a GA account which:" -ForegroundColor Green
Write-Host "- is not federated" -ForegroundColor Red
Write-Host "- is not password-less, and not accessed using a TAP (Temporary access pass)" -ForegroundColor Red
Write-Host "- the account is listed in 'Users may join devices to Microsoft Entra' setting in Entra, if device enrolement is restrected" -ForegroundColor Red
Write-Host "These are Microsoft requirements so are unreleated to PowerSyncPro features and functionality." -ForegroundColor Green

Write-Host -ForegroundColor Cyan "Connected to '$tenantID' with $($NewGraphConnection.Account)"

#check for Microsoft.Azure.SyncFabric
Write-Host -ForegroundColor Cyan "Verifying that Microsoft.Azure.SyncFabric exists, creating if not."
$SyncFabric=Get-MgServicePrincipal -All | Where-Object {$_.AppId -eq "00000014-0000-0000-c000-000000000000"}
if(!$SyncFabric){
    Write-Host -ForegroundColor Cyan "Adding Microsoft.Azure.SyncFabric"
    New-MgServicePrincipal -AccountEnabled:$true -AppId 00000014-0000-0000-c000-000000000000 -AppRoleAssignmentRequired:$False -DisplayName Microsoft.Azure.SyncFabric -Tags {WindowsAzureActiveDirectoryIntegratedApp}
}

$requiredResourceAccess = @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000"
        ResourceAccess = @(
            @{
                Id = "7438b122-aefc-4978-80ed-43db9fcc7715"
                Type = "Role"
            },
            @{
                Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
                Type = "Role"
            },
            @{
                Id = "dbb9058a-0e50-45d7-ae91-66909b5d4664"
                Type = "Role"
            },
            @{
                Id = "bf7b1a76-6e77-406b-b258-bf5c7720e98f"
                Type = "Role"
            },
            @{
                Id = "62a82d76-70ea-41e2-9197-370581804d09"
                Type = "Role"
            },
            @{
                Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"
                Type = "Role"
            },
            @{
                Id = "09850681-111b-4a89-9bed-3f2cae46d706"
                Type = "Role"
            },
            @{
                Id = "df021288-bdef-4463-88db-98f22de89214"
                Type = "Role"
            },
            @{
                Id = "741f803b-c850-494e-b5df-cde7c675a1ca"
                Type = "Role"
            }
        )
    },
    @{
        ResourceAppId = "00000002-0000-0ff1-ce00-000000000000"
        ResourceAccess = @(
            @{
                Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"
                Type = "Role"
            }
        )
    }

 Write-Host -ForegroundColor Cyan "Creating PowerSyncPro application '$appName'"
$app = New-MgApplication -DisplayName $appName -spa @{
    RedirectUris = @($RedirectURI)
} -Info @{
    PrivacyStatementUrl  = $PrivacyStatementUrl ;
    SupportUrl = $SupportUrl ;
    TermsOfServiceUrl  = $TermsOfServiceUrl 
} -RequiredResourceAccess $requiredResourceAccess

 Write-Host -ForegroundColor Cyan "Adding bulk enrolement self_service_device_delete permissions"

$newPermission = @{
    resourceAppId = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
    resourceAccess = @(@{
        id = "086327cd-9afe-4777-8341-b136a1866bb3"
        type = "Scope"
    })
}

$ForDeviceRegistration = Get-MgApplication -ApplicationId $app.Id

$updatedPermissions = @($ForDeviceRegistration.RequiredResourceAccess)
$updatedPermissions += $newPermission

# Update the app registration with the additional permission for bulk enrolement
# urn:ms-drs:enterpriseregistration.windows.net/self_service_device_delete
Update-MgApplication -ApplicationId $ForDeviceRegistration.Id -RequiredResourceAccess $updatedPermissions

Write-Host -ForegroundColor Cyan "Granting admin consent '$appName'"

$SP = New-MgServicePrincipal -AppId $app.AppId
$Roles = $requiredResourceAccess.ResourceAccess.id

#Get SP for Graph, granting admin consent
$TargetSP = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
foreach($Role in ($Roles | ? {$_ -ne "dc50a0fb-09a3-484d-be87-e023b12c6440"})){
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.id -PrincipalId $SP.id -ResourceId $TargetSP.id -AppRoleId $Role  -ErrorAction "stop" | Out-Null
}

#Get SP for Exchange, granting admin consent
$TargetSP = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.id -PrincipalId $SP.id -ResourceId $TargetSP.id -AppRoleId "dc50a0fb-09a3-484d-be87-e023b12c6440" -ErrorAction "stop" | Out-Null

# Generate a client secret
Write-Host -ForegroundColor Cyan "Creating secret"
$secret = Add-MgApplicationPassword -ApplicationId $ForDeviceRegistration.Id 

# Updating with ServicePrincipalLockConfiguration

$lockConfig = @{
  IsEnabled                = $true
  AllProperties            = $true
  CredentialsWithUsageSign = $true
  CredentialsWithUsageVerify = $true
  TokenEncryptionKeyId     = $true
}

Update-MgApplication -ApplicationId $ForDeviceRegistration.Id -ServicePrincipalLockConfiguration $lockConfig

# Output the Tenant ID, Client ID, and Client Secret
$tenantId = (Get-MgOrganization).Id
$clientId = $ForDeviceRegistration.AppId
$clientSecret = $secret.SecretText
Write-Host "`n"
Write-Host "---------------------------------------------------------------------------------------------------------"
Write-Host "`n"
Write-Warning "This information is unique to your tenant and anyone with it can access your tenant."
Write-Warning "If you run into issues with this script, please *DO NOT* share this information with PowerSyncPro Support."
Write-Output "`n"
Write-Output "Application name    : $appName"
Write-Output "Training Tenant ID  : bf94a801-31a5-43eb-a9b3-3f2bf1ad3f9e < use this"
Write-Output "Application ID      : $clientId"
Write-Output "Client Secret text  : $clientSecret"
Write-Output "Redirect URI        : $RedirectURI"
Write-Output "`n"
Write-Output "If creating a BPRT you must navigate the the URL $redirectUri (no other vanity name) to successfully create the token."
Write-Output "`n"
Write-Output "The script will now finish, please ensure you have saved the information above."
pause

