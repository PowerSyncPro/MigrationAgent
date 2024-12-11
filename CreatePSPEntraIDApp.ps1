<#
.DESCRIPTION
    The script created the PowerSyncPro Entra ID app with all permissions related to Migration Agent and Directory Syncronisation
 
.NOTES
    Date            November/2024
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 1.0
#>

# Define application details

$appName = "PowerSyncPro Dirsync and Migration Agent"

# Check if the Microsoft.Graph module is installed
Write-Host -ForegroundColor Cyan "Checking that Microsoft.Graph is installed"
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Output "Microsoft.Graph module is not installed. Installing now..."
    try {
        # Install the Microsoft.Graph module
        Install-Module -Name Microsoft.Graph -Scope AllUsers -Force -AllowClobber
        Write-Output "Microsoft.Graph module installed successfully."
    } catch {
        Write-Output "An error occurred during installation: $_"
        exit
    }
} else {
    Write-Output "Microsoft.Graph module is already installed."
}

Write-Host -ForegroundColor Cyan "Creating App registration in your tenant called '$appName'"
Write-Host "`n"
Write-Host -ForegroundColor Cyan "First, enter the ID of the tennat you wish PowerSyncPro to connect to:"
$tenantID = Read-Host

$redirectUri = "http://localhost:5000/redirect"
$termsOfServiceUrl = "https://downloads.powersyncpro.com/current/Declaration-Software-End-User-License-Agreement.pdf"
$homepageurl = "https://powersyncpro.com/"
$PrivacyStatementUrl  = "https://powersyncpro.com/privacy-policy/"
$SupportUrl = "https://kb.powersyncpro.com"
$requiredPermissions = @("Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Organization.Read.All")

$currentgraphconnection = get-mgcontext
if($currentgraphconnection -and $currentgraphconnection.tenantid -ne $tenantID){
    Write-Host -ForegroundColor Cyan "Wrong tenant connected, disconnecting Graph"
    Disconnect-MgGraph -InformationAction SilentlyContinue
        }else{
            Write-Host -ForegroundColor Cyan "Connecting to '$tenantID'"
            Connect-MgGraph -Scopes $requiredPermissions -TenantId $tenantID -NoWelcome
}

$NewGraphConnection = get-mgcontext

if(($requiredPermissions | Where-Object { $_ -notin @($NewGraphConnection.Scopes) }) -gt 0){Write-Output "Not all permissions were granted to Graph";exit}

Write-Host -ForegroundColor Cyan "Connected to '$tenantID' with $($NewGraphConnection.Account)"

#check for Microsoft.Azure.SyncFabric
$SyncFabric=Get-MgServicePrincipal | Where-Object {$_.AppId -eq "00000014-0000-0000-c000-000000000000"}
if(!$SyncFabric){
    Write-Host -ForegroundColor Cyan "Adding Microsoft.Azure.SyncFabric"
    New-MgServicePrincipal -AccountEnabled:$true -AppId 00000014-0000-0000-c000-000000000000 -AppRoleAssignmentRequired:$False -DisplayName Microsoft.Azure.SyncFabric -Tags {WindowsAzureActiveDirectoryIntegratedApp}
}

$requiredResourceAccess = @(
    @{
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
)

 Write-Host -ForegroundColor Cyan "Creating application '$appName'"
$app = New-MgApplication -DisplayName $appName -spa @{
    RedirectUris = @($redirectUri)
} -Info @{
    PrivacyStatementUrl  = $PrivacyStatementUrl ;
    SupportUrl = $SupportUrl ;
    TermsOfServiceUrl  = $TermsOfServiceUrl 
} -RequiredResourceAccess $requiredResourceAccess

 Write-Host -ForegroundColor Cyan "Adding additional permissions"

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

# Output the Tenant ID, Client ID, and Client Secret
$tenantId = (Get-MgOrganization).Id
$clientId = $ForDeviceRegistration.AppId
$clientSecret = $secret.SecretText

Write-Output "`n"
Write-Output "Application name  : $appName"
Write-Output "Tenant ID         : $tenantId"
Write-Output "Application ID    : $clientId"
Write-Output "Client Secret text: $clientSecret"
Write-Output "`n"
