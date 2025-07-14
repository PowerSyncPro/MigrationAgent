<#
.DESCRIPTION
    The script finds devices in Entra which have been registered with the BPRT, finds the associated device in InTune and updates the owner of the Ebtra device with the InTune owner.
    You will need to update the $BPRTuserUpn with your bulk enrolement user UPN.
 
.NOTES
    Date            July/2025
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script. This is a demonstration/test script and should not be used for production.
    Version: 1.0
    Updated: 14th July 2025 Created script
#>


# ─── CONFIG ──────────────────────────────────────────────────────────────
# The PSP BPRT account which registered devices:
# Note: this may need to be updated if your BPRT token expires in the PSP console.
$BPRTuserUpn = "<UPN here>"

# ─── PREREQS ─────────────────────────────────────────────────────────────
# Install and import the Graph SDK if you haven't already:
#   Install-Module Microsoft.Graph -Scope CurrentUser
#   Import-Module Microsoft.Graph
# Import the identity/directory module for the DeviceRegisteredOwner cmdlet:
#   Import-Module Microsoft.Graph.Identity.DirectoryManagement


# ─── CONNECT ─────────────────────────────────────────────────────────────
$scopes = @(
    "Device.ReadWrite.All",               # to modify AAD devices
    "Directory.ReadWrite.All",            # to add owners (directoryObjects)
    "DeviceManagementManagedDevices.Read.All",  # to read Intune device info
    "Directory.AccessAsUser.All"          # to add owners (directoryObjects)    
)

Connect-MgGraph -Scopes $scopes

# ─── PULL AAD/ENTRA DEVICES ─────────────────────────────────────────────
$regDevices = Get-MgUserRegisteredDevice -UserId $BPRTuserUpn -All |
    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.device' }

Write-Host "Devices with BPRT of '$($BPRTuserUpn)' found = $(@($regDevices).count)" -ForegroundColor Cyan

# ─── LOOP & SYNC OWNERSHIP ────────────────────────────────────────────────
foreach ($dev in $regDevices) {
    # extract raw values from AdditionalProperties
    $deviceId   = $dev.AdditionalProperties['deviceId']
    $deviceName = $dev.AdditionalProperties['displayName']

    Write-Host "Processing AAD device '$deviceName' (ID: $deviceId)" -ForegroundColor Cyan

    # 1) Find the matching Intune managedDevice by AzureAdDeviceId
    $md = Get-MgDeviceManagementManagedDevice -Filter "AzureAdDeviceId eq '$($deviceId)'" -All

    if (-not $md) {
        Write-Warning "No Intune device found matching '$deviceName'"
        continue
    }

    # 2) Ensure the Intune device has a user assigned
    if (-not $md.UserId) {
        Write-Warning "Intune device has no user assigned; skipping"
        continue
    }

    Write-Host "Found Intune owner: $($md.UserPrincipalName) ($($md.UserId))"       

        # 3) Remove existing owner(s)
    $CurrentOwner = Get-MgDeviceRegisteredOwner -DeviceId $dev.id
    foreach ($owner in $CurrentOwner) {
        Remove-MgDeviceRegisteredOwnerByRef -DeviceId $dev.id -DirectoryObjectId $Owner.id
        Write-Host "Removed existing owner owner '$($Owner.id)' of '$deviceName'" -ForegroundColor Green
    }
  
    # 4) Add the owner reference on the AAD device
    try {
        New-MgDeviceRegisteredOwnerByRef -DeviceId $dev.id -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$($md.UserId)"
        Write-Host "Assigned $($md.UserPrincipalName) as owner of '$deviceName'" -ForegroundColor Green
    }
    catch {
        # ignore "already exists" errors
        if ($_.Exception.Message -match 'Another reference already exists') {
            Write-Host "Owner already assigned, skipping"
        }
        else {
            Write-Error "Failed to add owner: $($_.Exception.Message)"
        }
    }
}

# ─── CLEAN UP ─────────────────────────────────────────────────────────────
#Commented out for testing
#Disconnect-MgGraph
