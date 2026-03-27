# ================================================
# INTERACTIVE PASSWORD RESET for StudentsTraining AU
# Only shows users the app is allowed to reset
#
# Actions performed:
#   1. Get user members directly from the AU
#   2. Sort users alphabetically
#   3. Reset password in Entra ID
#   4. Reset password in PSPSource.local
#   5. Reset password in PSPTarget.local if account exists
#
# DC selection logic:
#   If local hostname is PSP-TRN-PSP12.psptarget.local
#   then:
#     source DC = PSP-TRN-SRC12.pspsource.local
#     target DC = PSP-TRN-TRG12.psptarget.local
# ================================================

Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module ActiveDirectory

# =========================================================
# GRAPH APP DETAILS
# =========================================================
$tenantId     = "bf94a801-31a5-43eb-a9b3-3f2bf1ad3f9e"
$appId        = "06c463bc-0ed2-4e8b-9fc6-ce6e989e44cc"
$clientSecret = ""

# =========================================================
# ADMINISTRATIVE UNIT
# =========================================================
$auDisplayName = "StudentsTraining-PasswordReset-OnlyUsers"

# =========================================================
# AD DOMAIN / UPN SETTINGS
# =========================================================
$sourceUpnSuffix = "@pspsource.local"
$targetUpnSuffix = "@psptarget.local"

# =========================================================
# AD SERVICE ACCOUNT CREDENTIALS
# Replace these with the actual accounts that can reset
# passwords in each domain.
#
# If you have issues with DOMAIN\user format, try UPN format:
#   svc-passwordreset@pspsource.local
#   svc-passwordreset@psptarget.local
# =========================================================

# --- PSPSource.local account ---
$sourceAdUsername = "trn.da@pspsource.local"
$sourceAdPassword = "Oz#5VqCE5esrvIQ5"

# --- PSPTarget.local account ---
$targetAdUsername = "trn.da@psptarget.local"
$targetAdPassword = "uoYBP4IgZ7n8M#hU"

# =========================================================
# OPTIONAL PASSWORD SETTINGS
# =========================================================
$minimumPasswordLength = 8
$forceChangeAtNextSignIn = $false

# =========================================================
# HELPER: GET LOCAL FQDN
# =========================================================
function Get-LocalFqdn {
    try {
        $hostName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().HostName
        $domainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

        if (-not [string]::IsNullOrWhiteSpace($domainName)) {
            return "$hostName.$domainName"
        }

        return $env:COMPUTERNAME
    }
    catch {
        return $env:COMPUTERNAME
    }
}

# =========================================================
# HELPER: DERIVE SOURCE/TARGET DCs FROM LOCAL HOSTNAME
# Expected host pattern:
#   PSP-TRN-PSP12
#   PSP-TRN-SRC12
#   PSP-TRN-TRG12
#
# Derived:
#   PSP-TRN-SRC12.pspsource.local
#   PSP-TRN-TRG12.psptarget.local
# =========================================================
function Get-DcNamesFromHost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalFqdn
    )

    $shortName = ($LocalFqdn -split '\.')[0].ToUpper()

    if ($shortName -notmatch '^PSP-TRN-(?:PSP|SRC|TRG)(\d+)$') {
        throw "Unable to derive DC names from hostname '$shortName'. Expected pattern like PSP-TRN-PSP12."
    }

    $siteNumber = $Matches[1]

    [PSCustomObject]@{
        SiteNumber = $siteNumber
        SourceDC   = "PSP-TRN-SRC$siteNumber.pspsource.local"
        TargetDC   = "PSP-TRN-TRG$siteNumber.psptarget.local"
    }
}

# =========================================================
# HELPER: RESET AD PASSWORD BY UPN
# =========================================================
function Reset-AdPasswordByUpn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [securestring]$NewPassword,

        [Parameter(Mandatory = $false)]
        [bool]$AccountMayNotExist = $false
    )

    try {
        $adUser = Get-ADUser `
            -Server $Server `
            -Credential $Credential `
            -Filter "UserPrincipalName -eq '$UserPrincipalName'" `
            -Properties UserPrincipalName,  SamAccountName `
            -ErrorAction Stop

        if (-not $adUser) {
            if ($AccountMayNotExist) {
                Write-Host "Account not found on $Server, skipping: $UserPrincipalName" -ForegroundColor Yellow
                return
            }
            else {
                Write-Host "Account not found on $Server : $UserPrincipalName" -ForegroundColor Red
                return
            }
        }

        Set-ADAccountPassword `
            -Identity $adUser `
            -Server $Server `
            -Credential $Credential `
            -Reset `
            -NewPassword $NewPassword `
            -ErrorAction Stop

        Unlock-ADAccount `
            -Identity $adUser `
            -Server $Server `
            -Credential $Credential `
            -ErrorAction SilentlyContinue

        Write-Host "[$Server] Password reset:" -ForegroundColor Green
        Write-Host "  UPN    : $UserPrincipalName"
        Write-Host "  SAM    : $($adUser.SamAccountName)"
    }
    catch {
        if ($AccountMayNotExist) {
            Write-Host "Could not reset or account not found on $Server for $UserPrincipalName : $($_.Exception.Message)" -ForegroundColor Yellow
        }
        else {
            Write-Host "Failed to reset account on $Server for $UserPrincipalName : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# =========================================================
# BUILD GRAPH CREDENTIAL
# =========================================================
$secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$graphCred = New-Object System.Management.Automation.PSCredential ($appId, $secureSecret)

# =========================================================
# BUILD AD CREDENTIALS
# =========================================================
$sourceAdSecurePassword = ConvertTo-SecureString $sourceAdPassword -AsPlainText -Force
$sourceAdCred = New-Object System.Management.Automation.PSCredential ($sourceAdUsername, $sourceAdSecurePassword)

$targetAdSecurePassword = ConvertTo-SecureString $targetAdPassword -AsPlainText -Force
$targetAdCred = New-Object System.Management.Automation.PSCredential ($targetAdUsername, $targetAdSecurePassword)

# =========================================================
# WORK OUT EXACT DCS FROM LOCAL HOSTNAME
# =========================================================
try {
    $localFqdn = Get-LocalFqdn
    $dcInfo = Get-DcNamesFromHost -LocalFqdn $localFqdn

    $sourceAdServer = $dcInfo.SourceDC
    $targetAdServer = $dcInfo.TargetDC

    Write-Host "Local host detected as: $localFqdn" -ForegroundColor Cyan
    Write-Host "Using source DC: $sourceAdServer" -ForegroundColor Cyan
    Write-Host "Using target DC: $targetAdServer" -ForegroundColor Cyan
}
catch {
    Write-Host "Failed to derive DC names: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# =========================================================
# CONNECT TO GRAPH
# =========================================================
try {
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $graphCred -NoWelcome -ErrorAction Stop
    Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
}
catch {
    Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# =========================================================
# FIND THE ADMINISTRATIVE UNIT
# =========================================================
try {
    $au = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$auDisplayName'" -All -ErrorAction Stop | Select-Object -First 1
}
catch {
    Write-Host "Failed to retrieve Administrative Unit: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

if (-not $au) {
    Write-Host "Error: Administrative Unit '$auDisplayName' not found." -ForegroundColor Red
    exit
}

$auId = $au.Id
Write-Host "Using AU: $auDisplayName ($auId)" -ForegroundColor Cyan

# =========================================================
# GET USER MEMBERS DIRECTLY
# This removes the need for the separate resolve loop
# =========================================================
try {
    $members = Get-MgDirectoryAdministrativeUnitMemberAsUser `
        -AdministrativeUnitId $auId `
        -All `
        -Property Id,DisplayName,UserPrincipalName `
        -ErrorAction Stop
}
catch {
    Write-Host "Failed to retrieve AU user members: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

if (-not $members -or $members.Count -eq 0) {
    Write-Host "No user members found in the AU." -ForegroundColor Yellow
    exit
}

# Keep only entries with a UPN
$members = $members |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName) } |
    Select-Object Id, DisplayName, UserPrincipalName

if (-not $members -or $members.Count -eq 0) {
    Write-Host "No AU users with UserPrincipalName were returned." -ForegroundColor Yellow
    exit
}

# =========================================================
# SORT ALPHABETICALLY
# =========================================================
$members = $members | Sort-Object DisplayName, UserPrincipalName

# =========================================================
# DISPLAY NUMBERED LIST
# =========================================================
Write-Host ""
Write-Host "Users you are allowed to reset password for:" -ForegroundColor Green
Write-Host "---------------------------------------------------"

for ($i = 0; $i -lt $members.Count; $i++) {
    $displayIndex = $i + 1
    Write-Host "$displayIndex) $($members[$i].DisplayName)  ($($members[$i].UserPrincipalName))"
}

Write-Host "---------------------------------------------------"

# =========================================================
# USER SELECTION
# =========================================================
$choice = Read-Host "`nEnter number (1-$($members.Count)) to select user"

if (-not ($choice -match '^\d+$') -or [int]$choice -lt 1 -or [int]$choice -gt $members.Count) {
    Write-Host "Invalid selection." -ForegroundColor Red
    exit
}

$selectedUser = $members[[int]$choice - 1]
$targetUPN = $selectedUser.UserPrincipalName

Write-Host "`nSelected: $($selectedUser.DisplayName) ($targetUPN)" -ForegroundColor Cyan

# =========================================================
# PROMPT FOR NEW PASSWORD
# =========================================================
$securePassword = Read-Host "Enter new temporary password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)

try {
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    if ([string]::IsNullOrWhiteSpace($plainPassword) -or $plainPassword.Length -lt $minimumPasswordLength) {
        Write-Host "Password should be at least $minimumPasswordLength characters." -ForegroundColor Red
        exit
    }

    # =====================================================
    # RESET IN ENTRA ID
    # =====================================================
    try {
        $passwordProfile = @{
            Password                      = $plainPassword
            ForceChangePasswordNextSignIn = $forceChangeAtNextSignIn
        }

        Update-MgUser -UserId $targetUPN -PasswordProfile $passwordProfile -ErrorAction Stop
        Write-Host "`nEntra ID password reset successful for $targetUPN" -ForegroundColor Green


        $file = "C:\binaries\PSPEnvironment.rdg"

        $oldLine = '<replacewithUPN>'          # exact match
        $newLine = $targetUPN    # new value

        $content = Get-Content $file -Raw

        if ($content -match [regex]::Escape($oldLine)) {
            $content -replace [regex]::Escape($oldLine), $newLine |
                Set-Content $file -Force -Encoding UTF8

        Write-Host "Successfully replaced UPN in RDG $file with $targetUPN, close and re-open your RDP without saving for it to reflect" -ForegroundColor Green
        }
            else {
               Write-Host "Warning: Could not find the exact string '$oldLine' in the file." -ForegroundColor Yellow
            }


    }
    catch {
        Write-Host "`nFailed to reset Entra ID password for $targetUPN : $($_.Exception.Message)" -ForegroundColor Red
        exit
    }

    # =====================================================
    # BUILD MATCHING SOURCE/TARGET UPNs
    # =====================================================
    $sourceUPN   = ($targetUPN -replace '@.*$', $sourceUpnSuffix)
    $targetAdUPN = ($targetUPN -replace '@.*$', $targetUpnSuffix)

    $adNewPassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    # =====================================================
    # RESET IN PSPSource.local
    # =====================================================
    Reset-AdPasswordByUpn `
        -Server $sourceAdServer `
        -Credential $sourceAdCred `
        -UserPrincipalName $sourceUPN `
        -NewPassword $adNewPassword `
        -AccountMayNotExist $false

    # =====================================================
    # RESET IN PSPTarget.local
    # =====================================================
    Reset-AdPasswordByUpn `
        -Server $targetAdServer `
        -Credential $targetAdCred `
        -UserPrincipalName $targetAdUPN `
        -NewPassword $adNewPassword `
        -AccountMayNotExist $true

    Write-Host "`nCompleted." -ForegroundColor Cyan

    if ($forceChangeAtNextSignIn) {
        Write-Host "User must change password at next sign-in." -ForegroundColor Yellow
    }
    else {
        Write-Host "User is not forced to change password at next sign-in." -ForegroundColor Yellow
    }
}
finally {
    if ($BSTR -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}
