

# 1. Connect to Microsoft Graph
#    - This assumes you have the Microsoft.Graph.Users module installed.
Connect-MgGraph -Scopes "User.Read.All"

#Function to convert the azure IDs into SID for the workstation
function Convert-AzureAdObjectIdToSid {
    param (
        [string]$ObjectId
    )
    $bytes = [Guid]::Parse($ObjectId).ToByteArray()
    $array = New-Object 'UInt32[]' 4
    [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
    $sid = "S-1-12-1-$array".Replace(' ', '-')
    return $sid
}

# 2. Fetch all users whose onPremisesSecurityIdentifier is not null
$usersWithSid = Get-MgUser -All `
    -Property "onPremisesSecurityIdentifier","id" `
  | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null } | select onPremisesSecurityIdentifier,@{name='EntraSID';Expression={Convert-AzureAdObjectIdToSid -ObjectId $_.id}}

# 3. Build a hashtable mapping:  onPrem SID  →  Azure AD user ID (GUID)
$mapping = @{}
foreach ($u in $usersWithSid) {
    $mapping[$u.OnPremisesSecurityIdentifier] = $u.EntraSID
}

# 4. Convert that hashtable to JSON text, with no extra whitespace
$jsonPayload = $mapping | ConvertTo-Json -Depth 1

# 5. Export table
Set-Content -Path "TranslationTable.json" -Value $jsonPayload



