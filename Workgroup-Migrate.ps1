param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$ComputerName,

    [string]$FileName = "TranslationTable.json",  # Optional parameter with a default value

    [Parameter(Mandatory = $true)]
    [Guid[]]$RunbookGUIDs  # Array of GUIDs
)

$regKey = "HKLM:\SOFTWARE\Declaration Software\Migration Agent"
$maDataDirectory = "C:\ProgramData\Declaration Software\Migration Agent"
$serviceName = "PowerSyncPro Migration Agent"
$runbooksFileName = "Runbooks.json"
$asciiLogo = 

"________                .__                       __  .__               
\______ \   ____   ____ |  | _____ ____________ _/  |_|__| ____   ____  
 |    |  \_/ __ \_/ ___\|  | \__  \\_  __ \__  \\   __\  |/  _ \ /    \ 
 |_____\  \  ___/\  \___|  |__/ __ \|  | \// __ \|  | |  (  <_> )   |  \
/_______  /\___  >\___  >____(____  /__|  (____  /__| |__|\____/|___|  /
        \/     \/     \/          \/           \/                    \/ 
  _________       _____  __                                             
 /   _____/ _____/ ____\/  |___  _  _______ _______   ____              
 \_____  \ /  _ \   __\\   __\ \/ \/ /\__  \\_  __ \_/ __ \             
 /        (  <_> )  |   |  |  \     /  / __ \|  | \/\  ___/             
/_______  /\____/|__|   |__|   \/\_/  (____  /__|    \___  >            
        \/                                 \/            \/             
"

Write-Host $asciiLogo
Write-Host "Workgroup Workstation Migration"

Start-Sleep 4

if((Test-Path $FileName)){

    Write-Host "Stopping Service $serviceName"

    Stop-Service -name $serviceName

    Write-Host "Setting Registry Entries"

    # Set the values for Domain and ComputerName in the registry
    Set-ItemProperty -Path $regKey -Name "DomainName" -Value $DomainName
    Set-ItemProperty -Path $regKey -Name "ComputerName" -Value $ComputerName
    
    Write-Output "ComputerName and DomainName have been saved to the registry under $regKey"
    
    # Processing GUIDs
    Write-Output "Processing RunbookGUIDs:"
    foreach ($guid in $RunbookGUIDs) {
        $translationTableTargetFolder = Join-Path -Path $maDataDirectory -ChildPath $guid
        
        if( -not (Test-Path $translationTableTargetFolder)){
            New-Item -Path $translationTableTargetFolder -ItemType "Directory" | Out-Null
        }

        Write-Host "Copying SID Translation Table $FileName to $translationTableTargetFolder"

        Copy-Item $FileName $translationTableTargetFolder  | Out-Null
    }

    $runbookFilePath = Join-Path -Path $maDataDirectory -ChildPath $runbooksFileName
    
    Write-Host "Removing $runbookFilePath"

    Remove-Item $runbookFilePath -ErrorAction SilentlyContinue  | Out-Null

    Write-Host "Restarting Service $serviceName"

    Restart-Service -name $serviceName
}
else{
    Write-Host "$FileName not found, script cannot continue"
}

