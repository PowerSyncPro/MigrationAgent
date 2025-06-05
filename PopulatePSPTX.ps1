# This is a demonstration/test script and should not be used for production.

$DateCollected = $((get-date -Format "yyyy/MM/dd hh:mm").tostring().replace('/','-').replace(':','-').replace(' ','-'))
Start-Transcript $ENV:TEMP\PreScriptPopulateTX$($DateCollected).log -Append

$RunbookGUID="70870C66-040D-4C2E-218B-08DDA41E96EC" # Put your own runbook ID here.
$maDataDirectory = "C:\ProgramData\Declaration Software\Migration Agent"
$FileName = "TranslationTable.json"
$translationTableTargetFolder = Join-Path -Path $maDataDirectory -ChildPath $RunbookGUID

if( -not (Test-Path $translationTableTargetFolder -ErrorAction SilentlyContinue)){
   New-Item -Path $translationTableTargetFolder -ItemType "Directory"  -ErrorAction SilentlyContinue | Out-Null
   Write-Host "Created: $translationTableTargetFolder"
}

$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$backupFile = "$FileName.$timestamp.bak"
$originalfile = "$translationTableTargetFolder\$FileName"
if(Test-Path $originalfile -ErrorAction SilentlyContinue){
       Copy-Item -Path $originalfile -Destination "$translationTableTargetFolder\$backupFile" -ErrorAction Stop
       Write-Host "Backup created: $backupFile"
}else{
       Write-Host "No $originalfile found for backup"
       }

Copy-Item ".\$FileName" $translationTableTargetFolder
Write-Host "Copied new: $FileName"

Stop-Transcript
