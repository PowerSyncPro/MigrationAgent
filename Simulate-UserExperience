# Path to your JSON file
$runbooksPath = 'C:\ProgramData\Declaration Software\Migration Agent\runbooks.json'

# 1) Check that the JSON file exists
if (-not (Test-Path $runbooksPath)) {
    Write-Error "Runbooks file not found at path: $runbooksPath"
    exit 1
}

# 2) Read & parse JSON
try {
    $json = Get-Content -Raw $runbooksPath | ConvertFrom-Json
}
catch {
    Write-Error "Failed to parse JSON. Please check file integrity."
    exit 1
}

# 3) Extract GUIDs and their display names, forcing to an array
$entries = @(
    $json.PSObject.Properties |
      ForEach-Object {
        [PSCustomObject]@{
            Guid = $_.Name
            Name = $_.Value.name
        }
      }
)

# 4) Ensure we actually got some runbooks
if ($entries.Count -eq 0) {
    Write-Error "No runbook GUIDs found in JSON."
    exit 1
}

# 5) If only one runbook, auto-select it
if ($entries.Count -eq 1) {
    $chosen     = $entries[0]
    $chosenGuid = $chosen.Guid
    $chosenName = $chosen.Name
    Write-Host "Only one runbook found. Using:`n  $chosenGuid - $chosenName"
}
else {
    # Select Runbook from list
    Write-Host 'Available Runbooks:'
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $n = $i + 1
        $e = $entries[$i]
        Write-Host " [$n] $($e.Guid) - $($e.Name)"
    }

    $sel = Read-Host 'Enter the number of the runbook you want'
    if (-not ([int]::TryParse($sel, [ref]$null)) -or [int]$sel -lt 1 -or [int]$sel -gt $entries.Count) {
        Write-Error 'Invalid selection.'
        exit 1
    }

    $chosen     = $entries[[int]$sel - 1]
    $chosenGuid = $chosen.Guid
    $chosenName = $chosen.Name
}

# Define actions (plus Exit)
$actions = @(
    'runbook-available-notification'
    'migration-start-warning'
    'migration-in-progress'
    'runbook-completion-notification'
    'service-unavailable-notification'
    'cache-creds'
    'Exit'
)

# Loop until Exit
while ($true) {
    Write-Host ''
    Write-Host "Actions for '$chosenName':"
    for ($j = 0; $j -lt $actions.Count; $j++) {
        $m = $j + 1
        Write-Host " [$m] $($actions[$j])"
    }

    $actSel = Read-Host 'Enter the number of the action to invoke'
    if (-not ([int]::TryParse($actSel, [ref]$null)) -or [int]$actSel -lt 1 -or [int]$actSel -gt $actions.Count) {
        Write-Warning 'Invalid selection; please choose a valid number.'
        continue
    }

    $chosenAction = $actions[[int]$actSel - 1]
    if ($chosenAction -eq 'Exit') {
        Write-Host 'Exiting. Goodbye!'
        break
    }

    # Build and run the command
    $exePath   = 'C:\Program Files\Declaration Software\PSP MA\DeclarationSoftware.PowerSyncPro.MigrationAgent.exe'
    $arguments = "-$chosenAction", $chosenGuid
    $cmdString = "$exePath $($arguments -join ' ')"

    Write-Host ''
    Write-Host 'Running:'
    Write-Host "  $cmdString"

    & $exePath @arguments

    if ($LASTEXITCODE -eq 0) {
        Write-Host 'Completed successfully.'
    }
    else {
        Write-Warning "Process exited with code $LASTEXITCODE."
    }

    # Special pause-and-kill behavior for migration-in-progress
    if ($chosenAction -eq 'migration-in-progress') {
        Write-Host ''
        Write-Host 'Migration is in progress. Press Enter to terminate the agent process...'
        Read-Host
        Write-Host 'Terminating MigrationAgent process...'
        Stop-Process -Name 'DeclarationSoftware.PowerSyncPro.MigrationAgent' -Force -ErrorAction SilentlyContinue
        Write-Host 'Process terminated.'
    }
}
