#requires -version 5.1
[CmdletBinding()]
param(
    [string]$ServiceName = 'PowerSyncPro Migration Agent',
    [string]$DisplayNamePattern = 'PowerSyncPro Migration Agent',
    [string]$VendorRegistryPath = 'HKLM:\SOFTWARE\Declaration Software',
    [string]$VendorDataPath = 'C:\ProgramData\Declaration Software',
    [string]$ProvisioningPackagePattern = 'PowerSyncPro*.ppkg'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDirectory = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
$LogPath = Join-Path $LogDirectory 'Uninstall-PowerSyncProMigrationAgent.log'
$RebootRequired = $false

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-UninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $results = foreach ($path in $paths) {
        foreach ($entry in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
            $displayName = [string](Get-ObjectPropertyValue -InputObject $entry -PropertyName 'DisplayName')
            if (-not [string]::IsNullOrWhiteSpace($displayName) -and $displayName -like "*$DisplayNamePattern*") {
                $entry
            }
        }
    }

    @($results)
}

function Invoke-UninstallEntry {
    param([Parameter(Mandatory)]$Entry)

    $displayName = [string](Get-ObjectPropertyValue -InputObject $Entry -PropertyName 'DisplayName')
    $quiet = [string](Get-ObjectPropertyValue -InputObject $Entry -PropertyName 'QuietUninstallString')
    $normal = [string](Get-ObjectPropertyValue -InputObject $Entry -PropertyName 'UninstallString')
    $productCode = [string](Get-ObjectPropertyValue -InputObject $Entry -PropertyName 'PSChildName')

    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $productCode }
    Write-Log "Processing uninstall entry: $displayName"

    if ($productCode -match '^\{[0-9A-Fa-f-]{36}\}$') {
        Write-Log "Using MSI product code: $productCode"
        $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru -WindowStyle Hidden
    }
    else {
        $commandLine = if (-not [string]::IsNullOrWhiteSpace($quiet)) { $quiet } else { $normal }
        if ([string]::IsNullOrWhiteSpace($commandLine)) { throw "No uninstall command was found for '$displayName'." }
        if ($commandLine -notmatch '(?i)(/quiet|/qn|/passive|/silent|/s)(\s|$)') {
            $commandLine = "$commandLine /norestart /passive"
        }
        Write-Log "Executing uninstall command: $commandLine"
        $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d','/s','/c',"`"$commandLine`"" -Wait -PassThru -WindowStyle Hidden
    }

    Write-Log "Uninstaller exit code: $($process.ExitCode)"
    switch ($process.ExitCode) {
        0     { }
        1605  { Write-Log 'Product is already absent.' 'WARN' }
        1614  { Write-Log 'Product is already uninstalled.' 'WARN' }
        1641  { $script:RebootRequired = $true; Write-Log 'Uninstall succeeded and initiated a restart.' 'WARN' }
        3010  { $script:RebootRequired = $true; Write-Log 'Uninstall succeeded; restart required.' 'WARN' }
        default { throw "Uninstaller returned exit code $($process.ExitCode) for '$displayName'." }
    }
}

try {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    Write-Log 'Starting PowerSyncPro Migration Agent removal.'

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.Status -ne 'Stopped') {
            Write-Log "Stopping service '$ServiceName'."
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
            Write-Log 'Service stopped.' 'SUCCESS'
        }
        else { Write-Log 'Service is already stopped.' }
    }
    else { Write-Log 'Service is not present.' }

    $entries = @(Get-UninstallEntries)
    if ($entries.Count -eq 0) {
        Write-Log 'No matching uninstall entry was found. Continuing with cleanup.' 'WARN'
    }
    else {
        Write-Log "Found $($entries.Count) matching uninstall entry/entries."
        foreach ($entry in $entries) { Invoke-UninstallEntry -Entry $entry }
    }

    Start-Sleep -Seconds 3

    foreach ($path in @($VendorRegistryPath, $VendorDataPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            Write-Log "Removed leftover path: $path" 'SUCCESS'
        }
        else { Write-Log "Leftover path is already absent: $path" }
    }

    $provisioningFolder = Join-Path $env:ProgramData 'Microsoft\Provisioning'
    $packages = @(Get-ChildItem -Path $provisioningFolder -Filter $ProvisioningPackagePattern -File -ErrorAction SilentlyContinue)
    foreach ($package in $packages) {
        Remove-Item -LiteralPath $package.FullName -Force -ErrorAction Stop
        Write-Log "Removed provisioning package: $($package.FullName)" 'SUCCESS'
    }

    $remainingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $remainingEntries = @(Get-UninstallEntries)
    if (($null -ne $remainingService) -or ($remainingEntries.Count -gt 0)) {
        throw 'PowerSyncPro Migration Agent is still detectable after uninstall.'
    }

    Write-Log 'Removal completed successfully.' 'SUCCESS'
    if ($RebootRequired) { exit 3010 }
    exit 0
}
catch {
    Write-Log "Removal failed: $($_.Exception.Message)" 'ERROR'
    if (-not [string]::IsNullOrWhiteSpace($_.ScriptStackTrace)) { Write-Log $_.ScriptStackTrace 'ERROR' }
    exit 1
}
