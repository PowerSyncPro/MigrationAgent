<#
.SYNOPSIS
    Creates an MST (transform) file for an MSI by injecting a PSK and target URL
    into the MSI's Property table—without modifying the original MSI.

.DESCRIPTION
    This script safely generates a Windows Installer transform (.mst) for an MSI
    package by:
        1. Opening the source MSI in read-only mode.
        2. Creating a temporary working copy of the MSI.
        3. Injecting the supplied PSK and URL into the Property table of the
           temporary MSI.
        4. Generating a transform representing only the differences.
        5. Releasing all Windows Installer COM handles to avoid file locking.

    The original MSI is never modified. The generated MST is written to the same
    directory as the MSI using the name:
        <MSIName>-AutoInject.mst

.PARAMETER MSIPath
    Full path to the MSI file for which the MST should be created.
    This file is opened read-only and never modified.

.PARAMETER PSKValue
    The Pre-Shared Key (PSK) value that will be injected into the MSI's
    Property table within the transform.

.PARAMETER URLValue
    The PSP server URL that will be injected into the MSI's Property table
    within the transform. Typically in the format:
        https://pspserver.domain.com/Agent

.EXAMPLE
    .\PSP-CreateMST.ps1 `
        -MSIPath "C:\Temp\PSPMigrationAgentInstaller.msi" `
        -PSKValue "+RXvgE4N1PAOOMpxq6ZXGBOHDGnJ+ragm3wld3XNso0XaYIOKLKfBJVxWiE1sqPF" `
        -URLValue "https://psp.company.com/Agent"

    Creates:
        C:\Temp\PSPMigrationAgentInstaller-AutoInject.mst

.NOTES
    Requires:
      • Windows Installer COM automation (built-in)
      • PowerShell 5.1 or later

    This script does NOT modify the MSI and ensures no lingering file handles.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$MSIPath,

    [Parameter(Mandatory=$true)]
    [string]$PSKValue,

    [Parameter(Mandatory=$true)]
    [string]$URLValue
)

# Validate MSI exists
if (-not (Test-Path $MSIPath)) {
    throw "MSI not found at path: $MSIPath"
}

# Resolve MSI path
$msiFull = (Resolve-Path $MSIPath).Path
$msiItem = Get-Item $msiFull
$msiDir  = $msiItem.DirectoryName
$msiName = [System.IO.Path]::GetFileNameWithoutExtension($msiItem.Name)

# Determine output MST file path
$mstPath = Join-Path $msiDir "$msiName-AutoInject.mst"

Write-Host "MSI: $msiFull"
Write-Host "Output MST: $mstPath"
Write-Host ""

# Create installer COM object
$installer = New-Object -ComObject WindowsInstaller.Installer

# Open original MSI in read-only mode (0)
$origDb = $installer.OpenDatabase($msiFull, 0)

# Create a temporary working MSI copy
$tempPath = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName() + ".msi")
Copy-Item $msiFull $tempPath -Force

# Open the clone with read-write mode (1)
$modDb = $installer.OpenDatabase($tempPath, 1)

# Helper function to update or insert MSI properties
function Set-MSIProperty {
    param($db, $name, $value)

    $view = $db.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='$name'")
    $view.Execute()
    $rec = $view.Fetch()
    $view.Close()

    if ($rec) {
        $view = $db.OpenView("UPDATE `Property` SET `Value`='$value' WHERE `Property`='$name'")
        $view.Execute()
        $view.Close()
    }
    else {
        $view = $db.OpenView("INSERT INTO `Property` (`Property`,`Value`) VALUES ('$name','$value')")
        $view.Execute()
        $view.Close()
    }
}

Write-Host "Injecting properties into temporary MSI clone..."
Set-MSIProperty -db $modDb -name "PSK" -value $PSKValue
Set-MSIProperty -db $modDb -name "URL" -value $URLValue

# Commit changes to the clone
$modDb.Commit()

Write-Host "Generating transform..."
$modDb.GenerateTransform($origDb, $mstPath)
$modDb.CreateTransformSummaryInfo($origDb, $mstPath, 0, 0)

Write-Host "MST successfully created at: $mstPath"
Write-Host ""

# Cleanup Section — MUST release COM before deleting temp file
Write-Host "Cleaning up COM objects..."

if ($modDb) {
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($modDb) | Out-Null
    $modDb = $null
}
if ($origDb) {
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($origDb) | Out-Null
    $origDb = $null
}
if ($installer) {
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null
    $installer = $null
}

# Force garbage collection TWICE to release Windows Installer COM handles
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[GC]::Collect()
[GC]::WaitForPendingFinalizers()

Write-Host "Removing temporary MSI: $tempPath"
Remove-Item $tempPath -Force

Write-Host "Done."
