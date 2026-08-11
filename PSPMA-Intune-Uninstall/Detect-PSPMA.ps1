#requires -version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$ServiceName = 'PowerSyncPro Migration Agent'
$DisplayNamePattern = 'PowerSyncPro Migration Agent'

function Get-ObjectPropertyValue {
    param([Parameter(Mandatory)]$InputObject,[Parameter(Mandatory)][string]$PropertyName)
    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -ne $property) { return $property.Value }
    return $null
}

$serviceFound = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
$applicationFound = $false

foreach ($path in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)) {
    foreach ($entry in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
        $displayName = [string](Get-ObjectPropertyValue -InputObject $entry -PropertyName 'DisplayName')
        if (-not [string]::IsNullOrWhiteSpace($displayName) -and $displayName -like "*$DisplayNamePattern*") {
            $applicationFound = $true
            break
        }
    }
    if ($applicationFound) { break }
}

if ($serviceFound -or $applicationFound) {
    Write-Output 'PowerSyncPro Migration Agent is installed.'
    exit 0
}
exit 1
