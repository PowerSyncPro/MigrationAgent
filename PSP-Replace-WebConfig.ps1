Param (
    [Parameter(Mandatory = $true, HelpMessage = "Provide the PSP endpoint external domain (e.g. psp.contoso.com). It must not include slashes or 'http'.")]
    [string]$NewValue
)

# Validate that the new value does not have slashes (/ or \)
if ($NewValue -match "[/\\]") {
    Write-Error "Error: The provided value '$NewValue' contains a slash. It must not include '/' or '\' characters."
    exit 1
}

# Validate that the new value does not contain 'http' (case-insensitive)
if ($NewValue -imatch "http") {
    Write-Error "Error: The provided value '$NewValue' should not contain 'http'."
    exit 1
}

# Check if the script is running with Administrator privileges
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are required."
    exit
}

# Your script continues here...
Write-Host "Script is running with administrator privileges."

# Define the path to the web.config file (modify the path as needed)
$webConfigPath = "C:\inetpub\wwwroot\web.config" 

# Ensure the web.config exists
if (!(Test-Path $webConfigPath)) {
    Write-Error "Error: The file '$webConfigPath' does not exist."
    exit 1
}

# Create a backup file with a timestamp (format: yyyyMMddHHmmss) in the same directory
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$backupFile = "$webConfigPath.$timestamp"
Copy-Item -Path $webConfigPath -Destination $backupFile -ErrorAction Stop
Write-Host "Backup created: $backupFile"

# Define the new XML settings in a here-string
$xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <clear />
                <rule name="ReverseProxyInboundRule1" stopProcessing="true">
                    <match url="agent/(.*)" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false" />
                    <action type="Rewrite" url="http://localhost:5000/agent/{R:1}" />
                </rule>
                <rule name="Rewrite rule1 for agent" stopProcessing="true">
                    <match url="agent" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false" />
                    <action type="Rewrite" url="http://localhost:5000/agent" appendQueryString="true" />
                </rule>
                <rule name="RequestBlockingRule1" patternSyntax="Wildcard" stopProcessing="true">
                    <match url="*" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
                        <add input="{URL}" pattern="*" />
                    </conditions>
                    <action type="CustomResponse" statusCode="403" statusReason="Forbidden: Access is denied, you shouldn't be here." statusDescription="An IIS rewrite configuration has correctly prevented you accessing this portion of the PowerSyncPro website." />
                </rule>
            </rules>
            <outboundRules>
                <rule name="ReverseProxyOutboundRule1" preCondition="ResponseIsHtml1">
                    <match filterByTags="A, Form, Img" pattern="^http(s)?://localhost:5000/(.*)" />
                    <action type="Rewrite" value="http{R:1}://domainnamevalue/{R:2}" />
                </rule>
                <preConditions>
                    <preCondition name="ResponseIsHtml1">
                        <add input="{RESPONSE_CONTENT_TYPE}" pattern="^text/html" />
                    </preCondition>
                </preConditions>
            </outboundRules>
            <rewriteMaps>
                <rewriteMap name="agent" />
            </rewriteMaps>
        </rewrite>
    </system.webServer>
</configuration>
"@

# Replace the placeholder "thisvaluehere" with the user provided value
$xmlContent = $xmlContent -replace "domainnamevalue", $NewValue

# Write the updated configuration to web.config (using UTF8 encoding)
Set-Content -Path $webConfigPath -Value $xmlContent -Encoding UTF8
Write-Host "web.config has been updated successfully."
iisreset
Write-Host "IIS has been restarted successfully."


