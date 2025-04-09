#requires -RunAsAdministrator

Param (
    [Parameter(Mandatory = $true, HelpMessage = "Provide the PSP external endpoint domain (e.g. psp.contoso.com). It must not include slashes or 'http'.")]
    [string]$Domain,

    [Parameter(Mandatory = $false, HelpMessage = "Provide the PSP local endpoint. Defaults to 'localhost:5000'. It must not include slashes or 'http'.")]
    [string]$LocalEndpoint = "localhost:5000"
)

# Validate $NewValue
if (($LocalEndpoint -match "[/\\]" -or $LocalEndpoint -imatch "http") -and $LocalEndpoint -imatch ":") {
    Write-Error "Error: The PSP local endpoint must not include slashes or 'http'."
    exit 1
}

# Validate $LocalEndpoint
if ($Domain -match "[/\\]" -or $Domain -match "http") {
    Write-Error "Error: The PSP external domain must not include slashes or 'http'."
    exit 1
}

# Output the validated parameter values
Write-Host "PSP Endpoint External Domain: $Domain"
Write-Host "Local Endpoint: $LocalEndpoint"

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
                    <action type="Rewrite" url="http://localendpoint/agent/{R:1}" />
                </rule>
                <rule name="Rewrite rule1 for agent" stopProcessing="true">
                    <match url="agent" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false" />
                    <action type="Rewrite" url="http://localendpoint/agent" appendQueryString="true" />
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
                    <match filterByTags="A, Form, Img" pattern="^http(s)?://localendpoint/(.*)" />
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
$xmlContent = $xmlContent -replace "domainnamevalue", $Domain
$xmlContent = $xmlContent -replace "localendpoint", $LocalEndpoint

# Write the updated configuration to web.config (using UTF8 encoding)
Set-Content -Path $webConfigPath -Value $xmlContent -Encoding UTF8
Write-Host "web.config has been updated successfully."
iisreset
Write-Host "IIS has been restarted successfully."
