# PowerSyncPro MigrationAgent

PowerSyncPro specializes in Windows 10 & 11 Workstation Migrations (Hybrid to Cloud Native), Active Directory (AD) to AD or Entra to Entra migrations.
We also offer enterprise grade Directory Synchronisation, with features like the 'WhatIf report' to review attribute changes before you commit any configuration change

# CheckPSPServerPrerequisites.ps1

For more information on the requirements validation please refer to our KB article

https://kb.powersyncpro.com/requirements-validation-on-the-powersyncpro-server

# CreatePSPEntraIDApp.ps1

Then for creating the enterprise app, also refer to this KB article for the latest information.
You will need Graph installed, and have Global Admin access to the tenant so that admin consent can be granted.
When you run the script it will ask your for the Tenant ID, then output the Application ID and Secret for putting into PowerSyncPro directory configuration.

https://kb.powersyncpro.com/en_US/create-powersyncpro-entraid-application

# Workgroup-Migrate.ps1

How to migrate a workgroup machine

For more information reffer to this KB article.

https://kb.powersyncpro.com/workgroup-workstation-migration-process

# Manage-PSPSCP.ps1

Manage the Service Connection Point for the PowerSyncPro proxcy agent

List the SCP if available - without any parameters
./Manage-PSPSCP.ps1

Add URL to a new or existing SCP
./Manage-PSPSCP.ps1 -ProxyURL https://pspproxy1.contoso.com:5001
./Manage-PSPSCP.ps1 -ProxyURL https://pspproxy2.contoso.com:5001

Remove a URL from the SCP
./Manage-PSPSCP.ps1 -ProxyURL http://something:5000/agent -Remove

Remove the SCP altogether
./Manage-PSPSCP.ps1 -Remove

# PSP-Replace-WebConfig.ps1

This will replace and standardise the IIS web.config file with the rewrite rules to prevent /agent/ from being accessible on your endpoint.
This is intended for a stand alone IIS configuration dedicated for PowerSyncPro migration agent default installation.

If you're introducing remote proxy agent or remote password agent this will revert the configuration, so this script should not be used.

NOYTE: any other config in IIS web.config will be replaced and ignored.

You must supply the domain for the SSL cert and DNS which is pointing to the server.

.\PSP-Replace-WebConfig.ps1 -Domain "psptraining.migsource.net"

If you have a custom installation then you can also specify the local endpoint

.\PSP-Replace-WebConfig.ps1 -Domain psptraining.migsource.net -LocalEndpoint localhost:5000


