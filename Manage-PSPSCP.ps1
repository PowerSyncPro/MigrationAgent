#
# Windows PowerShell script to configure the SCP for PowerSyncPro Proxy Agent
# Copyright 2024 PowerSyncPro
#
 
param([string]$ProxyURL, [switch]$Remove)
 
$SCPGuid = "cbf5cd4c-24df-4727-8ff3-b533cae18abb"
$rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$configCN = $rootDSE.Properties["configurationNamingContext"][0].ToString()
$servicesCN = "CN=Services," + $configCN
$pspCN = "CN=PowerSyncPro Configuration," + $servicesCN
$scpCN = "CN=" + $SCPGuid + "," + $pspCN

 
if( $Remove ) {
	if( [String]::IsNullorEmpty( $ProxyURL ) ) {
		if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://" + $scpCN)) {
			$deSCP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $scpCN)
			$deSCP.DeleteTree()
 
			$dePSP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $pspCN)
			$dePSP.DeleteTree()
		}
	} else {
		if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://" + $scpCN)) {
			$deSCP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $scpCN)
			# remove the url if it exists
			if( $deSCP.Properties['serviceBindingInformation'] -contains $ProxyURL ) {
				$deSCP.Properties['serviceBindingInformation'].Remove($ProxyURL)
				$deSCP.CommitChanges()
			} else {
				Write-Host "URL not found on the SCP" -fore yellow
			}


			# clean up if the SCP is now empty
			if( $deSCP.Properties['serviceBindingInformation'].count -eq 0 ) {
				$deSCP.DeleteTree()
	 
				$dePSP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $pspCN)
				$dePSP.DeleteTree()
			}
		} else {
			Write-Host "No SCP found" -fore yellow
		}
	}
} else {
	if( [String]::IsNullorEmpty( $ProxyURL ) ) {
		$searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $ConfigCN)
		$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
		$searcher.Filter = "(&(objectClass=serviceConnectionPoint)(CN=$SCPGuid))"
		$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

		$result = $searcher.FindOne()

		if ($result -ne $null) {
			$deSCP = $result.GetDirectoryEntry()
			Write-Output "PSP Service Connection Point found, URLs:"
			foreach( $Url in $deSCP.Properties['serviceBindingInformation'] ) {
				Write-Host "`t$Url"
			}
		} else {
			Write-Output "No PSP Service Connection Point found"
		}
	} else {
		# get or add the parent container
		if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://" + $pspCN)) {
			$dePSP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $pspCN)
		} else {
			$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $servicesCN)
			$dePSP = $de.Children.Add("CN=PowerSyncPro Configuration", "container")
			$dePSP.CommitChanges()
		}
 
		# get or add the SCP
		if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://" + $scpCN)) {
			$deSCP = New-Object System.DirectoryServices.DirectoryEntry("LDAP://" + $scpCN)
		} else {
			$deSCP = $dePSP.Children.Add("CN=cbf5cd4c-24df-4727-8ff3-b533cae18abb", "serviceConnectionPoint")
		}
 
		# add the new URL if needed
		if( $deSCP.Properties['serviceBindingInformation'] -notcontains $ProxyURL ) {
			$NewCount = $deSCP.Properties['serviceBindingInformation'].Add($ProxyURL)
			$deSCP.CommitChanges()
		} else {
			Write-Host "URL already exists on the SCP" -fore yellow
		}
	}
}
