<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.ManagedServiceIdentity, Az.Resources

#region Function definitions
function New-AzureSoftwareContainer {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $false)]
		[string]$Location = "EastUS"
	)

	#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
	$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
	$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
	$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
	#endregion

	#region Set up the environment and variables
	# get existing context
	$AzContext = Get-AzContext
	# Your subscription. This command gets your current subscription
	$subscriptionID = $AzContext.Subscription.Id

	#Timestamp
	$DigitNumber = 3
	$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))

	#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
	$ResourceGroupPrefix = "rg"
	$StorageAccountPrefix = "sa"
	$NetworkSecurityGroupPrefix = "nsg"
	$VirtualNetworkPrefix = "vnet"
	$SubnetPrefix = "snet"

	# Location (see possible locations in the main docs)
	#$Location = "EastUS"
	Write-Verbose -Message "`$Location: $Location"
	$LocationShortName = $shortNameHT[$Location].shortName
	Write-Verbose -Message "`$LocationShortName: $LocationShortName"

	$Project = "avd"
	$Role = "aib"
	#endregion

	#region Create storage resource group
	Do {
		$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
		$StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
		Start-Sleep -Second 1
	} While (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)
 

	$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance 
	$ResourceGroupName = $ResourceGroupName.ToLower()
	Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"

	Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
	$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

	$StorageAccountSkuName = "Standard_LRS"
	$ContainerName = "software"
	$StorageAccount = New-AzStorageAccount -AccountName $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true #-AllowBlobPublicAccess $true
	$StorageContext = $StorageAccount.Context
	$StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $StorageContext

	$SoftwareDir = New-Item -Path $CurrentDir -Name "Software" -ItemType Directory -Force
	#region Notepad++
	#region Notepad++ Installer
	$DownloadURI = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6/npp.8.6.Installer.x64.exe"
	$DestinationFileName = Split-Path -Path $DownloadURI -Leaf
	$DestinationDirName = "001-NotepadPlusPlus"
	$DestinationDir = New-Item -Path $SoftwareDir -Name $DestinationDirName -ItemType Directory -Force
	$BlobName = Join-Path -Path $DestinationDirName -ChildPath $DestinationFileName
	$DestinationFullName = Join-Path $DestinationDir -ChildPath $DestinationFileName
	Start-BitsTransfer -Source $DownloadURI -Destination $DestinationFullName -DisplayName $DownloadURI
	$null = Set-AzStorageBlobContent -Context $StorageContext -File $DestinationFullName -Container $ContainerName -Blob $BlobName -BlobType Block -Force
	#endregion
	
	#region Notepad++ Setup PowerShell Script
	$InstallPowershellScript = New-Item -Path $DestinationDir -Name "Install-NotepadPlusPlus.ps1" -Value "Start-Process -FilePath `"`$env:comspec`" -ArgumentList '/c', `"`"`"`$PSScriptRoot\$DestinationFileName`"`" /S`" -Wait" -Force
	$DestinationFileName = Split-Path -Path $InstallPowershellScript -Leaf
	$BlobName = Join-Path -Path $DestinationDirName -ChildPath $DestinationFileName
	$null = Set-AzStorageBlobContent -Context $StorageContext -File $InstallPowershellScript -Container $ContainerName -Blob $BlobName -BlobType Block -Force
	#endregion
	#endregion
	<#
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#file-customizer (Read the note for the file size)
    #region Storage Explorer 
    #region Storage Explorer Installer
    $DownloadURI = "https://download.microsoft.com/download/A/E/3/AE32C485-B62B-4437-92F7-8B6B2C48CB40/StorageExplorer-windows-x64.exe"
    $DestinationFileName = Split-Path -Path $DownloadURI -Leaf
    $DestinationDirName = "02-StorageExplorer"
    $DestinationDir = New-Item -Path $SoftwareDir -Name $DestinationDirName -ItemType Directory -Force
    $BlobName = Join-Path -Path $DestinationDirName -ChildPath $DestinationFileName
    $DestinationFullName = Join-Path $DestinationDir -ChildPath $DestinationFileName
    Start-BitsTransfer -Source $DownloadURI -Destination $DestinationFullName -DisplayName $DownloadURI
    $null = Set-AzStorageBlobContent -Context $StorageContext -File $DestinationFullName -Container $ContainerName -Blob $BlobName -BlobType Block -Force
    #endregion
	
    #region StorageExplorer Setup PowerShell Script
	$InstallPowershellScript = New-Item -Path $DestinationDir -Name "Install-StorageExplorer.ps1" -Value "Start-Process -FilePath `"`$env:comspec`" -ArgumentList '/c', `"`"`"`$PSScriptRoot\$DestinationFileName`"`" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS`" -Wait" -Force
    $DestinationFileName = Split-Path -Path $InstallPowershellScript -Leaf
    $BlobName = Join-Path -Path $DestinationDirName -ChildPath $DestinationFileName
    $null = Set-AzStorageBlobContent -Context $StorageContext -File $InstallPowershellScript -Container $ContainerName -Blob $BlobName -BlobType Block -Force
    #endregion
    #endregion
    #>
	#endregion

	#region Create Virtual Network and Subnet
	#From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-vnet
	$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
	$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
	$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance        
	$VirtualNetworkName = $VirtualNetworkName.ToLower()
	$SubnetName = $SubnetName.ToLower()
	$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
	Write-Verbose "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
	Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         
	Write-Verbose "`$SubnetName: $SubnetName"         
	$VNetAddressRange = '10.0.0.0/16'
	$SubnetAddressRange = '10.0.1.0/24'

	#Add an NSG rule
	$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -Force
	$null = $NetworkSecurityGroup | Add-AzNetworkSecurityRuleConfig -Name AzureImageBuilderAccess -Description "Allow Image Builder Private Link Access to Proxy VM" -Access Allow -Protocol Tcp -Direction Inbound -Priority 400 -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * -DestinationAddressPrefix VirtualNetwork -DestinationPortRange 60000-60001 | Set-AzNetworkSecurityGroup
	#Disable private service policy on the subnet
	$subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $SubnetAddressRange -PrivateLinkServiceNetworkPoliciesFlag "Disabled" -NetworkSecurityGroup $NetworkSecurityGroup
	$vNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VNetAddressRange -Location $Location -Subnet $Subnet
	#endregion

	#region Private endpoint for Storage Setup
	#From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
	#From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
	#From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
	## Create the private endpoint connection. ## 

	Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$StorageAccountName' (in the '$($ResourceGroupName)' Resource Group) ..."
	$PrivateEndpointName = "pep{0}" -f $($StorageAccountName -replace "\W")
	$GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $StorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "blob" }
	$PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $StorageAccount.Id -GroupId $GroupId
	$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNetwork
	$PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -Location $Location -Subnet $Subnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

	## Create the private DNS zone. ##
	#Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$StorageAccountName' (in the '$($ResourceGroupName)' Resource Group) ..."
	$AzContext = Get-AzContext
	$StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix
	$PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
	$PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
	if ($null -eq $PrivateDnsZone) {
		Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$StorageAccountName' (in the '$($ResourceGroupName)' Resource Group) ..."
		$PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ResourceGroupName -Name $PrivateDnsZoneName
	}

	$PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($vNetwork.Name -replace "\W")
	$PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
	if ($null -eq $PrivateDnsVirtualNetworkLink) {
		## Create a DNS network link. ##
		Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$StorageAccountName' (in the '$($ResourceGroupName)' Resource Group) ..."
		$PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $vNetwork.Id
	}

	## Configure the DNS zone. ##
	Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$StorageAccountName' ..."
	$PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

	## Create the DNS zone group. ##
	Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group) ..."
	$PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

	#Storage Account - Disabling Public Access
	#From https://www.jorgebernhardt.com/azure-storage-public-access/
	#From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
	#From https://github.com/adstuart/azure-privatelink-dns-microhack
	#Write-Verbose -Message "Disabling the Public Access for the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
	#$null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Disabled
	#(Get-AzStorageAccount -Name $ResourceGroupName -ResourceGroupName $StorageAccountName ).AllowBlobPublicAccess
	#endregion

	return $StorageContainer
}

#FROM https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $false)]
		[string]$Location = "EastUS",
		[Parameter(Mandatory = $false)]
		[string[]]$ReplicationRegions = "EastUS2",
		[Parameter(Mandatory = $true)]
		[object]$StorageContainer
	)

	#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
	$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
	$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
	$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
	#endregion

	#region Set up the environment and variables
	# get existing context
	$AzContext = Get-AzContext
	# Your subscription. This command gets your current subscription
	$subscriptionID = $AzContext.Subscription.Id

	#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
	$AzureComputeGalleryPrefix = "acg"
	$ResourceGroupPrefix = "rg"

	# Location (see possible locations in the main docs)
	#$Location = "EastUS"
	Write-Verbose -Message "`$Location: $Location"
	$LocationShortName = $shortNameHT[$Location].shortName
	Write-Verbose -Message "`$LocationShortName: $LocationShortName"
	#$ReplicationRegions = "EastUS2"
	Write-Verbose -Message "`$ReplicationRegions: $($ReplicationRegions -join ', ')"

	$Project = "avd"
	$Role = "aib"
	#Timestamp
	$timeInt = (Get-Date $([datetime]::UtcNow) -UFormat "%s").Split(".")[0]
	$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
	$ResourceGroupName = $ResourceGroupName.ToLower()
	Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"

	# Image template and definition names
	#AVD MultiSession Session Image Market Place Image + customizations: VSCode
	$imageDefName01 = "win11-24h2-ent-avd-custom-vscode"
	$imageTemplateName01 = $imageDefName01 + "-template-" + $timeInt
	#AVD MultiSession + Microsoft 365 Market Place Image + customizations: VSCode
	$imageDefName02 = "win11-24h2-ent-avd-m365-vscode"
	$imageTemplateName02 = $imageDefName02 + "-template-" + $timeInt
	Write-Verbose -Message "`$imageDefName01: $imageDefName01"
	Write-Verbose -Message "`$imageTemplateName01: $imageTemplateName01"
	Write-Verbose -Message "`$imageDefName02: $imageDefName02"
	Write-Verbose -Message "`$imageTemplateName02: $imageTemplateName02"

	# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
	$runOutputName01 = "cgOutput01"
	$runOutputName02 = "cgOutput02"

	#$Version = "1.0.0"
	$Version = Get-Date -UFormat "%Y.%m.%d"
	$Jobs = @()

	#region Get data related to the software container
	$StorageContainerStorageAccount = Get-AzStorageAccount | Where-Object -FilterScript { $_.StorageAccountName -eq $StorageContainer.Context.StorageAccount.Credentials.AccountName }
	$StorageContainerVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $StorageContainerStorageAccount.ResourceGroupName
	$StorageContainerSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $StorageContainerVirtualNetwork
	#endregion
	#endregion

	#region Create resource group
	if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
		Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
		Remove-AzResourceGroup -Name $ResourceGroupName -Force
	}
	Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
	$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force
	#endregion

	#region Permissions, user identity, and role
	# setup role def names, these need to be unique
	$imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
	$networkRoleDefName = "Azure Image Builder Network Def" + $timeInt
	$identityName = "aibIdentity-$timeInt"
	Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
	Write-Verbose -Message "`$identityName: $identityName"

	# Create the identity
	Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
	$AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location

	#region aibRoleNetworking.json
	#$aibRoleNetworkingUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/master/solutions/12_Creating_AIB_Security_Roles/aibRoleNetworking.json"
	$aibRoleNetworkingUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleNetworking.json"
	$aibRoleNetworkingPath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $aibRoleNetworkingUrl -Leaf)
	$aibRoleNetworkingPath = $aibRoleNetworkingPath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$aibRoleNetworkingPath: $aibRoleNetworkingPath"
	# Download the config
	Invoke-WebRequest -Uri $aibRoleNetworkingUrl -OutFile $aibRoleNetworkingPath -UseBasicParsing

    ((Get-Content -Path $aibRoleNetworkingPath -Raw) -replace 'Azure Image Builder Service Networking Role', $networkRoleDefName) | Set-Content -Path $aibRoleNetworkingPath

	# update role definitions
    ((Get-Content -Path $aibRoleNetworkingPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleNetworkingPath
    ((Get-Content -Path $aibRoleNetworkingPath -Raw) -replace '<vnetRgName>', $StorageContainerStorageAccount.ResourceGroupName) | Set-Content -Path $aibRoleNetworkingPath
	#endregion


	#region aibRoleImageCreation.json
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
	$aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
	#$aibRoleImageCreationPath = "aibRoleImageCreation.json"
	$aibRoleImageCreationPath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
	#Generate a unique file name 
	$aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

	# Download the config
	Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath
	#endregion

	#region Role Definition(s) and Assignement(s)
	# Create a role definition
	#Image
	Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
	$RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath
	# Grant the role definition to the VM Image Builder service principal
	Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
	Do {
		Write-Verbose -Message "Sleeping 10 seconds ..."
		Start-Sleep -Seconds 10
		$RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
	} While ($null -eq $RoleAssignment)
  
	#Network
	Write-Verbose -Message "Creating '$networkRoleDefName' Role Definition ..."
	$RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleNetworkingPath
	# Grant the role definition to the VM Image Builder service principal
	Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
	$Scope = "/subscriptions/$subscriptionID/resourceGroups/$($StorageContainerStorageAccount.ResourceGroupName)"
	Do {
		Write-Verbose -Message "Sleeping 10 seconds ..."
		Start-Sleep -Seconds 10
		$RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope -ErrorAction Ignore #-Debug
	} While ($null -eq $RoleAssignment)

	#Granting the "Storage Blob Data Reader" role to the container
	Write-Verbose -Message "Assigning 'Storage Blob Data Reader' Role to '$($AssignedIdentity.Name)' ..."
	$StorageAccount = Get-AzStorageAccount | Where-Object -FilterScript { $_.StorageAccountName -eq $StorageContainer.Context.StorageAccount.Credentials.AccountName }
	$Scope = "$($StorageAccount.Id)/blobServices/default/containers/$($StorageContainer.Name)"
	Do {
		Write-Verbose -Message "Sleeping 10 seconds ..."
		Start-Sleep -Seconds 10
		$RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName "Storage Blob Data Reader" -Scope $Scope -ErrorAction Ignore #-Debug
	} While ($null -eq $RoleAssignment)

	#endregion
	#endregion
	#endregion

	#region Create an Azure Compute Gallery
	$GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
	Write-Verbose -Message "`$GalleryName: $GalleryName"

	# Create the gallery
	Write-Verbose -Message "Creating Azure Compute Gallery '$GalleryName' ..."
	$Gallery = New-AzGallery -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location
	#endregion

	#region Template #1 via a customized JSON file
	#Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
	# Create the gallery definition
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName01' (From Customized JSON)..."
	$GalleryImageDefinition01 = New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'win10-22h2-ent-g2-arm-vscode' -HyperVGeneration V2

	#region Download and configure the template
	#$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
	#$templateFilePath = "armTemplateWVD.json"
	$templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD-v4.json"
	$templateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $templateUrl -Leaf)
	#Generate a unique file name 
	$templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

	Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

	# update AIB image config template
    ((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
	#((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

    ((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<region1>', $replicationRegions) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<vnetName>', $StorageContainerVirtualNetwork.Name) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<subnetName>', $StorageContainerSubnet.Name) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<vnetRgName>', $StorageContainerStorageAccount.ResourceGroupName) | Set-Content -Path $templateFilePath
	#endregion

	#region Submit the template
	Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
	$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2020-02-14" } -imageTemplateName $imageTemplateName01 -svclocation $location

	#region Build the image
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName01' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01 -AsJob
	#endregion
	#endregion
	#endregion

	#region Template #2 via a image from the market place + customizations
	# create gallery definition
	$GalleryParams = @{
		GalleryName       = $GalleryName
		ResourceGroupName = $ResourceGroupName
		Location          = $location
		Name              = $imageDefName02
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = 'Contoso'
		Offer             = 'Windows'
		Sku               = 'win10-22h2-ent-g2-posh-vscode'
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From A Market Place Image)..."
	$GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

	$SrcObjParams = @{
		PlatformImageSource = $true
		Publisher           = 'MicrosoftWindowsDesktop'
		Offer               = 'Windows-10'    
		Sku                 = 'win10-22h2-ent-g2'  
		Version             = 'latest'
	}
	Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
	$srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

	$disObjParams = @{
		SharedImageDistributor = $true
		GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
		ArtifactTag            = @{source = 'win10-22h2-ent-g2-posh-vscode'; baseosimg = 'windows10' }

		# 1. Uncomment following line for a single region deployment.
		#ReplicationRegion = $location

		# 2. Uncomment following line if the custom image should be replicated to another region(s).
		ReplicationRegion      = @($location) + $replicationRegions

		RunOutputName          = $runOutputName02
		ExcludeFromLatest      = $false
	}
	Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
	$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams
    
	#region Customizer
	#region Software Customizer

	#We sort by extension descending to be sure an MSI/EXE file be processed before its related powershell setup file
	$StartTime = Get-Date
	$ExpiryTime = $StartTime.AddDays(1)

	$StorageBlob = Get-AzStorageBlob -Container $SoftwareContainer.Name -Context $SoftwareContainer.Context
	$NonPowerShellScriptStorageBlob = $StorageBlob | Where-Object -FilterScript { $_.Name -notmatch "\.ps1$" } | Sort-Object -Property Name
	$PowerShellScriptStorageBlob = $StorageBlob | Where-Object -FilterScript { $_.Name -match "\.ps1$" } | Sort-Object -Property Name
	$StorageBlob = @($NonPowerShellScriptStorageBlob) + @($PowerShellScriptStorageBlob)
	$StorageBlobCustomizers = foreach ($CurrentStorageBlob in $StorageBlob) {
		$CurrentStorageBlobSASToken = New-AzStorageBlobSASToken -Container $SoftwareContainer.Name -Blob $CurrentStorageBlob.Name -Permission rl -Context $SoftwareContainer.Context -FullUri -StartTime $StartTime -ExpiryTime $ExpiryTime
		$Destination = Join-Path "C:\AVDImage" -ChildPath $CurrentStorageBlob.Name
		$CurrentStorageBlobFileCustomizerParams = @{  
			FileCustomizer = $true  
			Name           = "FC_{0}" -f ($CurrentStorageBlob.Name -replace "\W", "_")
			sourceUri      = $CurrentStorageBlobSASToken
			destination    = $Destination
		}
		Write-Verbose -Message "Creating Azure Image Builder Template File Customizer Object for copying '$($CurrentStorageBlob.Name)' from a Storage Account Container ..."
		New-AzImageBuilderTemplateCustomizerObject @CurrentStorageBlobFileCustomizerParams 
        
		if ($CurrentStorageBlob.Name -match "\.ps1$") {
			$CurrentStorageBlobPowerShellCustomizerParams = @{  
				PowerShellCustomizer = $true  
				Name                 = "PC_{0}" -f ($CurrentStorageBlob.Name -replace "\W", "_")
				RunElevated          = $true  
				runAsSystem          = $true
				inline               = $Destination
			}
			Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for running '$($CurrentStorageBlob.Name)' ..."
			New-AzImageBuilderTemplateCustomizerObject @CurrentStorageBlobPowerShellCustomizerParams 
		}
	}

	$ImgCopyInstallLanguagePacksFileCustomizerParams = @{  
		FileCustomizer = $true  
		Name           = 'CopyInstallLanguagePacks'  
		sourceUri      = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-11-20/InstallLanguagePacks.ps1'
		destination    = "C:\AVDImage\installLanguagePacks.ps1"
	}

	Write-Verbose -Message "Creating Azure Image Builder Template Customizer Object for copying 'InstallLanguagePacks.ps1' from the RDS-Templates Github repository ..."
	$CopyInstallLanguagePacksCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgCopyInstallLanguagePacksFileCustomizerParams 

	$ImgInstallLanguagePacksFileCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'InstallLanguagePacks'  
		RunElevated          = $true  
		runAsSystem          = $true
		inline               = "C:\AVDImage\installLanguagePacks.ps1 -LanguageList 'German (Germany)','French (France)'"
	}
	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for running 'InstallLanguagePacks.ps1' ..."
	$InstallLanguagePacksCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgInstallLanguagePacksFileCustomizerParams 

	$ImgTimeZoneRedirectionPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Timezone Redirection'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgTimeZoneRedirectionPowerShellCustomizerParams.Name)' ..."
	$TimeZoneRedirectionCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgTimeZoneRedirectionPowerShellCustomizerParams 

	$ImgVSCodePowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install Visual Studio Code'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)' ..."
	$VSCodeCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgVSCodePowerShellCustomizerParams 

	Write-Verbose -Message "Creating Azure Image Builder Template WindowsUpdate Customizer Object ..."
	$WindowsUpdateCustomizer = New-AzImageBuilderTemplateCustomizerObject -WindowsUpdateCustomizer -Name 'WindowsUpdate' -Filter @('exclude:$_.Title -like ''*Preview*''', 'include:$true') -SearchCriterion "IsInstalled=0" -UpdateLimit 40

	$ImgDisableAutoUpdatesPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Disable AutoUpdates'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgDisableAutoUpdatesPowerShellCustomizerParams.Name)' ..."
	$DisableAutoUpdatesCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgDisableAutoUpdatesPowerShellCustomizerParams 

	#Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
	#As $StorageBlobCustomizers is an array we force the two first items in an array so $Customize will be cast as an array
	$Customize = @($CopyInstallLanguagePacksCustomizer, $InstallLanguagePacksCustomizer) + @($StorageBlobCustomizers) + @($TimeZoneRedirectionCustomizer, $VSCodeCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer)
	$ImgTemplateParams = @{
		ImageTemplateName      = $imageTemplateName02
		ResourceGroupName      = $ResourceGroupName
		Source                 = $srcPlatform
		Distribute             = $disSharedImg
		Customize              = $Customize
		Location               = $location
		UserAssignedIdentityId = $AssignedIdentity.Id
		VMProfileVmsize        = "Standard_D8s_v5"
		VMProfileOsdiskSizeGb  = 127
		BuildTimeoutInMinute   = 240
		VnetConfigSubnetId     = $StorageContainerSubnet.Id

	}
	Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
	$ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

	#Write-Verbose -Message "Disabling the Public Access for the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
	$null = Set-AzStorageAccount -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -PublicNetworkAccess Disabled
	#(Get-AzStorageAccount -Name $StorageAccount.ResourceGroupName -ResourceGroupName $StorageAccountName ).AllowBlobPublicAccess

	#region Build the image
	#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
	#endregion

	Write-Verbose -Message "Waiting for jobs to complete ..."
	$Jobs | Wait-Job | Out-Null

	#region imageTemplateName01 status 
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatus01 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01
	# Optional - if you have any errors running the preceding command, run:
	Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorCode: $($getStatus01.ProvisioningErrorCode) "
	Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorMessage: $($getStatus01.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunState: $($getStatus01.LastRunStatusRunState) "
	Write-Verbose -Message "'$imageTemplateName01' LastRunStatusMessage: $($getStatus01.LastRunStatusMessage) "
	Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunSubState: $($getStatus01.LastRunStatusRunSubState) "
	if ($getStatus01.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateName01' has failed:\r\n$($getStatus01.LastRunStatusMessage)"
	}
	Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01' ..."
	#$Jobs += $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
	$getStatus01 | Remove-AzImageBuilderTemplate -NoWait
	Write-Verbose -Message "Removing '$aibRoleImageCreationPath' ..."
	Write-Verbose -Message "Removing '$templateFilePath' ..."
	Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
	#endregion

	#region imageTemplateName02 status
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatus02 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02
	# Optional - if you have any errors running the preceding command, run:
	Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorCode: $($getStatus02.ProvisioningErrorCode) "
	Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorMessage: $($getStatus02.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunState: $($getStatus02.LastRunStatusRunState) "
	Write-Verbose -Message "'$imageTemplateName02' LastRunStatusMessage: $($getStatus02.LastRunStatusMessage) "
	Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunSubState: $($getStatus02.LastRunStatusRunSubState) "
	if ($getStatus02.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateName02' has failed:\r\n$($getStatus02.LastRunStatusMessage)"
	}
	Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02' ..."
	#$Jobs += $getStatus02 | Remove-AzImageBuilderTemplate -AsJob
	$getStatus02 | Remove-AzImageBuilderTemplate -NoWait
	#endregion

	#Adding a delete lock (for preventing accidental deletion)
	#New-AzResourceLock -LockLevel CanNotDelete -LockNotes "$ResourceGroupName - CanNotDelete" -LockName "$ResourceGroupName - CanNotDelete" -ResourceGroupName $ResourceGroupName -Force
	#region Clean up your resources
	<#
    ## Remove the Resource Group
    Remove-AzResourceGroup $ResourceGroupName -Force -AsJob
    ## Remove the definitions
    Remove-AzRoleDefinition -Name $RoleDefinition.Name -Force
    #>
	#endregion
  
	$Jobs | Wait-Job | Out-Null
	Write-Verbose -Message "Removing jobs ..."
	$Jobs | Remove-Job -Force
	return $Gallery
}
#endregion

#region Main code
Clear-Host
$Error.Clear()
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Defining variables 
$SubscriptionName = "Cloud Solution Architect"
#endregion

#region Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
	Connect-AzAccount
	Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
	#$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
	#Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

#region To use Azure Image Builder, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = 'Microsoft.VirtualMachineImages', 'Microsoft.Storage', 'Microsoft.Compute', 'Microsoft.KeyVault', 'Microsoft.ManagedIdentity'
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
	Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
	Write-Verbose -Message "Sleeping 10 seconds ..."
	Start-Sleep -Seconds 10
}
$Jobs | Remove-Job -Force
#endregion
$SoftwareContainer = New-AzureSoftwareContainer -Verbose

$AzureComputeGallery = New-AzureComputeGallery -StorageContainer $SoftwareContainer -Verbose
$AzureComputeGallery

$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Total Processing Time: $($TimeSpan.ToString())"
#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob
#endregion