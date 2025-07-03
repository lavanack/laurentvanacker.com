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
function New-CMKDiskEncryptionSet {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[string]$Project,
		[Parameter(Mandatory = $true)]
		[string]$Role,
		[Parameter(Mandatory = $true)]
		[string]$Location,
		[Parameter(Mandatory = $true)]
		[string]$LocationShortName,
		[Parameter(Mandatory = $true)]
		[string]$TimeInt,
		[Parameter(Mandatory = $true)]
		[string]$ResourceGroupName
	)

	$KeyVaultPrefix = "kv"
	$DiskEncryptionSetPrefix = "des"
	$DiskEncryptionKeyPrefix = "dek"
	$KeyVaultName = "{0}-{1}-{2}-{3}-{4}" -f $KeyVaultPrefix, $Project, $Role, $LocationShortName, $TimeInt                                             
	$KeyVaultName = "{0}{1}{2}{3}{4}" -f $KeyVaultPrefix, $Project, $Role, $LocationShortName, $TimeInt                                             
	$DiskEncryptionSetName = "{0}-{1}-{2}-{3}-{4}" -f $DiskEncryptionSetPrefix, $Project, $Role, $LocationShortName, $TimeInt                                             
	$DiskEncryptionKeyName = "{0}-{1}-{2}-{3}-{4}" -f $DiskEncryptionKeyPrefix, $Project, $Role, $LocationShortName, $TimeInt
    $DiskEncryptionKeyDestination = "Software"

	Write-Verbose -Message "`$KeyVaultName: $KeyVaultName"
	$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $Location -EnabledForDiskEncryption -EnablePurgeProtection

    #region "Key Vault Administrator" RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition "Key Vault Administrator"
    $RoleAssignment = New-AzRoleAssignment -SignInName (Get-AzContext).Account.Id -RoleDefinitionName $RoleDefinition.Name -Scope $KeyVault.ResourceId -ErrorAction Ignore #-Debug
    #endregion

    Start-Sleep -Seconds 30

	#FROM https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell#set-up-an-azure-key-vault-and-diskencryptionset-optionally-with-automatic-key-rotation
	$key = Add-AzKeyVaultKey -VaultName $keyVaultName -Name $DiskEncryptionKeyName -Destination $DiskEncryptionKeyDestination
	$DiskEncryptionSetConfig = New-AzDiskEncryptionSetConfig -Location $Location -SourceVaultId $keyVault.ResourceId -KeyUrl $key.Key.Kid -IdentityType SystemAssigned -RotationToLatestKeyVersionEnabled $true
	$DiskEncryptionSet = New-AzDiskEncryptionSet -Name $DiskEncryptionSetName -ResourceGroupName $ResourceGroupName -InputObject $DiskEncryptionSetConfig

    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-host-based-encryption-powershell#create-an-azure-key-vault-and-diskencryptionset
    # Grant the DiskEncryptionSet resource access to the key vault.
    #$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $DiskEncryptionSet.Identity.PrincipalId -PermissionsToKeys wrapkey,unwrapkey,get -Verbose
    #region "Key Vault Crypto Service Encryption User" RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition "Key Vault Crypto Service Encryption User"
    $RoleAssignment = New-AzRoleAssignment -ObjectId $DiskEncryptionSet.Identity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $KeyVault.ResourceId -ErrorAction Ignore #-Debug
    #endregion

	return $DiskEncryptionSet
}

#FROM https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $false)]
		[string]$Location = "EastUS2",
		[Parameter(Mandatory = $false)]
		[string[]]$TargetRegions = @($Location),
		[Parameter(Mandatory = $false)]
		[int]$ReplicaCount = 1
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
	Write-Verbose -Message "`$Location: $Location"
	$LocationShortName = $shortNameHT[$Location].shortName
	Write-Verbose -Message "`$LocationShortName: $LocationShortName"
	if ($Location -notin $TargetRegions) {
		$TargetRegions += $Location
	}
	Write-Verbose -Message "`$TargetRegions: $($TargetRegions -join ', ')"
	[array] $TargetRegionSettings = foreach ($CurrentTargetRegion in $TargetRegions) {
		@{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
	}

	$Project = "avd"
	$Role = "aib"
	#Timestamp
	$timeInt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
	$ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
	$ResourceGroupName = $ResourceGroupName.ToLower()
	Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"

	#region Source Image 
	$SrcObjParams1 = @{
		Publisher           = 'MicrosoftWindowsDesktop'
		Offer               = 'Office-365'        
		Sku                 = 'win11-22h2-avd-m365'    
		Version             = 'latest'
	}

	$SrcObjParams2 = @{
		Publisher = 'MicrosoftWindowsDesktop'
		Offer     = 'Office-365'    
		Sku       = 'win11-24h2-avd-m365'  
		Version   = 'latest'
	}
	#endregion

	#region Image template and definition names
	#Image Market Place Image + customizations: VSCode
	$imageDefName = "{0}-posh-vscode" -f $SrcObjParams2.Sku
	$imageTemplateName = "{0}-template-{1}" -f $imageDefName, $timeInt
	Write-Verbose -Message "`$imageDefName: $imageDefName"
	Write-Verbose -Message "`$imageTemplateName: $imageTemplateName"
	#endregion

	# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
	$runOutputName = "cgOutput"

	#$Version = "1.0.0"
	#PMK version (ending with 0)
	$PMKGalleryImageVersionName = Get-Date -UFormat "%Y.%m.%d"
	$Jobs = @()
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
	#region setup role def names, these need to be unique
	$imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
	$identityName = "aibIdentity-$timeInt"
	Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
	Write-Verbose -Message "`$identityName: $identityName"
	#endregion

	#region Create the identity
	Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
	$AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $Location

	#Hastable for all Disk Encryption Sets (The location is the key) 
	$CMKDiskEncryptionSetHT = @{}
	foreach ($CurrentTargetRegion in $TargetRegions) {
		$CurrentTargetRegionShortName = $shortNameHT[$CurrentTargetRegion].shortName
		Write-Verbose "Processing '$CurrentTargetRegion' Azure Region ..."
		$CMKDiskEncryptionSetHT[$CurrentTargetRegion] = New-CMKDiskEncryptionSet -Project $Project -Role $Role -Location $CurrentTargetRegion -LocationShortName $CurrentTargetRegionShortName -TimeInt $timeInt -ResourceGroupName $ResourceGroupName -Verbose
	}

	#region RBAC Assignment(s)
	#region aibRoleImageCreation.json creation and RBAC Assignment
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
	#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
	$aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
	#$aibRoleImageCreationPath = "aibRoleImageCreation.json"
	$aibRoleImageCreationPath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
	#Generate a unique file name 
	$aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

	# Download the config
	Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -Path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

	#region Create a role definition
	Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
	$RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath
	#endregion

	# Grant the role definition to the VM Image Builder service principal
	Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
	$Scope = $ResourceGroup.ResourceId
	<#
    if (-not(Get-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope)) {
        Write-Verbose -Message "Assigning the '$($RoleDefinition.Name)' RBAC role to the '$($AssignedIdentity.PrincipalId)' System Assigned Managed Identity"
        $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $Scope
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    } else {
        Write-Verbose -Message "The '$($RoleDefinition.Name)' RBAC role is already assigned to the '$($AssignedIdentity.PrincipalId)' System Assigned Managed Identity"
    } 
    #> 
	$Parameters = @{
		ObjectId           = $AssignedIdentity.PrincipalId
		RoleDefinitionName = $RoleDefinition.Name
		Scope              = $Scope
	}

	While (-not(Get-AzRoleAssignment @Parameters)) {
		Write-Verbose -Message "Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' System Assigned Managed Identity on the '$($Parameters.Scope)' scope"
		$RoleAssignment = New-AzRoleAssignment @Parameters
		Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
		if ($null -eq $RoleAssignment) {
			Write-Verbose -Message "Sleeping 30 seconds"
			Start-Sleep -Seconds 30
		}
	}
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

	#region Template via a image from the market place + customizations
	# create gallery definition
	$GalleryParams = @{
		GalleryName       = $GalleryName
		ResourceGroupName = $ResourceGroupName
		Location          = $location
		Name              = $imageDefName
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-posh" -f $SrcObjParams2.Publisher
		Offer             = "{0}-posh" -f $SrcObjParams2.Offer
		Sku               = "{0}-posh" -f $SrcObjParams2.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName' (From Powershell)..."
	$GalleryImageDefinition = New-AzGalleryImageDefinition @GalleryParams

	Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
	$srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams2 -PlatformImageSource

	<# 
    #Optional : Get Virtual Machine publisher, Image Offer, Sku and Image
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq $SrcObjParams2.Publisher}
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq $SrcObjParams2.Offer}
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq $SrcObjParams2.Sku}
    $AllImages = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending
    $LatestImage = $AllImages | Select-Object -First 1
    #>


	$disObjParams = @{
		SharedImageDistributor = $true
		GalleryImageId         = "$($GalleryImageDefinition.Id)/versions/$PMKGalleryImageVersionName"
		ArtifactTag            = @{Publisher = $SrcObjParams2.Publisher; Offer = $SrcObjParams2.Publisher; Sku = $SrcObjParams2.Publisher }

		# 1. Uncomment following line for a single region deployment.
		#ReplicationRegion = $location

		# 2. Uncomment following line if the custom image should be replicated to another region(s).
		TargetRegion           = $TargetRegionSettings

		RunOutputName          = $runOutputName
		ExcludeFromLatest      = $false
	}
	Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
	$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

	$ImgCustomParams = @{    
		PowerShellCustomizer = $true    
		Name                 = 'InstallVSCode'    
		RunElevated          = $true    
		runAsSystem          = $true    
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)' ..."
	$Customizer = New-AzImageBuilderTemplateCustomizerObject @ImgCustomParams 

	#Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
	$ImgTemplateParams = @{
		ImageTemplateName      = $imageTemplateName
		ResourceGroupName      = $ResourceGroupName
		Source                 = $srcPlatform
		Distribute             = $disSharedImg
		Customize              = $Customizer
		Location               = $location
		UserAssignedIdentityId = $AssignedIdentity.Id
		VMProfileVmsize        = "Standard_D4s_v5"
		VMProfileOsdiskSizeGb  = 127
		BuildTimeoutInMinute   = 240
	}
	Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName' Image Template Name ..."
	$ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

	#region Build the image
	#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName -AsJob
	#endregion
	#endregion
	
	#region Waiting for jobs to complete
	Write-Verbose -Message "Waiting for jobs to complete ..."
	$Jobs | Wait-Job | Out-Null
	#endregion

	#region imageTemplateName status
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatus = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName
	# Optional - if you have any errors running the preceding command, run:
	Write-Verbose -Message "'$imageTemplateName' ProvisioningErrorCode: $($getStatus.ProvisioningErrorCode) "
	Write-Verbose -Message "'$imageTemplateName' ProvisioningErrorMessage: $($getStatus.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Verbose -Message "'$imageTemplateName' LastRunStatusRunState: $($getStatus.LastRunStatusRunState) "
	Write-Verbose -Message "'$imageTemplateName' LastRunStatusMessage: $($getStatus.LastRunStatusMessage) "
	Write-Verbose -Message "'$imageTemplateName' LastRunStatusRunSubState: $($getStatus.LastRunStatusRunSubState) "
	if ($getStatus.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateName' has failed:\r\n$($getStatus.LastRunStatusMessage)"
	}
	Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName' ..."
	#$Jobs += $getStatus | Remove-AzImageBuilderTemplate -AsJob
	$getStatus | Remove-AzImageBuilderTemplate -NoWait
	#endregion

	#region Adding a Customer-managed key (CMK) version
	#From https://learn.microsoft.com/en-us/azure/virtual-machines/image-version-encryption#powershell
	#From https://learn.microsoft.com/en-us/powershell/module/az.compute/new-azgalleryimageversion?view=azps-10.3.0#example-10-add-a-new-image-version-with-encryption-in-multiple-regions
    #Tomorrow
	$CMKGalleryImageVersionName = "{0:yyyy.MM.dd}" -f $((Get-date).AddDays(1))
	$sourceImageId = (Get-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -GalleryImageDefinitionName $GalleryImageDefinition.Name).Id | Sort-Object -Descending | Select-Object -First 1
	$replicaCount = 1
    
	$GalleryImageVersionTargetRegions = foreach ($CurrentTargetRegion in $TargetRegions) {
		# Replication region(s) settings
		$CurrentTargetRegionDES = $CMKDiskEncryptionSetHT[$CurrentTargetRegion].Id
		$EncryptionCurrentGalleryImageVersionTargetRegionOS = @{ DiskEncryptionSetId = $CurrentTargetRegionDES }
		$EncryptionCurrentGalleryImageVersionTargetRegion = @{ OSDiskImage = $EncryptionCurrentGalleryImageVersionTargetRegionOS }
		$GalleryImageVersionTargetRegion = @{ Name = $CurrentTargetRegion; ReplicaCount = $replicaCount; StorageAccountType = 'Standard_LRS'; Encryption = $EncryptionCurrentGalleryImageVersionTargetRegion }
		$GalleryImageVersionTargetRegion
	}
    
	# Create images
	$GalleryImageVersion = New-AzGalleryImageVersion -ResourceGroupName $ResourceGroupName -GalleryName $GalleryName -GalleryImageDefinitionName $GalleryImageDefinition.Name -Name $CMKGalleryImageVersionName -Location $Location -SourceImageId $sourceImageId -TargetRegion $GalleryImageVersionTargetRegions
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
  
	#region Waiting for jobs to complete
	$Jobs | Wait-Job | Out-Null
	Write-Verbose -Message "Removing jobs ..."
	$Jobs | Remove-Job -Force
	return $Gallery
	#endregion
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

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion


#region To use Azure Image Builder, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = $RequiredResourceProviders = 'Microsoft.VirtualMachineImages', 'Microsoft.Storage', 'Microsoft.Compute', 'Microsoft.KeyVault', 'Microsoft.ManagedIdentity', 'Microsoft.Network', 'Microsoft.ContainerInstance'
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

$AzureComputeGallery = New-AzureComputeGallery -Location EastUS2 -TargetRegions EastUS2, CentralUS -Verbose
$AzureComputeGallery

$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Total Processing Time: $($TimeSpan.ToString())"

#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob
#endregion