﻿<#
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
		Publisher = 'MicrosoftWindowsDesktop'
		Offer     = 'Windows-11'    
		Sku       = 'win11-24h2-avd'  
		Version   = 'latest'
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
	$imageDefName01 = "{0}-json-vscode" -f $SrcObjParams1.Sku
	$imageTemplateName01 = "{0}-template-{1}" -f $imageDefName01, $timeInt
	Write-Verbose -Message "`$imageDefName01: $imageDefName01"
	Write-Verbose -Message "`$imageTemplateName01: $imageTemplateName01"

	#Image Market Place Image + customizations: VSCode
	$imageDefName02 = "{0}-posh-vscode" -f $SrcObjParams2.Sku
	$imageTemplateName02 = "{0}-template-{1}" -f $imageDefName02, $timeInt
	Write-Verbose -Message "`$imageDefName02: $imageDefName02"
	Write-Verbose -Message "`$imageTemplateName02: $imageTemplateName02"
	#endregion

	# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
	$runOutputName01 = "cgOutput01"
	$runOutputName02 = "cgOutput02"

	#$Version = "1.0.0"
	$Version = Get-Date -UFormat "%Y.%m.%d"
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
	$AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location
	#endregion

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

	#region Template #1 via a customized JSON file
	#Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD

	#region Download and configure the template
	#$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
	#$templateFilePath = "armTemplateWVD.json"
	$templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD-v8.json"
	$templateFilePath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $templateUrl -Leaf)
	#Generate a unique file name 
	$templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

	Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

    ((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
	#((Get-Content -Path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

    ((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<TargetRegions>', $(ConvertTo-Json -InputObject $TargetRegionSettings)) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath

    ((Get-Content -Path $templateFilePath -Raw) -replace '<publisher>', $SrcObjParams1.Publisher) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<offer>', $SrcObjParams1.Offer) | Set-Content -Path $templateFilePath
    ((Get-Content -Path $templateFilePath -Raw) -replace '<sku>', $SrcObjParams1.sku) | Set-Content -Path $templateFilePath
	#endregion

	#region Create the gallery definition
	$GalleryParams = @{
		GalleryName       = $GalleryName
		ResourceGroupName = $ResourceGroupName
		Location          = $location
		Name              = $imageDefName01
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-json" -f $SrcObjParams2.Publisher
		Offer             = "{0}-json" -f $SrcObjParams2.Offer
		Sku               = "{0}-json" -f $SrcObjParams2.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName01' (From Customized JSON)..."
	$Result = (Get-Content -Path $templateFilePath -Raw) -replace "`r|`n" -replace "\s+", ' ' -match '"source".*(?<Source>{.*}),\s+"customize"'
	if ($Result) {
		$Source = $Matches["Source"] | ConvertFrom-Json
		$GalleryImageDefinition01 = New-AzGalleryImageDefinition @GalleryParams
	}
	else {
		$GalleryParams = @{
			$GalleryParams['Publisher'] = 'Contoso'
			$GalleryParams['Offer']     = 'Windows'
			$GalleryParams['Sku']       = 'Windows Client'
		}
		$GalleryImageDefinition01 = New-AzGalleryImageDefinition @GalleryParams
	}
	#endregion

	#region Submit the template
	Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
	$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateName01; "svclocation" = $location }

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
		Publisher         = "{0}-posh" -f $SrcObjParams2.Publisher
		Offer             = "{0}-posh" -f $SrcObjParams2.Offer
		Sku               = "{0}-posh" -f $SrcObjParams2.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From Powershell)..."
	$GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

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
		GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
		ArtifactTag            = @{Publisher = $SrcObjParams2.Publisher; Offer = $SrcObjParams2.Publisher; Sku = $SrcObjParams2.Publisher }

		# 1. Uncomment following line for a single region deployment.
		#ReplicationRegion = $location

		# 2. Uncomment following line if the custom image should be replicated to another region(s).
		TargetRegion           = $TargetRegionSettings

		RunOutputName          = $runOutputName02
		ExcludeFromLatest      = $false
	}
	Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
	$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

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

	$ImgMOMAgentPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install MOM Agent'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-MOMAgent.ps1'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgMOMAgentPowerShellCustomizerParams.Name)' ..."
	$MOMAgentCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgMOMAgentPowerShellCustomizerParams 

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
	$Customize = $TimeZoneRedirectionCustomizer, $VSCodeCustomizer, $MOMAgentCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer
	$ImgTemplateParams = @{
		ImageTemplateName      = $imageTemplateName02
		ResourceGroupName      = $ResourceGroupName
		Source                 = $srcPlatform
		Distribute             = $disSharedImg
		Customize              = $Customize
		Location               = $location
		UserAssignedIdentityId = $AssignedIdentity.Id
		VMProfileVmsize        = "Standard_D4s_v5"
		VMProfileOsdiskSizeGb  = 127
		BuildTimeoutInMinute   = 240
	}
	Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
	$ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

	#region Build the image
	#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
	#endregion
	#endregion
	
	#region Waiting for jobs to complete
	Write-Verbose -Message "Waiting for jobs to complete ..."
	$Jobs | Wait-Job | Out-Null
	#endregion

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