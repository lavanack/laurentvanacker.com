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
#requires -Version 3.0 -Modules Az.Accounts, Az.ImageBuilder, Az.Compute

Param(
	[Parameter(Mandatory = $true)]
	[string]$GalleryId,
	[Parameter(Mandatory = $true)]
	[string]$UserAssignedManagedIdentityId,
	[Parameter(Mandatory = $false)]
	[string[]]$TargetRegions,
	[Parameter(Mandatory = $false)]
	[bool] $excludeFromLatest = $false
)

#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject "`$AzureContext: $AzureContext"
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject "`$AzureContext: $AzureContext"
$SubscriptionID = $AzureContext.Subscription.Id
Write-Output -InputObject "`$SubscriptionID: $subscriptionID"
#endregion

#region Parameters
Write-Output -InputObject "`$GalleryId: $GalleryId"
Write-Output -InputObject "`$UserAssignedManagedIdentityId: $UserAssignedManagedIdentityId"
Write-Output -InputObject "`$excludeFromLatest: $excludeFromLatest"
#endregion

#region Azure Gallery Image Definition Version
$Gallery = Get-AzGallery -ResourceId $GalleryId
$ResourceGroupName = $Gallery.ResourceGroupName
$UserAssignedManagedIdentity = Get-AzResource -ResourceId $UserAssignedManagedIdentityId
$AssignedIdentity = Get-AzUserAssignedIdentity -Name $UserAssignedManagedIdentity.Name -ResourceGroupName $UserAssignedManagedIdentity.ResourceGroupName
$Location = $Gallery.Location

if ([string]::IsNullOrEmpty($TargetRegions)) {
    $TargetRegions = @($Location)
}
elseif ($Location -notin $TargetRegions) {
	$TargetRegions += $Location
}

[array] $TargetRegionSettings = foreach ($CurrentTargetRegion in $TargetRegions) {
	@{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
}



#region Source Image 
$SrcObjParamsARM = @{
	Publisher = 'MicrosoftWindowsDesktop'
	Offer     = 'Windows-11'    
	Sku       = 'win11-25h2-avd'  
	Version   = 'latest'
}

$SrcObjParamsPowerShell = @{
	Publisher = 'MicrosoftWindowsDesktop'
	Offer     = 'Office-365'    
	Sku       = 'win11-25h2-avd-m365'  
	Version   = 'latest'
}
#endregion

#region Image template and definition names
#Image Market Place Image + customizations: VSCode
$imageDefinitionNameARM = "{0}-arm-softwares" -f $SrcObjParamsARM.Sku
$imageTemplateNameARM = "{0}-template-{1}" -f $imageDefinitionNameARM, $timeInt
Write-Output -InputObject "`$imageDefinitionNameARM: $imageDefinitionNameARM"
Write-Output -InputObject "`$imageTemplateNameARM: $imageTemplateNameARM"
$StagingResourceGroupNameARM = "IT_{0}_{1}_{2}" -f $ResourceGroupName, $imageTemplateNameARM.Substring(0, 13), (New-Guid).Guid
Write-Output -InputObject "`$StagingResourceGroupNameARM: $StagingResourceGroupNameARM"

#Image Market Place Image + customizations: VSCode
$imageDefinitionNamePowerShell = "{0}-posh-softwares" -f $SrcObjParamsPowerShell.Sku
$imageTemplateNamePowerShell = "{0}-template-{1}" -f $imageDefinitionNamePowerShell, $timeInt
Write-Output -InputObject "`$imageDefinitionNamePowerShell: $imageDefinitionNamePowerShell"
Write-Output -InputObject "`$imageTemplateNamePowerShell: $imageTemplateNamePowerShell"
$StagingResourceGroupNamePowerShell = "IT_{0}_{1}_{2}" -f $ResourceGroupName, $imageTemplateNamePowerShell.Substring(0, 13), (New-Guid).Guid
Write-Output -InputObject "`$StagingResourceGroupNamePowerShell: $StagingResourceGroupNamePowerShell"
#endregion

# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
$runOutputNameARM = "cgOutputARM"
$runOutputNamePowerShell = "cgOutputPowerShell"

$Version = Get-Date -UFormat "%Y.%m.%d"
Write-Output -InputObject "`$Version: $Version"

$Jobs = @()

#region Create resource group
if (Get-AzResourceGroup -Name $StagingResourceGroupNameARM -Location $Location -ErrorAction Ignore) {
	Write-Output -InputObject "Removing '$StagingResourceGroupNameARM' Resource Group Name ..."
	Remove-AzResource -Name $StagingResourceGroupNameARM -Force
}
Write-Output -InputObject "Creating '$StagingResourceGroupNameARM' Resource Group Name ..."
$StagingResourceGroupARM = New-AzResourceGroup -Name $StagingResourceGroupNameARM -Tag $Tags -Location $Location -Force

if (Get-AzResourceGroup -Name $StagingResourceGroupNamePowerShell -Location $Location -ErrorAction Ignore) {
	Write-Output -InputObject "Removing '$StagingResourceGroupNamePowerShell' Resource Group Name ..."
	Remove-AzResource -Name $StagingResourceGroupNamePowerShell -Force
}
Write-Output -InputObject "Creating '$StagingResourceGroupNamePowerShell' Resource Group Name ..."
$StagingResourceGroupPowerShell = New-AzResourceGroup -Name $StagingResourceGroupNamePowerShell -Location $Location -Tag $Tags -Force

$ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName
#endregion

#region RBAC Assignment(s)
#region RBAC Owner Role on both Staging Resource Groups
foreach ($CurrentStagingResourceGroup in $StagingResourceGroupARM, $StagingResourceGroupPowerShell) {
	$RoleDefinition = Get-AzRoleDefinition -Name "Contributor"
	$Parameters = @{
		ObjectId           = $AssignedIdentity.PrincipalId
		RoleDefinitionName = $RoleDefinition.Name
		Scope              = $CurrentStagingResourceGroup.ResourceId
	}
	while (-not(Get-AzRoleAssignment @Parameters)) {
		Write-Output -InputObject "Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
		try {
			$RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
		} 
		catch {
			$RoleAssignment = $null
		}
		Write-Output -InputObject "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
		Write-Output -InputObject "Sleeping 30 seconds"
		Start-Sleep -Seconds 30
	}
}
#endregion
#endregion

#endregion

#region Checking of Image version already exists
$Parameters = @{
	ResourceGroupName = $ResourceGroupName 
	GalleryName       = $Gallery.Name 
}
if ((Get-AzGalleryImageVersion @Parameters -GalleryImageDefinitionName $imageDefinitionNameARM).Name -eq $Version) {
	Write-Error "The '$Version' for the '$($imageDefinitionNameARM)' Image Definition already exists on '$($Parameters.GalleryName)' Azure Compute Gallery (ResourceGroup: '$($Parameters.ResourceGroupName)'). Processing Stopped !" -ErrorAction "Stop"
}
if ((Get-AzGalleryImageVersion @Parameters -GalleryImageDefinitionName $imageDefinitionNamePowerShell).Name -eq $Version) {
	Write-Error "The '$Version' for the '$($imageDefinitionNamePowerShell)' Image Definition already exists on '$($Parameters.GalleryName)' Azure Compute Gallery (ResourceGroup: '$($Parameters.ResourceGroupName)'). Processing Stopped !" -ErrorAction "Stop"
}
#endregion

#region Template #1 via a customized JSON file
#Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD

#region Download and configure the template
	#$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
	#$templateFilePath = "armTemplateWVD.json"
	$templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/armTemplateAVD-v14.json"
	$templateFilePath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $templateUrl -Leaf)
	#Generate a unique file name 
	$templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
	Write-Output -InputObject "`$templateFilePath: $templateFilePath  ..."

	Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

	((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $SubscriptionID) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
	#((Get-Content -Path $templateFilePath -Raw) -replace '<region>',$Location) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputNameARM) | Set-Content -Path $templateFilePath

	((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefinitionNameARM) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $Gallery.Name) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<excludeFromLatest>', $excludeFromLatest.ToString().ToLower()) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<TargetRegions>', $(ConvertTo-Json -InputObject $TargetRegionSettings)) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<stagingResourceGroupName>', $StagingResourceGroupNameARM) | Set-Content -Path $templateFilePath

	((Get-Content -Path $templateFilePath -Raw) -replace '<publisher>', $SrcObjParamsARM.Publisher) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<offer>', $SrcObjParamsARM.Offer) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<sku>', $SrcObjParamsARM.sku) | Set-Content -Path $templateFilePath
	#endregion

#region Create the gallery definition
	$GalleryParams = @{
		GalleryName       = $Gallery.Name
		ResourceGroupName = $ResourceGroupName
		Location          = $Location
		Name              = $imageDefinitionNameARM
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-arm" -f $SrcObjParamsARM.Publisher
		Offer             = "{0}-arm" -f $SrcObjParamsARM.Offer
		Sku               = "{0}-arm" -f $SrcObjParamsARM.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Output -InputObject "Creating Azure Compute Gallery Image Definition '$imageDefinitionNameARM' (From ARM)..."
	$GalleryImageDefinitionARM = New-AzGalleryImageDefinition @GalleryParams
	#endregion

#region Submit the template
	Write-Output -InputObject "Starting Resource Group Deployment from '$templateFilePath' ..."
	$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateNameARM; "svclocation" = $Location }  #-Tag $Tags
	
	#region Build the image
	Write-Output -InputObject "Starting Image Builder Template from '$imageTemplateNameARM' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNameARM -AsJob
	#endregion
	#endregion
#endregion

#region Template #2 via a image from the market place + customizations
	# create gallery definition
	$GalleryParams = @{
		GalleryName       = $Gallery.Name
		ResourceGroupName = $ResourceGroupName
		Location          = $Location
		Name              = $imageDefinitionNamePowerShell
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-posh" -f $SrcObjParamsPowerShell.Publisher
		Offer             = "{0}-posh" -f $SrcObjParamsPowerShell.Offer
		Sku               = "{0}-posh" -f $SrcObjParamsPowerShell.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Output -InputObject "Creating Azure Compute Gallery Image Definition '$imageDefinitionNamePowerShell' (From Powershell)..."
	$GalleryImageDefinitionPowerShell = New-AzGalleryImageDefinition @GalleryParams

	Write-Output -InputObject "Creating Azure Image Builder Template Source Object  ..."
	$srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParamsPowerShell -PlatformImageSource

	<# 
    #Optional : Get Virtual Machine publisher, Image Offer, Sku and Image
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq $SrcObjParamsPowerShell.Publisher}
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq $SrcObjParamsPowerShell.Offer}
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq $SrcObjParamsPowerShell.Sku}
    $AllImages = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending
    $LatestImage = $AllImages | Select-Object -First 1
    #>


	$disObjParams = @{
		SharedImageDistributor = $true
		GalleryImageId         = "$($GalleryImageDefinitionPowerShell.Id)/versions/$version"
		ArtifactTag            = @{Publisher = $SrcObjParamsPowerShell.Publisher; Offer = $SrcObjParamsPowerShell.Publisher; Sku = $SrcObjParamsPowerShell.Publisher }

		# 1. Uncomment following line for a single region deployment.
		#ReplicationRegion = $Location

		# 2. Uncomment following line if the custom image should be replicated to another region(s).
		TargetRegion           = $TargetRegionSettings

		RunOutputName          = $runOutputNamePowerShell
		ExcludeFromLatest      = $excludeFromLatest
	}
	Write-Output -InputObject "Creating Azure Image Builder Template Distributor Object  ..."
	$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

	$ImgTimeZoneRedirectionPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Timezone Redirection'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgTimeZoneRedirectionPowerShellCustomizerParams.Name)' ..."
	$TimeZoneRedirectionCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgTimeZoneRedirectionPowerShellCustomizerParams 

	$ImgPowerShellCrossPlatformPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install PowerShell Cross Platform'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/Install-PowerShell.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgPowerShellCrossPlatformPowerShellCustomizerParams.Name)' ..."
	$PowerShellCrossPlatformCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgPowerShellCrossPlatformPowerShellCustomizerParams 

	$ImgPuttyPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install Putty'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/Install-Putty.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgPuttyPowerShellCustomizerParams.Name)' ..."
	$PuttyCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgPuttyPowerShellCustomizerParams 

	$ImgWinSCPPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install WinSCP'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/Install-WinSCP.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgWinSCPPowerShellCustomizerParams.Name)' ..."
	$WinSCPCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgWinSCPPowerShellCustomizerParams 

	$ImgNotepadPlusPlusPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install Notepad++'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/Install-NotepadPlusPlus.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgNotepadPlusPlusPowerShellCustomizerParams.Name)' ..."
	$NotepadPlusPlusCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgNotepadPlusPlusPowerShellCustomizerParams 



	$ImgVSCodePowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Install Visual Studio Code'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20VM%20Image%20Builder/Install-VSCode.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)' ..."
	$VSCodeCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgVSCodePowerShellCustomizerParams 

	Write-Output -InputObject "Creating Azure Image Builder Template WindowsUpdate Customizer Object ..."
	$WindowsUpdateCustomizer = New-AzImageBuilderTemplateCustomizerObject -WindowsUpdateCustomizer -Name 'WindowsUpdate' -Filter @('exclude:$_.Title -like ''*Preview*''', 'include:$true') -SearchCriterion "IsInstalled=0" -UpdateLimit 40

	$ImgDisableAutoUpdatesPowerShellCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'Disable AutoUpdates'  
		RunElevated          = $true  
		runAsSystem          = $true  
		ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
	}

	Write-Output -InputObject "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgDisableAutoUpdatesPowerShellCustomizerParams.Name)' ..."
	$DisableAutoUpdatesCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgDisableAutoUpdatesPowerShellCustomizerParams 

	#Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
	$Customize = $TimeZoneRedirectionCustomizer, $PowerShellCrossPlatformCustomizer, $PuttyCustomizer, $WinSCPCustomizer, $NotepadPlusPlusCustomizer, $VSCodeCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer
	$ImgTemplateParams = @{
		ImageTemplateName      = $imageTemplateNamePowerShell
		ResourceGroupName      = $ResourceGroupName
		Source                 = $srcPlatform
		Distribute             = $disSharedImg
		Customize              = $Customize
		Location               = $Location
		UserAssignedIdentityId = $AssignedIdentity.Id
		VMProfileVmsize        = "Standard_D8s_v6"
		VMProfileOsdiskSizeGb  = 127
		BuildTimeoutInMinute   = 240
		StagingResourceGroup   = $StagingResourceGroupPowerShell.ResourceId
		#Tag                    = @{"SecurityControl"="Ignore"}
	}
	Write-Output -InputObject "Creating Azure Image Builder Template from '$imageTemplateNamePowerShell' Image Template Name ..."
	$ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

	#region Build the image
	#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
	Write-Output -InputObject "Starting Image Builder Template from '$imageTemplateNamePowerShell' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNamePowerShell -AsJob
	#endregion
	#endregion
	
#region Waiting for jobs to complete
	Write-Output -InputObject "Waiting for jobs to complete ..."
	#$Jobs | Wait-Job | Out-Null
	$null = $Jobs | Receive-Job -Wait -AutoRemoveJob
	#endregion

#region imageTemplateNameARM status 
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatusARM = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNameARM
	# Optional - if you have any errors running the preceding command, run:
	Write-Output -InputObject "'$imageTemplateNameARM' ProvisioningErrorCode: $($getStatusARM.ProvisioningErrorCode) "
	Write-Output -InputObject "'$imageTemplateNameARM' ProvisioningErrorMessage: $($getStatusARM.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Output -InputObject "'$imageTemplateNameARM' LastRunStatusRunState: $($getStatusARM.LastRunStatusRunState) "
	Write-Output -InputObject "'$imageTemplateNameARM' LastRunStatusMessage: $($getStatusARM.LastRunStatusMessage) "
	Write-Output -InputObject "'$imageTemplateNameARM' LastRunStatusRunSubState: $($getStatusARM.LastRunStatusRunSubState) "
	if ($getStatusARM.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateNameARM' has failed:\r\n$($getStatusARM.LastRunStatusMessage)"
	}
	Write-Output -InputObject "Removing Azure Image Builder Template for '$imageTemplateNameARM' ..."
	#$Jobs += $getStatusARM | Remove-AzImageBuilderTemplate -AsJob
	$getStatusARM | Remove-AzImageBuilderTemplate #-NoWait
	if ($aibRoleImageCreationPath) {
		Write-Output -InputObject "Removing '$aibRoleImageCreationPath' ..."
		Remove-Item -Path $aibRoleImageCreationPath -Force
	}
	Write-Output -InputObject "Removing '$templateFilePath' ..."
	Remove-Item -Path $templateFilePath -Force
	#endregion

#region imageTemplateNamePowerShell status
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatusPowerShell = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNamePowerShell
	# Optional - if you have any errors running the preceding command, run:
	Write-Output -InputObject "'$imageTemplateNamePowerShell' ProvisioningErrorCode: $($getStatusPowerShell.ProvisioningErrorCode) "
	Write-Output -InputObject "'$imageTemplateNamePowerShell' ProvisioningErrorMessage: $($getStatusPowerShell.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Output -InputObject "'$imageTemplateNamePowerShell' LastRunStatusRunState: $($getStatusPowerShell.LastRunStatusRunState) "
	Write-Output -InputObject "'$imageTemplateNamePowerShell' LastRunStatusMessage: $($getStatusPowerShell.LastRunStatusMessage) "
	Write-Output -InputObject "'$imageTemplateNamePowerShell' LastRunStatusRunSubState: $($getStatusPowerShell.LastRunStatusRunSubState) "
	if ($getStatusPowerShell.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateNamePowerShell' has failed:\r\n$($getStatusPowerShell.LastRunStatusMessage)"
	}
	Write-Output -InputObject "Removing Azure Image Builder Template for '$imageTemplateNamePowerShell' ..."
	#$Jobs += $getStatusPowerShell | Remove-AzImageBuilderTemplate -AsJob
	$getStatusPowerShell | Remove-AzImageBuilderTemplate #-NoWait
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
  
#region Removing Staging ResourceGroups
$null = Remove-AzResourceGroup -ResourceGroupName $StagingResourceGroupNameARM -Force -AsJob
$null = Remove-AzResourceGroup -ResourceGroupName $StagingResourceGroupNamePowerShell -Force -AsJob
#endregion

