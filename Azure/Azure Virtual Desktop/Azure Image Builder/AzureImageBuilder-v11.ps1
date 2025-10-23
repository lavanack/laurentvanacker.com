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

	#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
	$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
	$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
	#endregion

	#region Set up the environment and variables
	# get existing context
	$AzContext = Get-AzContext
	# Your subscription. This command gets your current subscription
	$subscriptionID = $AzContext.Subscription.Id

	#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
	#$AzureComputeGalleryPrefix = "acg"
	#$ResourceGroupPrefix = "rg"
	$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
	$AzureComputeGalleryPrefix = $ResourceTypeShortNameHT["Compute/galleries"].ShortName

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
	$SrcObjParamsARM = @{
		Publisher = 'MicrosoftWindowsServer'
		Offer     = 'WindowsServer'    
		Sku       = '2016-datacenter-gensecond'  
		Version   = 'latest'
	}

	$SrcObjParamsPowerShell = @{
		Publisher = 'MicrosoftWindowsServer'
		Offer     = 'WindowsServer'    
		Sku       = '2016-datacenter-gensecond'  
		Version   = 'latest'
	}
	#endregion

	#region Image template and definition names
	#Image Market Place Image + customizations: VSCode
	$imageDefinitionNameARM = "{0}-arm-vscode" -f $SrcObjParamsARM.Sku
	$imageTemplateNameARM = "{0}-template-{1}" -f $imageDefinitionNameARM, $timeInt
	Write-Verbose -Message "`$imageDefinitionNameARM: $imageDefinitionNameARM"
	Write-Verbose -Message "`$imageTemplateNameARM: $imageTemplateNameARM"
	$StagingResourceGroupNameARM = "IT_{0}_{1}_{2}" -f $ResourceGroupName, $imageTemplateNameARM.Substring(0, 13), (New-Guid).Guid


	#Image Market Place Image + customizations: VSCode
	$imageDefinitionNamePowerShell = "{0}-posh-vscode" -f $SrcObjParamsPowerShell.Sku
	$imageTemplateNamePowerShell = "{0}-template-{1}" -f $imageDefinitionNamePowerShell, $timeInt
	Write-Verbose -Message "`$imageDefinitionNamePowerShell: $imageDefinitionNamePowerShell"
	Write-Verbose -Message "`$imageTemplateNamePowerShell: $imageTemplateNamePowerShell"
	$StagingResourceGroupNamePowerShell = "IT_{0}_{1}_{2}" -f $ResourceGroupName, $imageTemplateNamePowerShell.Substring(0, 13), (New-Guid).Guid
	#endregion

	# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
	$runOutputNameARM = "cgOutputARM"
	$runOutputNamePowerShell = "cgOutputPowerShell"

	#$Version = "1.0.0"
	$Version = Get-Date -UFormat "%Y.%m.%d"
    if ($MyInvocation.MyCommand.ModuleName) {
        $Module = (Get-Module -Name $MyInvocation.MyCommand.ModuleName).Name
        $Tags =  @{
            "SecurityControl" = "Ignore"
            "Module" = $Module
        }
    } 
    else {
        $Script = $(Split-Path -Path $MyInvocation.ScriptName -Leaf)
        $Tags =  @{
            "SecurityControl" = "Ignore"
            "Script" = $Script
        }
    }
	$Jobs = @()
	#endregion

	#region Create resource group
	if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
		Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
		Remove-AzResourceGroup -Name $ResourceGroupName -Force
	}
	Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
	$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Tag $Tags -Force

	if (Get-AzResourceGroup -Name $StagingResourceGroupNameARM -Location $location -ErrorAction Ignore) {
		Write-Verbose -Message "Removing '$StagingResourceGroupNameARM' Resource Group Name ..."
		Remove-AzResource -Name $StagingResourceGroupNameARM -Force
	}
	Write-Verbose -Message "Creating '$StagingResourceGroupNameARM' Resource Group Name ..."
	$StagingResourceGroupARM = New-AzResourceGroup -Name $StagingResourceGroupNameARM -Tag $Tags -Location $location -Force

	if (Get-AzResourceGroup -Name $StagingResourceGroupNamePowerShell -Location $location -ErrorAction Ignore) {
		Write-Verbose -Message "Removing '$StagingResourceGroupNamePowerShell' Resource Group Name ..."
		Remove-AzResource -Name $StagingResourceGroupNamePowerShell -Force
	}
	Write-Verbose -Message "Creating '$StagingResourceGroupNamePowerShell' Resource Group Name ..."
	$StagingResourceGroupPowerShell = New-AzResourceGroup -Name $StagingResourceGroupNamePowerShell -Location $location -Tag $Tags -Force
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
		try {
			$RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
		} 
		catch {
			$RoleAssignment = $null
		}
		Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
		if ($null -eq $RoleAssignment) {
			Write-Verbose -Message "Sleeping 30 seconds"
			Start-Sleep -Seconds 30
		}
	}
	#endregion

	#region RBAC Owner Role on both Staging Resource Groups
	foreach ($CurrentStagingResourceGroup in $StagingResourceGroupARM, $StagingResourceGroupPowerShell) {
		$RoleDefinition = Get-AzRoleDefinition -Name "Contributor"
		$Parameters = @{
			ObjectId           = $AssignedIdentity.PrincipalId
			RoleDefinitionName = $RoleDefinition.Name
			Scope              = $CurrentStagingResourceGroup.ResourceId
		}
		while (-not(Get-AzRoleAssignment @Parameters)) {
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.Scope)' scope"
			try {
				$RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Stop
			} 
			catch {
				$RoleAssignment = $null
			}
			Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
			Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
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
	$templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD-v11.json"
	$templateFilePath = Join-Path -Path $env:TEMP -ChildPath $(Split-Path $templateUrl -Leaf)
	#Generate a unique file name 
	$templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
	Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

	Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

	((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
	#((Get-Content -Path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputNameARM) | Set-Content -Path $templateFilePath

	((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefinitionNameARM) | Set-Content -Path $templateFilePath
	((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
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
		GalleryName       = $GalleryName
		ResourceGroupName = $ResourceGroupName
		Location          = $location
		Name              = $imageDefinitionNameARM
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-arm" -f $SrcObjParamsARM.Publisher
		Offer             = "{0}-arm" -f $SrcObjParamsARM.Offer
		Sku               = "{0}-arm" -f $SrcObjParamsARM.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefinitionNameARM' (From ARM)..."
	$GalleryImageDefinitionARM = New-AzGalleryImageDefinition @GalleryParams
	#endregion

	#region Submit the template
	Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
	$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateNameARM; "svclocation" = $location }  #-Tag $Tags
	
	#region Build the image
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateNameARM' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNameARM -AsJob
	#endregion
	#endregion
	#endregion

	#region Template #2 via a image from the market place + customizations
	# create gallery definition
	$GalleryParams = @{
		GalleryName       = $GalleryName
		ResourceGroupName = $ResourceGroupName
		Location          = $location
		Name              = $imageDefinitionNamePowerShell
		OsState           = 'generalized'
		OsType            = 'Windows'
		Publisher         = "{0}-posh" -f $SrcObjParamsPowerShell.Publisher
		Offer             = "{0}-posh" -f $SrcObjParamsPowerShell.Offer
		Sku               = "{0}-posh" -f $SrcObjParamsPowerShell.Sku
		HyperVGeneration  = 'V2'
	}
	Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefinitionNamePowerShell' (From Powershell)..."
	$GalleryImageDefinitionPowerShell = New-AzGalleryImageDefinition @GalleryParams

	Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
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
		#ReplicationRegion = $location

		# 2. Uncomment following line if the custom image should be replicated to another region(s).
		TargetRegion           = $TargetRegionSettings

		RunOutputName          = $runOutputNamePowerShell
		ExcludeFromLatest      = $false
	}
	Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
	$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

	$ImgCopySetTLSFileCustomizerParams = @{  
		FileCustomizer = $true  
		Name           = 'CopySetTLS'  
		sourceUri      = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Set-TLS12.ps1'
		destination    = "C:\AVDImage\Set-TLS12.ps1"
	}

	Write-Verbose -Message "Creating Azure Image Builder Template Customizer Object for copying 'Set-TLS12.ps1' from the RDS-Templates Github repository ..."
	$CopySetTLSCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgCopySetTLSFileCustomizerParams 

	$ImgSetTLSFileCustomizerParams = @{  
		PowerShellCustomizer = $true  
		Name                 = 'SetTLS'  
		RunElevated          = $true  
		runAsSystem          = $true
		inline               = "C:\AVDImage\Set-TLS12.ps1 -DisableLegacyTls"
	}
	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for running 'Set-TLS12.ps1' ..."
	$SetTLSCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgSetTLSFileCustomizerParams 

	$ImgWindowsRestartCustomizerParams = @{  
		RestartCustomizer   = $true  
		Name                = 'WindowsRestart'
		RestartCheckCommand = 'powershell -Command "& {Write-Output "restarted."}"'
		RestartCommand      = 'powershell -Command "& {Restart-Computer -Force}"'
		RestartTimeout      = '10m'
	}

	Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgWindowsRestartCustomizerParams.Name)' ..."
	$WindowsRestartCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgWindowsRestartCustomizerParams 

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
	$Customize = $CopySetTLSCustomizer, $SetTLSCustomizer, $WindowsRestartCustomizer, $TimeZoneRedirectionCustomizer, $VSCodeCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer
	$ImgTemplateParams = @{
		ImageTemplateName      = $imageTemplateNamePowerShell
		ResourceGroupName      = $ResourceGroupName
		Source                 = $srcPlatform
		Distribute             = $disSharedImg
		Customize              = $Customize
		Location               = $location
		UserAssignedIdentityId = $AssignedIdentity.Id
		VMProfileVmsize        = "Standard_D4s_v5"
		VMProfileOsdiskSizeGb  = 127
		BuildTimeoutInMinute   = 240
		StagingResourceGroup   = $StagingResourceGroupPowerShell.ResourceId
		#Tag                    = @{"SecurityControl"="Ignore"}
	}
	Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateNamePowerShell' Image Template Name ..."
	$ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

	#region Build the image
	#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
	Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateNamePowerShell' (As Job) ..."
	$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNamePowerShell -AsJob
	#endregion
	#endregion
	
	#region Waiting for jobs to complete
	Write-Verbose -Message "Waiting for jobs to complete ..."
	#$Jobs | Wait-Job | Out-Null
	$null = $Jobs | Receive-Job -Wait -AutoRemoveJob
	#endregion

	#region imageTemplateNameARM status 
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatusARM = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNameARM
	# Optional - if you have any errors running the preceding command, run:
	Write-Verbose -Message "'$imageTemplateNameARM' ProvisioningErrorCode: $($getStatusARM.ProvisioningErrorCode) "
	Write-Verbose -Message "'$imageTemplateNameARM' ProvisioningErrorMessage: $($getStatusARM.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Verbose -Message "'$imageTemplateNameARM' LastRunStatusRunState: $($getStatusARM.LastRunStatusRunState) "
	Write-Verbose -Message "'$imageTemplateNameARM' LastRunStatusMessage: $($getStatusARM.LastRunStatusMessage) "
	Write-Verbose -Message "'$imageTemplateNameARM' LastRunStatusRunSubState: $($getStatusARM.LastRunStatusRunSubState) "
	if ($getStatusARM.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateNameARM' has failed:\r\n$($getStatusARM.LastRunStatusMessage)"
	}
	Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateNameARM' ..."
	#$Jobs += $getStatusARM | Remove-AzImageBuilderTemplate -AsJob
	$getStatusARM | Remove-AzImageBuilderTemplate #-NoWait
	Write-Verbose -Message "Removing '$aibRoleImageCreationPath' ..."
	Write-Verbose -Message "Removing '$templateFilePath' ..."
	Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
	#endregion

	#region imageTemplateNamePowerShell status
	#To determine whenever or not the template upload process was successful, run the following command.
	$getStatusPowerShell = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNamePowerShell
	# Optional - if you have any errors running the preceding command, run:
	Write-Verbose -Message "'$imageTemplateNamePowerShell' ProvisioningErrorCode: $($getStatusPowerShell.ProvisioningErrorCode) "
	Write-Verbose -Message "'$imageTemplateNamePowerShell' ProvisioningErrorMessage: $($getStatusPowerShell.ProvisioningErrorMessage) "
	# Shows the status of the build
	Write-Verbose -Message "'$imageTemplateNamePowerShell' LastRunStatusRunState: $($getStatusPowerShell.LastRunStatusRunState) "
	Write-Verbose -Message "'$imageTemplateNamePowerShell' LastRunStatusMessage: $($getStatusPowerShell.LastRunStatusMessage) "
	Write-Verbose -Message "'$imageTemplateNamePowerShell' LastRunStatusRunSubState: $($getStatusPowerShell.LastRunStatusRunSubState) "
	if ($getStatusPowerShell.LastRunStatusRunState -eq "Failed") {
		Write-Error -Message "The Image Builder Template for '$imageTemplateNamePowerShell' has failed:\r\n$($getStatusPowerShell.LastRunStatusMessage)"
	}
	Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateNamePowerShell' ..."
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

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion


#region To use Azure Image Builder, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = 'Microsoft.VirtualMachineImages', 'Microsoft.Storage', 'Microsoft.Compute', 'Microsoft.KeyVault', 'Microsoft.ManagedIdentity', 'Microsoft.Network', 'Microsoft.ContainerInstance'
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