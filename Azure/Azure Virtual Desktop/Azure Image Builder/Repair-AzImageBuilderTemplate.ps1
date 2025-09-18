Clear-Host
$Location = "eastus2"
$SubscriptionId = (Get-Azcontext).Subscription.Id

$TimeStamp = 1758172426
$ResourceGroupName = "rg-avd-aib-use2-$TimeStamp"
$TemplateName = "win11-24h2-avd-json-vscode-template-$TimeStamp"
$UserAssignedManagedIdentityName = "aibIdentity-$TimeStamp"
$UserAssignedManagedIdentityId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$UserAssignedManagedIdentityName"
$UserAssignedIdentity = New-AzUserAssignedIdentity -Name $UserAssignedManagedIdentityName -ResourceGroupName $ResourceGroupName -Location $Location

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -Location $Location
$ImageBuilderTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName

$CmdLine = "az image builder identity remove -g $ResourceGroupName -n $TemplateName --user-assigned $UserAssignedManagedIdentityId --yes"
$CmdLine | Set-Clipboard
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine -Wait

#region RBAC Contributor Role for the UAMI on Resource Group
$RoleDefinition = Get-AzRoleDefinition -Name "Contributor"
$Parameters = @{
	ObjectId           = $UserAssignedIdentity.PrincipalId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $ResourceGroup.ResourceId
}
while (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.PrincipalId)' Identity on the '$($Parameters.Scope)' scope"
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
#endregion


foreach ($CurrentGalleryImageId in $ImageBuilderTemplate.Distribute.GalleryImageId) {
    if ($CurrentGalleryImageId -match "^.*/galleries/(?<acg>.*)/images/(?<template>.*)/versions/(?<version>.*)$") {
        $CurrentTemplateName = $Matches['template']
        $CurrentTemplateVersion = $Matches['version']
        $CurrentAzureComputeGalleryName = $Matches['acg']

    	$CurrentAzureComputeGallery = New-AzGallery -GalleryName $CurrentAzureComputeGalleryName -ResourceGroupName $ResourceGroupName -Location $location


        $GalleryImageDefinition = Get-AzGalleryImageDefinition -ResourceGroupName $ResourceGroupName -GalleryName $CurrentAzureComputeGalleryName -Name $CurrentTemplateName -ErrorAction Ignore
        if (-not($GalleryImageDefinition)) {
	        $GalleryParams = @{
		        GalleryName       = $CurrentAzureComputeGalleryName
		        ResourceGroupName = $ResourceGroupName
		        Location          = $location
		        Name              = $CurrentTemplateName
		        OsState           = 'generalized'
		        OsType            = 'Windows'
		        Publisher         = "{0}-json" -f $SrcObjParams.Publisher
		        Offer             = "{0}-json" -f $SrcObjParams.Offer
		        Sku               = "{0}-json" -f $SrcObjParams.Sku
		        HyperVGeneration  = 'V2'
	        }
    	    Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$CurrentTemplateName' (From Powershell) ..."
	        $GalleryImageDefinition = New-AzGalleryImageDefinition @GalleryParams
        }
        else {
    	    Write-Verbose -Message "The Azure Compute Gallery Image Definition '$CurrentTemplateName' already exists ..."
        }
        $GalleryImageDefinition

        $TargetRegion = @(@{Name=$Location; ReplicaCount=1})
        $Parameters = @{
          ResourceGroupName = $ResourceGroupName
          GalleryName = $CurrentAzureComputeGalleryName
          GalleryImageDefinitionName = $CurrentTemplateName
          Name = $CurrentTemplateVersion
          Location = $Location
          TargetRegion = $TargetRegion
          sourceImageId = $CurrentGalleryImageId
        }
        # Create the new image version
        New-AzGalleryImageVersion @Parameters -ErrorAction Ignore

<#
    	$runOutputName = "cgOutput"
        [string[]]$TargetRegions = @($Location)

	    Write-Verbose -Message "`$TargetRegions: $($TargetRegions -join ', ')"
	    [array] $TargetRegionSettings = foreach ($CurrentTargetRegion in $TargetRegions) {
		    @{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
	    }

	    $disObjParams = @{
		    SharedImageDistributor = $true
		    GalleryImageId         = "$($GalleryImageDefinition.Id)/versions/$CurrentTemplateVersion"
		    ArtifactTag            = @{Publisher = $SrcObjParams.Publisher; Offer = $SrcObjParams.Publisher; Sku = $SrcObjParams.Publisher }

		    # 1. Uncomment following line for a single region deployment.
		    #ReplicationRegion = $location

		    # 2. Uncomment following line if the custom image should be replicated to another region(s).
		    TargetRegion           = $TargetRegionSettings

		    RunOutputName          = $runOutputName
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

	    $SrcObjParams = @{
		    Publisher = 'MicrosoftWindowsDesktop'
		    Offer     = 'Office-365'    
		    Sku       = 'win11-24h2-avd-m365'  
		    Version   = 'latest'
	    }
    	Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
	    $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams -PlatformImageSource

        $Customize = $TimeZoneRedirectionCustomizer
    	$ImgTemplateParams = @{
		    ImageTemplateName      = $CurrentTemplateName
		    ResourceGroupName      = $ResourceGroupName
		    Source                 = $srcPlatform
		    Distribute             = $disSharedImg
		    Location               = $location
		    Customize              = $Customize       
		    UserAssignedIdentityId = $UserAssignedIdentity.Id
		    VMProfileVmsize        = "Standard_D4s_v5"
		    VMProfileOsdiskSizeGb  = 127
		    BuildTimeoutInMinute   = 240
	    }
	    Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
	    $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams
#>
    }
}


$CmdLine = "az image builder identity assign -g $ResourceGroupName -n $TemplateName --user-assigned $UserAssignedManagedIdentityId" | Set-Clipboard
$CmdLine | Set-Clipboard
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CmdLine -Wait

