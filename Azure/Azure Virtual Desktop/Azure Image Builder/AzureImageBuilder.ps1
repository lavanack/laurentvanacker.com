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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.ManagedServiceIdentity, Az.Resources -RunAsAdministrator 

#FROM https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    [Parameter(Mandatory = $false)]
    [string[]]$ReplicationRegions = "eastus2"
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
  $timeInt = (Get-Date -UFormat "%s").Split(".")[0]

  #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
  $AzureComputeGalleryPrefix = "acg"
  $ResourceGroupPrefix = "rg"

  # Location (see possible locations in the main docs)
  #$Location = "eastus"
  Write-Verbose -Message "`$Location: $Location"
  $LocationShortName = $shortNameHT[$Location].shortName
  Write-Verbose -Message "`$LocationShortName: $LocationShortName"
  #$ReplicationRegions = "eastus2"
  Write-Verbose -Message "`$ReplicationRegions: $($ReplicationRegions -join ', ')"

  $Project = "avd"
  $Role = "aib"
  $TimeInt = (Get-Date -UFormat "%s").Split(".")[0]
  $ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
  $ResourceGroupName = $ResourceGroupName.ToLower()
  Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"

  # Image template and definition names
  #AVD MultiSession Session Image Market Place Image + customizations: VSCode
  $imageDefName01 = "win11-22h2-ent-avd-custom-vscode"
  $imageTemplateName01 = $imageDefName01 + "-template-" + $timeInt
  #AVD MultiSession + Microsoft 365 Market Place Image + customizations: VSCode
  $imageDefName02 = "win11-22h2-ent-avd-m365-vscode"
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
  #endregion
  #endregion

  # Create resource group
  if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
    Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
  }
  Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
  $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

  #region Permissions, user identity, and role
  # setup role def names, these need to be unique
  $imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
  $identityName = "aibIdentity-$timeInt"
  Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
  Write-Verbose -Message "`$identityName: $identityName"


  # Create the identity
  Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
  $AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location

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

  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
  ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

  # Create a role definition
  Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
  $RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

  # Grant the role definition to the VM Image Builder service principal
  Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
  Do
  {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
    $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
  } While ($null -eq $RoleAssignment)
  
  <#
  While (-not(Get-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId))
  {
      Start-Sleep -Seconds 10
  }
  #>

  #To allow Azure VM Image Builder to distribute images to either the managed images or to a Azure Compute Gallery, you will need to provide Contributor permissions for the service "Azure Virtual Machine Image Builder" (ApplicationId: cf32a0cc-373c-47c9-9156-0db11f6a6dfc) on the resource group.
  # assign permissions for the resource group, so that AIB can distribute the image to it
  <#
  Install-Module -Name AzureAD -Force
  Connect-AzureAD
  $ApplicationId = (Get-AzureADServicePrincipal -SearchString "Azure Virtual Machine Image Builder").AppId
  #>
  #New-AzRoleAssignment -ApplicationId cf32a0cc-373c-47c9-9156-0db11f6a6dfc -Scope $ResourceGroup.ResourceId -RoleDefinitionName Contributor
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
  $GalleryImageDefinition01 = New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'avd-win11-custom' -HyperVGeneration V2

  #region Download and configure the template
  #$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
  #$templateFilePath = "armTemplateWVD.json"
  $templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD.json"
  $templateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $templateUrl -Leaf)
  #Generate a unique file name 
  $templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
  Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

  Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

  ((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
  #((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

  ((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<region1>', $replicationRegions) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
  ((Get-Content -path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
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
    Sku               = 'avd-win11-m365'
    HyperVGeneration  = 'V2'
  }
  Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From A Market Place Image)..."
  $GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

  $SrcObjParams = @{
    PlatformImageSource = $true
    Publisher           = 'MicrosoftWindowsDesktop'
    Offer               = 'Office-365'    
    Sku                 = 'win11-22h2-avd-m365'  
    Version             = 'latest'
  }
  Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
  $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

  $disObjParams = @{
    SharedImageDistributor = $true
    GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
    ArtifactTag            = @{source = 'avd-win11'; baseosimg = 'windows11' }

    # 1. Uncomment following line for a single region deployment.
    #ReplicationRegion = $location

    # 2. Uncomment following line if the custom image should be replicated to another region(s).
    ReplicationRegion      = @($location) + $replicationRegions

    RunOutputName          = $runOutputName02
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

  Write-Verbose -Message "Creating Azure Image Builder Template Customizer Object  ..."
  $Customizer = New-AzImageBuilderTemplateCustomizerObject @ImgCustomParams 

  #Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
  $ImgTemplateParams = @{
    ImageTemplateName      = $imageTemplateName02
    ResourceGroupName      = $ResourceGroupName
    Source                 = $srcPlatform
    Distribute             = $disSharedImg
    Customize              = $Customizer
    Location               = $location
    UserAssignedIdentityId = $AssignedIdentity.Id
    VMProfileVmsize        = "Standard_D4s_v3"
    VMProfileOsdiskSizeGb  = 127
  }
  Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
  $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

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
  Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01' ..."
  $null = $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
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
  #endregion

  Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02' ..."
  $null = $getStatus02 | Remove-AzImageBuilderTemplate -AsJob
  Write-Verbose -Message "Removing jobs ..."
  $Jobs | Remove-Job
  #endregion

  $EndTime = Get-Date
  $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
  Write-Verbose -Message "Total Processing Time: $($TimeSpan.ToString())"
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
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.Storage
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.Compute
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.KeyVault
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity

#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages, Microsoft.Storage, Microsoft.Compute, Microsoft.KeyVault, Microsoft.ManagedIdentity | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
  Write-Verbose -Message "Sleeping 10 seconds ..."
  Start-Sleep -Seconds 10
}

$AzureComputeGallery = New-AzureComputeGallery -Verbose
$AzureComputeGallery
(Get-AzGalleryImageDefinition -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName).Id | Get-Random
#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob
#endregion