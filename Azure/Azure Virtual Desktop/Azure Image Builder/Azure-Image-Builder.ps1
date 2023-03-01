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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.ManagedServiceIdentity, Az.Resources -RunAsAdministrator 

#FROM https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD

Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

# Connect to Azure with a browser sign in token
Connect-AzAccount

#Select the right subscription
Get-AzSubscription | Out-GridView -OutputMode Single 


#To use Azure Image Builder, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages
Register-AzResourceProvider -ProviderNamespace Microsoft.Storage
Register-AzResourceProvider -ProviderNamespace Microsoft.Compute
Register-AzResourceProvider -ProviderNamespace Microsoft.KeyVault
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity

#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages, Microsoft.Storage, Microsoft.Compute, Microsoft.KeyVault, Microsoft.ManagedIdentity | Where-Object -FilterScript {$_.RegistrationState -ne 'Registered'})
{
    Start-Sleep -Seconds 10
}

#region Set up the environment and variables
# Step 1: Import module
Import-Module Az.Accounts

# Step 2: get existing context
$currentAzContext = Get-AzContext

# Destination image resource group
$imageResourceGroup="AVD-AZIMG-RG"

# Location (see possible locations in the main docs)
$location="eastus"

# Your subscription. This command gets your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

# Image template and definition names
#Fully Customized image
$imageDefName01      = "avd-win11-22h2-ent-fslogix-teams-vscode"
#$imageTemplateName01 = "avd-win11-22h2-ent-fslogix-teams-vscode-template"
$imageTemplateName01 = $imageDefName01 + "-template"
#Market place image + customization(s)
$imageDefName02      = "avd-win11-22h2-avd-m365-vscode"
#$imageTemplateName02 = "avd-win11-22h2-avd-m365-vscode-template"
$imageTemplateName02 = $imageDefName02 + "-template"

# Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
$runOutputName01="cgOutput01"
$runOutputName02="cgOutput02"

$Version = "1.0.0"

# Create resource group
if (Get-AzResourceGroup -Name $imageResourceGroup -Location $location -ErrorAction Ignore)
{
    Remove-AzResourceGroup -Name $imageResourceGroup -Force
}
New-AzResourceGroup -Name $imageResourceGroup -Location $location -Force
#endregion

#region Permissions, user identity, and role
# setup role def names, these need to be unique
$timeInt=(Get-Date -UFormat "%s").Split(".")[0]
$imageRoleDefName="Azure Image Builder Image Def"+$timeInt
$identityName="aibIdentity"+$timeInt

# Create the identity
New-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName -Location $location

$identityNameResourceId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).Id
$identityNamePrincipalId=$(Get-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName).PrincipalId


#$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
#$aibRoleImageCreationPath = "aibRoleImageCreation.json"
$aibRoleImageCreationPath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
#Generate a unique file name 
$aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"

# Download the config
Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $imageResourceGroup) | Set-Content -Path $aibRoleImageCreationPath
((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

# Create a role definition
New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

Do {
    # wait for role creation
    Start-Sleep -Seconds 30
} While (-not(Get-AzRoleDefinition -Name $imageRoleDefName))

# Grant the role definition to the VM Image Builder service principal
New-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $imageRoleDefName -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"
<#
While (-not(Get-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $imageRoleDefName -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"))
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
#New-AzRoleAssignment -ApplicationId cf32a0cc-373c-47c9-9156-0db11f6a6dfc -Scope /subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup -RoleDefinitionName Contributor
#endregion

#region Create an Azure Compute Gallery
$cgGalleryName= "AVD_ACG"

# Create the gallery
New-AzGallery -GalleryName $cgGalleryName -ResourceGroupName $imageResourceGroup  -Location $location

#region Template #1 via a customized JSON file
# Create the gallery definition
New-AzGalleryImageDefinition -GalleryName $cgGalleryName -ResourceGroupName $imageResourceGroup -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'avd-win11' -HyperVGeneration V2

#region Download and configure the template
#$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
#$templateFilePath = "armTemplateWVD.json"
$templateUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/armTemplateAVD.json"
$templateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $templateUrl -Leaf)
#Generate a unique file name 
$templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"

Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<rgName>',$imageResourceGroup) | Set-Content -Path $templateFilePath
#((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>',$runOutputName01) | Set-Content -Path $templateFilePath

((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>',$imageDefName01) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>',$cgGalleryName) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<region1>',$location) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>',$identityNameResourceId) | Set-Content -Path $templateFilePath
((Get-Content -path $templateFilePath -Raw) -replace '<version>',$version) | Set-Content -Path $templateFilePath
#endregion

#region Submit the template
New-AzResourceGroupDeployment -ResourceGroupName $imageResourceGroup -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2020-02-14"} -imageTemplateName $imageTemplateName01 -svclocation $location

#To determine whenever or not the template upload process was successful, run the following command.
$getStatus01=$(Get-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName01)
$getStatus01
# Optional - if you have any errors running the preceding command, run:
$getStatus01.ProvisioningErrorCode 
$getStatus01.ProvisioningErrorMessage

#region Build the image
Start-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName01 #-NoWait
$getStatus01=$(Get-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName01)

# Shows all the properties
$getStatus01 | Format-List -Property *

# Shows the status of the build
$getStatus01.LastRunStatusRunState 
$getStatus01.LastRunStatusMessage
$getStatus01.LastRunStatusRunSubState
#endregion

$getStatus01 | Remove-AzImageBuilderTemplate
Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
#endregion
#endregion

#region Template #2 via a image from the market place + customizations

# create gallery definition
$GalleryParams = @{
  GalleryName = $cgGalleryName
  ResourceGroupName = $imageResourceGroup
  Location = $location
  Name = $imageDefName02
  OsState = 'generalized'
  OsType = 'Windows'
  Publisher = 'Contoso'
  Offer = 'Windows'
  Sku = 'Win11WVD'
  HyperVGeneration = 'V2'
}
New-AzGalleryImageDefinition @GalleryParams

$SrcObjParams = @{
  PlatformImageSource = $true
  Publisher = 'MicrosoftWindowsDesktop'
  Offer = 'Office-365'    
  Sku = 'win11-22h2-avd-m365'  
  Version = 'latest'
}
$srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

$disObjParams = @{
  SharedImageDistributor = $true
  GalleryImageId = "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup/providers/Microsoft.Compute/galleries/$cgGalleryName/images/$imageDefName02/versions/$version"
  ArtifactTag = @{source='avd-win11';baseosimg='windows11'}
 
  # 1. Uncomment following line for a single region deployment.
  ReplicationRegion = $location
 
  # 2. Uncomment following line if the custom image should be replicated to another region.
  #ReplicationRegion = $location,'EastUS'
 
  RunOutputName = $runOutputName02
  ExcludeFromLatest = $false
}
$disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams


$ImgCustomParams = @{  
   PowerShellCustomizer = $true  
   Name = 'InstallVSCode'  
   RunElevated = $true  
   ScriptUri = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Install-VSCode.ps1'
  }

$Customizer = New-AzImageBuilderTemplateCustomizerObject @ImgCustomParams 

#Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
$ImgTemplateParams = @{
  ImageTemplateName = $imageTemplateName02
  ResourceGroupName = $imageResourceGroup
  Source = $srcPlatform
  Distribute = $disSharedImg
  Customize = $Customizer
  Location = $location
  UserAssignedIdentityId = $identityNameResourceId
}
New-AzImageBuilderTemplate @ImgTemplateParams

#To determine whenever or not the template upload process was successful, run the following command.
$getStatus02=$(Get-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName02)
$getStatus02
# Optional - if you have any errors running the preceding command, run:
$getStatus02.ProvisioningErrorCode 
$getStatus02.ProvisioningErrorMessage


#region Build the image
#Start the image building process using Start-AzImageBuilderTemplate cmdlet:
Start-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName02 #-NoWait
$getStatus02=$(Get-AzImageBuilderTemplate -ResourceGroupName $imageResourceGroup -Name $imageTemplateName02)

# Shows all the properties
$getStatus02 | Format-List -Property *

# Shows the status of the build
$getStatus02.LastRunStatusRunState 
$getStatus02.LastRunStatusMessage
$getStatus02.LastRunStatusRunSubState

$getStatus02 | Remove-AzImageBuilderTemplate
#endregion
#endregion

#endregion

#region Clean up your resources
<#
Remove-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $imageRoleDefName -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"

## Remove the definitions
Remove-AzRoleDefinition -Name "$identityNamePrincipalId" -Force -Scope "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroup"

## Delete the identity
Remove-AzUserAssignedIdentity -ResourceGroupName $imageResourceGroup -Name $identityName -Force

Remove-AzResourceGroup $imageResourceGroup -Force #-AsJob
#>
#endregion