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
#requires -Version 3.0 -Modules Az.Accounts, Az.Compute, Az.ImageBuilder, Az.ManagedServiceIdentity, Az.Resources
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
	[Parameter(Mandatory = $true)]
	[string]$GalleryResourceId,
	[Parameter(Mandatory = $true)]
	[string]$Image,
	[Parameter(Mandatory = $true)]
	[string] $StagingResourceGroupNameARM,
	[Parameter(Mandatory = $true)]
	[string] $AssignedIdentityId,
	[Parameter(Mandatory = $false)]
	[string]$Location = "EastUS2",
	[Parameter(Mandatory = $false)]
	[string[]]$TargetRegions = @($Location),
	[Parameter(Mandatory = $false)]
	[int]$ReplicaCount = 1,
	[Parameter(Mandatory = $false)]
    [boolean] $excludeFromLatest = $true
)

#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject "`$AzureContext: $($AzureContext | Out-String)" 
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject "`$AzureContext: $($AzureContext | Out-String)" 
$subscriptionID = $GalleryResourceId -replace "/resourcegroups/.+" -replace "/subscriptions/"
Write-Output -InputObject "`$subscriptionID: $subscriptionID" 
#endregion

#region Parameters
Write-Output -InputObject "`$GalleryResourceId: $GalleryResourceId" 
Write-Output -InputObject "`$Location: $Location" 
Write-Output -InputObject "`$TargetRegions: $($TargetRegions -join ', ')" 
Write-Output -InputObject "`$ReplicaCount: $ReplicaCount" 
Write-Output -InputObject "`$excludeFromLatest: $excludeFromLatest" 
#endregion

#region Target Regions
if ($Location -notin $TargetRegions) {
	$TargetRegions += $Location
}
Write-Output -InputObject "`$TargetRegions: $($TargetRegions -join ', ')" 
[array] $TargetRegionSettings = foreach ($CurrentTargetRegion in $TargetRegions) {
	@{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS"}
}
Write-Output -InputObject "`$TargetRegionSettings: $($TargetRegionSettings | Out-String)" 
#endregion

#region Variables
#region Source Image 
$SrcObjParamsARM = $Image | ConvertFrom-Json
#endregion

$Gallery = Get-AzGallery -ResourceId $GalleryResourceId
$ResourceGroupName = $Gallery.ResourceGroupName
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -Location $Gallery.Location
$runOutputNameARM = "cgOutputARM"
$Version = Get-Date -UFormat "%Y.%m.%d"
Write-Output -InputObject "`$Version: $Version" 
$Tags =  @{
    "SecurityControl" = "Ignore"
}
#endregion

#region Image template and definition names
#Image Market Place Image + customizations: VSCode
$timeInt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$imageDefinitionNameARM = "{0}-arm-vscode" -f $SrcObjParamsARM.Sku
$imageTemplateNameARM = "{0}-template-{1}" -f $imageDefinitionNameARM, $timeInt
Write-Output -InputObject "`$imageDefinitionNameARM: $imageDefinitionNameARM"
Write-Output -InputObject "`$imageTemplateNameARM: $imageTemplateNameARM"
#endregion


#region Checking of Image version already exists
$Parameters = @{
    ResourceGroupName = $ResourceGroupName 
    GalleryName = $Gallery.Name 
}
if ((Get-AzGalleryImageVersion @Parameters -GalleryImageDefinitionName $imageDefinitionNameARM).Name -eq $Version) {
    Write-Error "The '$Version' for the '$($imageDefinitionNameARM)' Image Definition already exists on '$($Parameters.GalleryName)' Azure Compute Gallery (ResourceGroup: '$($Parameters.ResourceGroupName)'). Processing Stopped !" -ErrorAction "Stop"
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

((Get-Content -Path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
#((Get-Content -Path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputNameARM) | Set-Content -Path $templateFilePath

((Get-Content -Path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefinitionNameARM) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<sharedImageGalName>', $Gallery.Name) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<excludeFromLatest>', $excludeFromLatest.ToString().ToLower()) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<TargetRegions>', $(ConvertTo-Json -InputObject $TargetRegionSettings)) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentityId) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<stagingResourceGroupName>', $StagingResourceGroupNameARM) | Set-Content -Path $templateFilePath

((Get-Content -Path $templateFilePath -Raw) -replace '<publisher>', $SrcObjParamsARM.Publisher) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<offer>', $SrcObjParamsARM.Offer) | Set-Content -Path $templateFilePath
((Get-Content -Path $templateFilePath -Raw) -replace '<sku>', $SrcObjParamsARM.sku) | Set-Content -Path $templateFilePath
Write-Output -InputObject "Template File Content: $(Get-Content -Path $templateFilePath)"
#endregion

#region Create the gallery definition
$GalleryParams = @{
	GalleryName       = $Gallery.Name
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
Write-Output -InputObject "Creating Azure Compute Gallery Image Definition '$imageDefinitionNameARM' (From ARM)..."
$GalleryImageDefinitionARM = New-AzGalleryImageDefinition @GalleryParams
#endregion

#region Submit the template
Write-Output -InputObject "`$ResourceGroupName: $ResourceGroupName  ..."
Write-Output -InputObject "`$templateFilePath: $templateFilePath  ..."
Write-Output -InputObject "`$imageTemplateNameARM: $imageTemplateNameARM  ..."
Write-Output -InputObject "`$location: $location  ..."

Write-Output -InputObject "Starting Resource Group Deployment from '$templateFilePath' ..."
$TemplateParameterObject = @{
    "api-Version" = "2022-07-01"
    "imageTemplateName" = $imageTemplateNameARM
    "svclocation" = $location 
}  
$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject $TemplateParameterObject  #-Tag $Tags
	
#region Build the image
Write-Output -InputObject "Starting Image Builder Template from '$imageTemplateNameARM' (As Job) ..."
$Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateNameARM -AsJob
#endregion
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
Write-Output -InputObject "Removing '$aibRoleImageCreationPath' ..."
Write-Output -InputObject "Removing '$templateFilePath' ..."
Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
#endregion

#region Removing Staging ResourceGroups
$null = Remove-AzResourceGroup -ResourceGroupName $StagingResourceGroupNameARM -Force -AsJob
#endregion