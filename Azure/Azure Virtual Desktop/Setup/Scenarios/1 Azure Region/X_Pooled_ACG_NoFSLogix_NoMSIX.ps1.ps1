#region Creating a new Pooled Host Pool for every image definition from an Azure Compute Gallery
#Looging for Azure Compute Gallery Image Definition with image version in the primary region
$GalleryImageDefinition = Get-PsAvdAzGalleryImageDefinition -Region $PrimaryRegion
if (-not($GalleryImageDefinition)) {
    #Creating an Azure Compute Gallery if needed
    $AzureComputeGallery = New-AzureComputeGallery -Location $PrimaryRegion -TargetRegions $PrimaryRegion
    $GalleryImageDefinition = Get-AzGalleryImageDefinition -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName
}

foreach ($CurrentGalleryImageDefinition in $GalleryImageDefinition) {
    #$LatestCurrentGalleryImageVersion = Get-AzGalleryImageVersion -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName -GalleryImageDefinitionName $CurrentGalleryImageDefinition.Name | Sort-Object -Property Id | Select-Object -Last 1
    #Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with an Image coming from an Azure Compute Gallery and without FSLogix and MSIX
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetVMSourceImageId($CurrentGalleryImageDefinition.Id).DisableFSLogix().DisableMSIX()
    Write-Verbose -Message "VM Source Image Id for the ACG Host Pool: $LatestCurrentGalleryImageVersion (MSIX: $($PooledHostPool.MSIX) / FSlogix: $($PooledHostPool.FSlogix))"
}
#endregion

