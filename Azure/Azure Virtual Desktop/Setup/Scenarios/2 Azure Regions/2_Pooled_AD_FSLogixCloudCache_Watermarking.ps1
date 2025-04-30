# Use case 8: Deploy 2 Pooled HostPools with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions)
$HP1 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
$HP2 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache($HP1).EnableWatermarking()

$HP1
$HP2    
