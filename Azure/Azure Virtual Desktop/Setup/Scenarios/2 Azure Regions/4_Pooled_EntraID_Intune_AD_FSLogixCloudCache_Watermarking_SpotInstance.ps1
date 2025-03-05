#Deploy 2 Pooled HostPools with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()

#Deploy 2 Pooled HostPools with Intune, FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions)
#Be sure to use the same Index in the both region when using FSLogix Cloud Cache
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableIntune().EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
