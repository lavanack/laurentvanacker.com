#Deploy 1 Pooled HostPool with FSLogix and FSLogix Cloud Cache Enabled
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()

#Deploy 1 Pooled HostPools with Intune, FSLogix and FSLogix Cloud Cache Enabled 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
