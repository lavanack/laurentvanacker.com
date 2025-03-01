$HP1 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache().EnableWatermarking()
$HP2 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableSpotInstance().EnableFSLogixCloudCache($HP1).EnableWatermarking()

$HP1
$HP2    
