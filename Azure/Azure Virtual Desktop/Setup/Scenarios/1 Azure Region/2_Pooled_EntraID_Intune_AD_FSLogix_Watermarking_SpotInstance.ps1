#Deploy 1 Pooled HostPool with FSLogix
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableWatermarking()

#Deploy 1 Pooled HostPool with Intune, FSLogix 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableSpotInstance().EnableWatermarking()
