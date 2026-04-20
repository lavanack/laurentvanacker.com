#Deploy 1 Pooled HostPool with Intune, FSLogix 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).EnableIntune().EnableScalingPlan().EnableWatermarking()
