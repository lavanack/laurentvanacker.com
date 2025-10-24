#Deploy 1 Pooled HostPool with Intune, FSLogix 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableScalingPlan().EnableWatermarking()
