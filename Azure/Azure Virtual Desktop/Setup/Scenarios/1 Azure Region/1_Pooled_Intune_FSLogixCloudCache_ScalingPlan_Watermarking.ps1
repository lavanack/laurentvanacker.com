#Deploy 1 Pooled HostPool with Intune and Scaling Plan
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableFSLogixCloudCache().EnableScalingPlan().EnableWatermarking()

