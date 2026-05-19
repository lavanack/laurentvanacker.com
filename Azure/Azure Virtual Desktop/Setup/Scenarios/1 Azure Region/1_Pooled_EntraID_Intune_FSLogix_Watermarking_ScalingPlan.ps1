#Deploy 1 Pooled HostPool with Intune, FSLogix 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetJoinMode([JoinMode]::MicrosoftEntraID).EnableIntune().EnableScalingPlan().EnableWatermarking()
