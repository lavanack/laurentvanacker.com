#Deploy 1 Pooled HostPool with Intune and Scaling Plan
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetJoinMode([JoinMode]::MicrosoftEntraID).EnableIntune().EnableScalingPlan().EnableWatermarking()

