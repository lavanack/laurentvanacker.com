#Deploy 1 Pooled HostPool with Intune, FSLogix 
#[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetJoinMode([JoinMode]::MicrosoftEntraID).SetIdentityModel([IdentityModel]::CloudOnly).EnableScalingPlan().EnableWatermarking()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetIdentityModel([IdentityModel]::CloudOnly)
