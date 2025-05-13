#Deploy 1 Personal HostPool with Intune
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetVMNumberOfInstances(1).EnableIntune().EnableSpotInstance()

#Deploy 1 Pooled HostPool with Intune
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetVMNumberOfInstances(1).EnableIntune().EnableSpotInstance()
