#Deploy 1 Personal HostPool with SSO
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).EnableSSO()

#Deploy 1 Pooled HostPool with SSO
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).EnableSSO()
