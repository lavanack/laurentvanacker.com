#Deploy 1 Pooled HostPool with FSLogix and Azure App Attach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id)
