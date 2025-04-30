#Deploy 1 Pooled HostPool with MSIX and FSLogix
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id)