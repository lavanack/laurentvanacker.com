#Deploy 2 Pooled HostPools with FSLogix and Azure App Attach 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id)

#Deploy 2 Pooled HostPools with FSLogix and Azure App Attach 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id, $SecondaryRegionPESubnet.Id)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id, $SecondaryRegionPESubnet.Id)
