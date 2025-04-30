#Deploy 2 Pooled HostPools with FSLogix and Azure App Attach 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableAppAttach()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableAppAttach()

#Deploy 2 Pooled HostPools with FSLogix and Azure App Attach 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableAppAttach()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableAppAttach()
