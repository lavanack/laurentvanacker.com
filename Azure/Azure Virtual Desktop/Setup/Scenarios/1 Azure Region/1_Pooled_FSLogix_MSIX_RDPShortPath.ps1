#Deploy 1 Pooled HostPools with MSIX and with FSLogix and RDP ShortPath
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableRDPShortPath()
