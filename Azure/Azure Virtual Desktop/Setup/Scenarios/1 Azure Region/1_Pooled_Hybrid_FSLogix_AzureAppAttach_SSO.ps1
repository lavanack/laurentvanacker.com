#Deploy 1 Pooled HostPool with FSLogix and AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetJoinMode([JoinMode]::Hybrid).EnableSSO()
