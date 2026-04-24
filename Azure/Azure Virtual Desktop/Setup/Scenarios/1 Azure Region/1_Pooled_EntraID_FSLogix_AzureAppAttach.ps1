#Deploy a Pooled HostPool with 3 (default value) Session Hosts (EntraID joined) and Azure AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
