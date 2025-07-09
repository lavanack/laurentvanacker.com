#Deploy a Pooled HostPool with 3 (default value) Session Hosts (EntraID joined) and with FSLogix Cloud Cache and Azure AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
