#Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and MSIX AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id)
#Deploy a Pooled HostPool with 3 (default value) Session Hosts (EntraID joined) with FSLogix 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
#Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and Azure AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableAppAttach()
