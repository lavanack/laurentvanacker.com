# Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (AD Domain joined) with FSLogix and AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetPreferredAppGroupType("RailApplications").EnableAppAttach()

# Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (Azure AD/Microsoft Entra ID joined) with FSLogix and AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).SetPreferredAppGroupType("RailApplications").EnableAppAttach()
