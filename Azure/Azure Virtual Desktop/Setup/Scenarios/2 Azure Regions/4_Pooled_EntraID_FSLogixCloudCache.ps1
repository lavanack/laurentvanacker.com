$HP1 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache().EnableAppAttach()
$HP2 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache($HP1).EnableAppAttach()
$HP3 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache().EnableAppAttach()
$HP4 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache($HP3).EnableAppAttach()

$HP1
$HP2
$HP3
$HP4    
