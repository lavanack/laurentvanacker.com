#Deploy 2 Pooled HostPools with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions and the second one references the first one)
$HP1 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
$HP2 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache($HP1)

#Deploy 2 Pooled HostPools with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions and the second one references the first one)
$HP3 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
$HP4 = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableFSLogixCloudCache($HP3)

$HP1
$HP2
$HP3
$HP4    
