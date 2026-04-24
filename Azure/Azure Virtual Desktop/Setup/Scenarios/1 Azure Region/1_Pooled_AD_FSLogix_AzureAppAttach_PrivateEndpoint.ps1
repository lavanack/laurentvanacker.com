#Deploy 1 Pooled HostPool with FSLogix and AppAttach
$PrimaryRegionResourceGroupName = "rg-avd-ad-use2-002"
$PrimaryRegionVNetName = "vnet-avd-avd-use2-002"
$PrimaryRegionPESubnetName = "snet-avd-pe-use2-002"
$PrimaryRegionVNet = Get-AzVirtualNetwork -Name $PrimaryRegionVNetName -ResourceGroupName $PrimaryRegionResourceGroupName
$PrimaryRegionPESubnet = $PrimaryRegionVNet  | Get-AzVirtualNetworkSubnetConfig -Name $PrimaryRegionPESubnetName

[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id, $PrimaryRegionPESubnet.Id).EnableAVDPrivateEndpoint()