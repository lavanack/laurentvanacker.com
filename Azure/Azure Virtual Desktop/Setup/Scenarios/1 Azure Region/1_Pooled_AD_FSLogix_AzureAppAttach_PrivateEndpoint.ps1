#Deploy 1 Pooled HostPool with FSLogix and AppAttach
$SubscriptionId = (Get-AzContext).Subscription.Id
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnablePrivateEndpoint("/subscriptions/$SubscriptionId/resourceGroups/rg-avd-ad-use2-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-use2-002/subnets/snet-avd-pe-use2-002")