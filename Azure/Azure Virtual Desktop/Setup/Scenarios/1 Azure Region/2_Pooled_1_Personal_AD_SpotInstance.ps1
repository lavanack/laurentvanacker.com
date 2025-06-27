#Deploy 1 Pooled HostPools Azure App Attach and with FSLogix and FSLogix Cloud Cache Enabled 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableWatermarking().EnableScalingPlan()
#Deploy 1 Pooled HostPools Azure App Attach and with FSLogix and FSLogix Cloud Cache Enabled for Remote Apps. The Session Host VMs will be Spot instances.
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().SetPreferredAppGroupType("RailApplications")

#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and Azure App Attach - Not necessary for Personal Desktops) and with a replication of the disk to a recovery region with Azure Site Recovery. The Session Host VMs will be Spot instances.
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance()
