#Deploy 2  Pooled HostPools without MSIX and with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().DisableMSIX().EnableFSLogixCloudCache().EnableWatermarking()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $SecondaryRegionSubnet.Id).EnableSpotInstance().DisableMSIX().EnableFSLogixCloudCache().EnableWatermarking()
#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and with a replication of the disk to a recovery region with Azure Site Recovery
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($SecondaryRegionVNet.Id)
#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance()
#Deploy 1 Pooled HostPool with FSLogix and MSIX App Attach VMs with ASR for the replication
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($SecondaryRegionVNet.Id)
