#Deploy 2  Pooled HostPools without Azure App Attach and with FSLogix and FSLogix Cloud Cache Enabled and replicating the profiles to each other (because they use Azure Paired Regions)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().DisableAppAttach().EnableWatermarking()

#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and Azure App Attach - Not necessary for Personal Desktops) and with a replication of the disk to a recovery region with Azure Site Recovery
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($SecondaryRegionVNet.Id)
