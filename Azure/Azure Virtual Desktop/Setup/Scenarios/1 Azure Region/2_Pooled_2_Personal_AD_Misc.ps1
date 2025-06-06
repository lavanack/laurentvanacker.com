#Deploy 1 Pooled HostPools without Azure App Attach and with FSLogix and FSLogix Cloud Cache Enabled 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().DisableAppAttach().EnableWatermarking()

#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and Azure App Attach - Not necessary for Personal Desktops) and with a replication of the disk to a recovery region with Azure Site Recovery
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($PrimaryRegionVNet.Id)
#Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and Azure App Attach - Not necessary for Personal Desktops)
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance()
#Deploy 1 Pooled HostPool with FSLogix and Azure App Attach App Attach as Spot Instance VMs and ASR for the replication
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($PrimaryRegionVNet.Id)
