#Deploy 1 Pooled HostPools without MSIX and with FSLogix and FSLogix Cloud Cache Enabled 
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().DisableMSIX().EnableFSLogixCloudCache().EnableWatermarking()

# Use case X: Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and with a replication of the disk to a recovery region with Azure Site Recovery
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($PrimaryRegionVNet.Id)
# Use case X: Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance()
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableAzureSiteRecovery($PrimaryRegionVNet.Id)
