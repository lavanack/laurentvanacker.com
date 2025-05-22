#Deploy 2 Pooled HostPools with OneDrive (For Known Folders)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableSpotInstance().EnableOneDriveForKnownFolders().EnableWatermarking()

#Deploy 2 Pooled HostPools with OneDrive (For Known Folders)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableSpotInstance().EnableOneDriveForKnownFolders().EnableWatermarking()
