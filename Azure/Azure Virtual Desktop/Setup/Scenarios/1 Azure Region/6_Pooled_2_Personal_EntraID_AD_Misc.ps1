# Use case 0: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (AD Domain joined) with FSLogix and MSIX
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetPreferredAppGroupType("RailApplications")#.EnableSpotInstance()
# Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (EntraID joined) with FSLogix and MSIX
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).SetPreferredAppGroupType("RailApplications")#.EnableSpotInstance()
# Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix, MSIX, Ephemeral OS Disk (ResourceDisk mode) and a Standard_D8ds_v5 size (compatible with Ephemeral OS Disk)
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetVMSize('Standard_D8ds_v5').EnableEphemeralOSDisk([DiffDiskPlacement]::ResourceDisk)
# Use case 3: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and AppAttach
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableAppAttach()
# Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix and Spot Instance VMs and setting the LoadBalancer Type to DepthFirst
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableSpotInstance().SetLoadBalancerType("DepthFirst")
# Use case 5: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined, enrolled with Intune) with FSLogix and a Scaling Plan
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).EnableIntune().EnableScalingPlan()#.SetVMNumberOfInstances(1).EnableSpotInstance()
# Use case 6: Deploy a Personal HostPool with 2 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and Hibernation enabled 
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetVMNumberOfInstances(2).SetVMSize('Standard_D8ds_v5').EnableHibernation()
# Use case 7: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and a Scaling Plan 
[PersonalHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableScalingPlan()
