# HostPool PowerShell Classes

- [HostPool PowerShell Classes](#hostpool-powershell-classes)
  - [Enumerations](#enumerations)
    - [IdentityProvider](#identityprovider)
    - [HostPoolType](#hostpooltype)
  - [PowerShell Classes](#powershell-classes)
    - [HostPool PowerShell Class (Base Class)](#hostpool-powershell-class-base-class)
      - [HostPool PowerShell Class \> Properties](#hostpool-powershell-class--properties)
      - [HostPool PowerShell Class \> Constructor](#hostpool-powershell-class--constructor)
      - [HostPool PowerShell Class \> Methods](#hostpool-powershell-class--methods)
    - [PooledHostPool PowerShell Class](#pooledhostpool-powershell-class)
      - [PooledHostPool PowerShell Class \> Properties](#pooledhostpool-powershell-class--properties)
      - [PooledHostPool PowerShell Class \> Constructor](#pooledhostpool-powershell-class--constructor)
      - [PooledHostPool PowerShell Class \> Methods](#pooledhostpool-powershell-class--methods)
      - [PooledHostPool PowerShell Class \> Examples](#pooledhostpool-powershell-class--examples)
    - [PersonalHostPool PowerShell Class](#personalhostpool-powershell-class)
      - [PersonalHostPool PowerShell Class \> Properties](#personalhostpool-powershell-class--properties)
      - [PersonalHostPool PowerShell Class \> Constructor](#personalhostpool-powershell-class--constructor)
      - [PersonalHostPool PowerShell Class \> Methods](#personalhostpool-powershell-class--methods)
      - [PersonalHostPool PowerShell Class \> Examples](#personalhostpool-powershell-class--examples)

## Enumerations

### IdentityProvider

This is an enumeration that defines the types of identity providers that can be used for a  host pool via the Powershell  classes defined in this document:

- `ActiveDirectory`: This represents an Active Directory identity provider.
- `MicrosoftEntraID`: This represents a Microsoft EntraID identity provider.

### HostPoolType

This is an enumeration that defines the types of host pools that can be created:

- `Personal`: This represents a personal host pool.
- `Pooled`: This represents a pooled host pool.

## PowerShell Classes

### HostPool PowerShell Class (Base Class)

This is the Base class for the PooledHostPool and PersonalHostPool PowerShell classes. It contains the common properties and methods for both HostPool types:

#### HostPool PowerShell Class > Properties

- IdentityProvider: the identity provider to use for the host pool (Default Value: `ActiveDirectory` - from the IdentityProvider enum)
- Name : The HostPool Name based on the following  naming convention: hp-<np|pd>-<ad|ei>-<3-letter project code>-<mp|cg>-<2 or 3-letter Azure location>-<2-digit Index>)
  - np: Non-Persistent for Pooled HostPool
  - pd: Personal Desktop for Personal HostPool
  - ad: Active Directory for AD Domain joined Session Hosts
  - ei: Microsoft Entra ID for Azure AD/Microsoft Entra ID joined Session Hosts
  - mp: MarketPlace for image coming from MarketPlace Gallery
  - cg: Compute Gallery for image coming from Compute Gallery
  - The 2 or 3-letter Azure location is generated automatically based on the Location property
  - 3-letter project code: 'poc' is used here
  - The index is incremental and starts at 1 (Each instanciation will increment the index).
  The name is automatically generated based on some properties (Type, IdentityProvider, Image, Location, Index) but you can customize it by setting the Name property.
- NamePrefix  : The HostPool Name prefix based on the following  naming convention: <n|p><a|e><3-letter project code><m|c><2 or 3 letter Azure location>-<2-digit Index>
  - n: Non-Persistent for Pooled HostPool
  - p: Personal Desktop for Personal HostPool
  - a: Active Directory for AD Domain joined Session Hosts
  - e: Microsoft Entra ID for Azure AD/Microsoft Entra ID joined Session Hosts
  - m: MarketPlace for image coming from MarketPlace Gallery
  - c: Compute Gallery for image coming from Compute Gallery)
- Location: Azure Location (Default Value: `eastus`)
- VMNumberOfInstances: Number of VMs in the HostPool (Default Value: `3`)
- KeyVault: Cedentials KeyVault for the local admin account and the AD Domain Join account for this host pool
- Intune: Boolean to indicate if the session host will be registered as Intune devices (Default Value: `$false`)
- Spot: Boolean to indicate if the VMs are Spot VMs (Default Value: `$true`)
- VMSize: Azure VM Size (Default Value: `Standard_D2s_v5`)
- ImagePublisherName: Image Publisher Name
- ImageOffer: Image Offer
- ImageSku: Image SKU
- VMSourceImageId: Azure VM Source Image Id from an Azure Compute Gallery
- AzLocationShortNameHT: This static member is a hashtable that maps Azure Location to a 2 or 3-letter Azure location code. It is used to generate the HostPool Name based on the Azure Location. This hashtable is filled (via the hidden static  BuildAzureLocationSortNameHashtable method during the first instanciation of an object of the HostPool class.

> [!NOTE]
> cf. <https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool> for more details about Azure Naming Convention

#### HostPool PowerShell Class > Constructor

The following properties are set by default and the following methods are called by the constructor of the class:

- PersonalHostPool(\<Azure KeyVault\> as [object])
  - Properties
    - Location: `EastUs`
    - VMNumberOfInstances: `3`
    - VMSIze: `Standard_D2s_v5`
    - IdentityProvider: `ActiveDirectory`
  - Methods
    - EnableSpotInstance()
    - DisableIntune()
  
#### HostPool PowerShell Class > Methods

- BuildAzureLocationSortNameHashtable(): This static method builds the AzLocationShortNameHT hashtable that maps Azure Location to a 2 or 3-letter Azure location code. It is used to generate the HostPool Name based on the Azure Location.
- HostPool(\<Azure KeyVault\> as [object]): Takes an Azure KeyVault as only parameter and instanciates a HostPool object.
- GetAzAvdWorkSpaceName(): Gets the related Azure AVD WorkSpace Name
- GetAzAvdScalingPlanName(): Gets the related Azure AVD Scaling Plan Name
- GetLogAnalyticsWorkSpaceName(): Gets the related Azure Log Analytics WorkSpace Name
- GetPropertyForJSON(): Returns some properties of the class used to export the object in a JSON structure and stored in a dedicated file if needed.
- GetResourceGroupName(): Gets the related Azure resource group name
- GetKeyVaultName(): Gets the related Azure key vault name
- SetVMNumberOfInstances([int]): Set the number of VMs in the HostPool
- DisableIntune(): Disable Intune registration for the session hosts
- EnableIntune(): Enable Intune registration for the session hosts
- IsIntuneEnrolled(): Check if the session hosts are registered as Intune devices (returns a boolean value)
- DisableSpotInstance: Disable Spot VMs for the session hosts
- EnableSpotInstance(): Enable Spot VMs for the session hosts
- RefreshNames(): hidden method overwritten by the child classes to refresh the Name and NamePrefix properties based on the properties of the child class.
- IsMicrosoftEntraIdJoined(): Check if the HostPool is Azure AD/Microsoft Entra ID joined (returns a boolean value)
- IsActiveDirectoryJoined(): Check if the HostPool is AD Domain joined (returns a boolean value)
- SetIdentityProvider([IdentityProvider]): Set the identity provider for the HostPool (Active Directory or Microsoft Entra ID)
- SetVMSize([string]): Sets the Azure VM Size for the HostPool
- SetLocation([string]): Sets the Azure Location for the HostPool
- SetName([string], [string]): Sets the HostPool Name and Name Prefix (User customisation)
- SetImage([string], [string], [string]): Sets the Image Publisher Name, Image Offer and Image SKU for the HostPool
  
> [!IMPORTANT]
> Except for the BuildAzureLocationSortNameHashtable and Is* methods and the constructor, all the methods returns the HostPool object to allow chaining. For instance :
>
> ```PowerShell
> $hostPool = [HostPool]::new($keyVault).SetVMNumberOfInstances(5).EnableIntune()
> ```
>
This is also the case for the child classes.

> cf. <https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool> for more details about Azure Naming Convention

### PooledHostPool PowerShell Class

#### PooledHostPool PowerShell Class > Properties

This class inherits from the HostPool PowerShell class and adds the following properties:

- MaxSessionLimit: Maximum number of sessions per user (Default Value: `5`)
- FSLogix: Boolean to indicate if FSLogix is enabled (Default Value: `$true`)
- MSIX: Boolean to indicate if MSIX App Attach is enabled (Default Value: `$true`)
- Index: Incremental index of the HostPool (Starting Value: `1`). Every time a PooledHostPool is created without specifiyng an Index (via the SetIndex method - implemented in the child classes), the index is incremented by 1.

#### PooledHostPool PowerShell Class > Constructor

The following properties are set by default and the following methods are called by the constructor of the class:

- PersonalHostPool(\<Azure KeyVault\> as [object])
  - Properties
    - Type: `Pooled`
    - ImagePublisherName: Image Publisher Name (Default Value: `MicrosoftWindowsDesktop`)
    - ImageOffer: Image Offer (Default Value: `office-365`)
    - ImageSku: Image SKU (Default Value: `win11-23h2-avd-m365`)
    - FSLogix: `$true`
    - MSIX: `$true`
  - Methods
    - refreshNames(): To refresh the Name and NamePrefix properties based on the properties of the child class. With the default values the Name and NamePrefix are set as follows:
      - NamePrefix: `"hp-pd-ad-poc-mp-use-<2-digit Index>`
      - NamePrefix: `"papocmeu<2-digit Index>`

#### PooledHostPool PowerShell Class > Methods

- ResetIndex(): Resets the Index to 0
- GetFSLogixStorageAccountName(): Returns the FSLogix Storage Account Name based on the HostPool Name
- GetMSIXStorageAccountName(): Returns the MSIX Storage Account Name based on the HostPool Name
- SetIndex([int]): Sets the Index for the HostPool
- SetMaxSessionLimit([int]): Sets the maximum number user sessions per host pool
- DisableFSLogix(): Disables FSLogix for the HostPool
- EnableFSLogix(): Enables FSLogix for the HostPool
- DisableMSIX(): Disables MSIX for the HostPool
- EnableMSIX(): Enables MSIX for the HostPool
- SetIdentityProvider([IdentityProvider]): Sets the identity provider for the HostPool (Active Directory or Microsoft Entra ID). If the session host are Microsoft Entra ID joined, the MSIX feature is disabled (not compatible as explained [here](https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers))Overwrites the parent method.
- RefreshNames() : Refresh the Name and NamePrefix properties based on the properties of the child class.

#### PooledHostPool PowerShell Class > Examples

```PowerShell
#Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix
$hostPool = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault)
#Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix
$hostPool = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
#Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and enrolled with Intune) with FSLogix
$hostPool = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).EnableIntune()
```

### PersonalHostPool PowerShell Class

#### PersonalHostPool PowerShell Class > Properties

This class inherits from the HostPool PowerShell class and adds the following properties:

- Index: Incremental index of the HostPool (Starting Value: `1`). Every time a PersonalHostPool is created without specifiyng an Index (via the SetIndex method - implemented in the child classes), the index is incremented by 1.
- HibernationEnabled: Boolean to indicate if the session hosts are hibernated when not in use (Default Value: `$false` - more details [here](https://learn.microsoft.com/en-us/azure/virtual-machines/hibernate-resume))

#### PersonalHostPool PowerShell Class > Constructor

The following properties are set by default and the following methods are called by the constructor of the class:

- PersonalHostPool(\<Azure KeyVault\> as [object])
  - Properties
    - Type: `Personal`
    - ImagePublisherName: Image Publisher Name (Default Value: `MicrosoftWindowsDesktop`)
    - ImageOffer: Image Offer (Default Value: `windows-11`)
    - ImageSku: Image SKU (Default Value: `win11-23h2-ent`)
    - HibernationEnabled: `$false`
  - Methods
    - refreshNames(): To refresh the Name and NamePrefix properties based on the properties of the child class. With the default values the Name and NamePrefix are set as follows:
      - NamePrefix: `"hp-np-ad-poc-mp-use-<2-digit Index>`
      - NamePrefix: `"napocmeu<2-digit Index>`

#### PersonalHostPool PowerShell Class > Methods

- ResetIndex(): Resets the Index to 0
- SetIndex([int]): Sets the Index for the HostPool
- DisableHiberation(): Disables hibernation for the HostPool
- EnableHiberation(): Enables hibernation for the HostPool
- RefreshNames() : Refresh the Name and NamePrefix properties based on the properties of the child class.

#### PersonalHostPool PowerShell Class > Examples
  
  ```PowerShell
  # Deploy a Personal HostPool with 4 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
    $hostPool = [PersonalHostPool]::new($KeyVault).SetVMNumberOfInstances(4)
  # Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
  $hostPool = [PersonalHostPool]::new($KeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableHibernation()
  ```
  