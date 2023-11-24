# HostPool PowerShell Classes

- [HostPool PowerShell Classes](#hostpool-powershell-classes)
  - [HostPool PowerShell Class (Base Class)](#hostpool-powershell-class-base-class)
  - [PooledHostPool PowerShell Class](#pooledhostpool-powershell-class)
    - [PooledHostPool PowerShell Class \> Constructors and Methods](#pooledhostpool-powershell-class--constructors-and-methods)
      - [PooledHostPool PowerShell Class \> Constructors](#pooledhostpool-powershell-class--constructors)
      - [PooledHostPool PowerShell Class \> Methods](#pooledhostpool-powershell-class--methods)
  - [PersonalHostPool PowerShell Class](#personalhostpool-powershell-class)
    - [PersonalHostPool PowerShell Class \> Constructors and Methods](#personalhostpool-powershell-class--constructors-and-methods)
      - [PersonalHostPool PowerShell Class \> Constructors](#personalhostpool-powershell-class--constructors)
      - [PersonalHostPool PowerShell Class \> Methods](#personalhostpool-powershell-class--methods)

## HostPool PowerShell Class (Base Class)

This is the Base class for the PooledHostPool and PersonalHostPool PowerShell classes. It contains the common properties and methods for both HostPool types:

- Name : The HostPool Name based on the following  naming convention: hp-<np|pd>-<ad|ei>-<3-letter project code>-<mp|cg>-<2 or 3 letter Azure location>-<2-digit Index>)
  - np: Non-Persistent for Pooled HostPool
  - pd: Personal Desktop for Personal HostPool
  - ad: Active Directory for AD Domain joined Session Hosts
  - ei: Microsoft Entra ID for Azure AD/Microsoft Entra ID joined Session Hosts
  - mp: MarketPlace for image coming from MarketPlace Gallery
  - cg: Compute Gallery for image coming from Compute Gallery

> [!NOTE]
> cf. <https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool> for more details about Azure Naming Convention

- Type: Personal or Pooled (via the HostPoolType enum)
- Location: Azure Location (Default Value: `eastus`)
- NamePrefix  : The HostPool Name prefix based on the following  naming convention: <n|p><a|e><3-letter project code><m|c><2 or 3 letter Azure location><Index>
  - n: Non-Persistent for Pooled HostPool
  - p: Personal Desktop for Personal HostPool
  - a: Active Directory for AD Domain joined Session Hosts
  - e: Microsoft Entra ID for Azure AD/Microsoft Entra ID joined Session Hosts
  - m: MarketPlace for image coming from MarketPlace Gallery
  - c: Compute Gallery for image coming from Compute Gallery)
- VMNumberOfInstances: Number of VMs in the HostPool (Default Value: `3`)
- KeyVault: Cedentials KeyVault for the local admin account and the AD Domain Join account
- IsMicrosoftEntraIdJoined: Boolean to indicate if the HostPool is Azure AD/Microsoft Entra ID joined (Default Value: `false`)
- VMSize: Azure VM Size (Default Value: `Standard_D2s_v3`)
- ImagePublisherName: Image Publisher Name
- ImageOffer: Image Offer
- ImageSku: Image SKU
- VMSourceImageId: Azure VM Source Image Id from an Azure Compute Gallery

## PooledHostPool PowerShell Class

This class inherits from the HostPool PowerShell class and adds the following properties:

- MaxSessionLimit: Maximum number of sessions per user (Default Value: `5`)
- FSLogix: Boolean to indicate if FSLogix is enabled (Default Value: `true`)
- MSIX: Boolean to indicate if MSIX App Attach is enabled (Default Value: `true`)
- Index: Incremental index of the HostPool (Starting Value: `1`). Every time a PooledHostPool is created without specifying an index, the index is incremented by 1.

The following properties are set by default:

- Type: Pooled
- NamePrefix: `"hp-np-ad-poc-mp-eu-<2-digit Index>`
- NamePrefix: `"napocmeu<2-digit Index>`
- ImagePublisherName: Image Publisher Name (Default Value: `MicrosoftWindowsDesktop`)
- ImageOffer: Image Offer (Default Value: `office-365`)
- ImageSku: Image SKU (Default Value: `win11-22h2-avd-m365`)
- FSLogix: `true`
- MSIX: `true`

### PooledHostPool PowerShell Class > Constructors and Methods

#### PooledHostPool PowerShell Class > Constructors

- PooledHostPool(KeyVault): Increments the Index and create a PooledHostPool with the default values
- PooledHostPool(Index, KeyVault): Uses the specified Index and create a PooledHostPool with the default values
- PooledHostPool(Name, NamePrefix, KeyVault): Uses the specified name and name prefix and create a PooledHostPool with the default values
- PooledHostPool(Name, NamePrefix, KeyVault, VMSourceImageId): Uses the specified name, name prefix and VMSourceImageId (Image reference from an Azure Compute Gallery) and create a PooledHostPool with the default values
- PooledHostPool(Name, Location, NamePrefix, MaxSessionLimit, VMNumberOfInstances, KeyVault, VMSize, ImagePublisherName, ImageOffer, ImageSku, FSLogix, MSIX): Uses the specified name, location, name prefix, max session limit, number of instances, VMSize, ImagePublisherName, ImageOffer, ImageSku, FSLogix and MSIX
- PooledHostPool(Name, Location, NamePrefix, MaxSessionLimit, VMNumberOfInstances, KeyVault, VMSize, VMSourceImageId, FSLogix, MSIX): Uses the specified name, location, name prefix, max session limit, number of instances, VMSize,  VMSourceImageId (Image reference from an Azure Compute Gallery), ImagePublisherName, ImageOffer, ImageSku, FSLogix and MSIX

#### PooledHostPool PowerShell Class > Methods  

- ResetIndex: Reset the Index to 0

> [!NOTE]
> I choose to not implement Azure AD/Microsoft Entra ID joined Session Hosts for Pooled HostPool this scenario in this scenario (Maybe in the future). The Session Hosts are joined to an AD Domain.

## PersonalHostPool PowerShell Class

This class inherits from the HostPool PowerShell class and adds the following properties:

- Index: Incremental index of the HostPool (Starting Value: `1`). Every time a PersonalHostPool is created without specifying an index, the index is incremented by 1.

The following properties are set by default:

- Type: Pooled
- NamePrefix: `"hp-pd-ad-poc-mp-eu-<2-digit Index>`
- NamePrefix: `"papocmeu<2-digit Index>`
- ImagePublisherName: Image Publisher Name (Default Value: `MicrosoftWindowsDesktop`)
- ImageOffer: Image Offer (Default Value: `windows-11`)
- ImageSku: Image SKU (Default Value: `win11-22h2-ent`)
- FSLogix: `true`
- MSIX: `true`

### PersonalHostPool PowerShell Class > Constructors and Methods

#### PersonalHostPool PowerShell Class > Constructors

- PersonalHostPool(KeyVault, IsMicrosoftEntraIdJoined): Specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not, increment the Index and create a PooledHostPool with the default values
- PersonalHostPool(Index, KeyVault, IsMicrosoftEntraIdJoined): Uses the specified Index, specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not and create a PooledHostPool with the default values
- PersonalHostPool(Name, NamePrefix, KeyVault, IsMicrosoftEntraIdJoined): Uses the specified name and name prefix, specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not and create a PooledHostPool with the default values
- PersonalHostPool(Name, NamePrefix, KeyVault, IsMicrosoftEntraIdJoined, VMSourceImageId): Uses the specified name, name prefix, specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not and VMSourceImageId (Image reference from an Azure Compute Gallery) and create a PooledHostPool with the default values
- PersonalHostPool(Name, Location, NamePrefix, MaxSessionLimit, VMNumberOfInstances, KeyVault, IsMicrosoftEntraIdJoined, VMSize, ImagePublisherName, ImageOffer, ImageSku, FSLogix, MSIX): Uses the specified name, location, name prefix, max session limit, number of instances, specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not, VMSize, ImagePublisherName, ImageOffer, ImageSku, FSLogix and MSIX
- PersonalHostPool(Name, Location, NamePrefix, MaxSessionLimit, VMNumberOfInstances, KeyVault, IsMicrosoftEntraIdJoined, specifies if the PersonalHostPool will be Azure AD/Microsoft Entra ID joined or not , VMSize, VMSourceImageId, FSLogix, MSIX): Uses the specified name, name prefix, name prefix, max session limit, number of instances, VMSize,  VMSourceImageId (Image reference from an Azure Compute Gallery), ImagePublisherName, ImageOffer, ImageSku, FSLogix and MSIX

#### PersonalHostPool PowerShell Class > Methods  

- ResetIndex: Reset the Index to 0

> [!NOTE]
> I choose to not implement FSLogix and MSIX for Personal HostPool this scenario (Maybe in the future)
