# Azure Virtual Desktop -Proof Of Concept - PowerShell version

- [Azure Virtual Desktop -Proof Of Concept - PowerShell version](#azure-virtual-desktop--proof-of-concept---powershell-version)
  - [Prerequisites](#prerequisites)
  - [What this script does ?](#what-this-script-does-)
  - [TL;DR](#tldr)
  - [Script Explanation](#script-explanation)
    - [HostPool PowerShell Classes](#hostpool-powershell-classes)
    - [Required PowerShell Modules](#required-powershell-modules)
    - [Azure Connection](#azure-connection)
    - [Azure Key Vault for Credentials](#azure-key-vault-for-credentials)
    - [Azure Compute Gallery](#azure-compute-gallery)
  - [Cleanup](#cleanup)
  - [Deployment](#deployment)
  - [Remote Desktop Connection Manager](#remote-desktop-connection-manager)
  - [Testing](#testing)
  - [Technical Details](#technical-details)
    - [New-AzAvdHostPoolSetup.ps1](#new-azavdhostpoolsetupps1)
    - [New-AzAvdPooledHostPoolSetup.ps1](#new-azavdpooledhostpoolsetupps1)
    - [New-AzAvdPersonalHostPoolSetup](#new-azavdpersonalhostpoolsetup)
    - [Helpers functions](#helpers-functions)
    - [Deliverables](#deliverables)

> [!IMPORTANT]
> This script is my version of an Azure Virtual Desktop (AVD) Proof Of Concept (POC) and is not intended to be used in production. It is provided "AS IS" without warranty of any. It was written during my rampup on AVD and to summarize in one location some best practices. It covers OnPrem and Azure setups in one PowerShell script.
> If you want to deploy a Microsoft supported version I recommend to use The Azure Virtual Desktop (AVD) Landing Zone Accelerator (LZA) available [here](https://github.com/Azure/avdaccelerator) (Covers only the Azure part)

## Prerequisites

Before continuing, make sure you have a domain controller (Windows Server with the Active Directory Directory Services role installed and configured) available in your Azure subscription. If not, you can use one of the following links to create these resources (from the least preferred to the most preferred option):

- [https://aka.ms/m365avdws](https://aka.ms/m365avdws)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell) (Only the New-AAD-Hybrid-Lab.ps1: Step-by-step guide is needed - the rest is optional)

> [!IMPORTANT]
> This script has to be run from the Domain Controller (from any local folder) from an account with the domain administrator privileges. Azure privilege role is also required (Global Administrator for instance) to deploy the Azure resources.

## What this script does ?

The goal of this script is to deploy multiple full Azure Virtual Desktop environments in a few minutes. The script is based on the Microsoft documentation and best practices.
Every script execution will generate a timestamped transcript in the script directory.

## TL;DR

If you don't want to continue reading, here is the [TL;DR](https://dictionary.cambridge.org/dictionary/english/tldr) version:

- The script, with its default values, will deploy 5 HostPools (3 Pooled and 2 Personal) with 3 Session Hosts each (all session hosts will be AD Domain joined except for one Personal that will be Azure AD/Microsoft entra ID joined). One Pooled HostPool will be configured with FSLogix and MSIX. The Session Hosts will be deployed in the `EastUS` Azure region. Some recommendations/best practices are also applied (like A/V exclusions, FSLogix Settings, etc.).

## Script Explanation

The script is around 4000 lines of code and is divided into differents regions and parts I need to explain.

### HostPool PowerShell Classes

At the start of the script, you'll see I created a PowerShell class for each HostPool type (Personal vs. Pooled). The both classes (PooledHostPool and PersonalHostPool) inherits from a base class (HostPool). The base class contains the common properties and methods for both HostPool types.
> [!NOTE]
> All details for these classes are available [here](./HostPoolClasses.md).

The class defintions are loaded at the beginning of the script.

There are some use cases for every kind of HostPool type at the end of the script to define the HostPool type you want to deploy:

```powershell:
# Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and MSIX
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault)
# Use case 2: Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined), a custom Index (random number here) and without FSLogix and MSIX
[PersonalHostPool]::new($RandomNumber, $HostPoolSessionCredentialKeyVault, $false)
# Use case 3: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined), a custom name and without FSLogix and MSIX
[PersonalHostPool]::new("hp-pd-ei-poc-mp-eu-{0:D2}" -f $RandomNumber, $null, "pepocmeu{0}" -f $RandomNumber, $null, $HostPoolSessionCredentialKeyVault, $true, $null, $null, $null, $null)
# Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with an Image coming from an Azure Compute Gallery and without FSLogix and MSIX
$PooledHostPool = [PooledHostPool]::new("hp-np-ad-poc-cg-eu-{0:D2}" -f $Index, "EastUS", "napocceu{0}" -f $Index, 5, 3, $HostPoolSessionCredentialKeyVault, "Standard_D2s_v3", $VMSourceImageId, $FSlogix, $MSIX)
```

This class is used to defined the HostPool objects you want to deploy in Azure and the code will do the rest for you.

### Required PowerShell Modules

The script requires some PowerShell modules to be installed on the machine (ADDS Domain Controller) where you'll run the script. The script will check if the modules are installed and if not, it will install them for you.
> [!WARNING]
> I fill a bug on the 7+ version of the Az.Compute module preventing the successful run of the Azure Compute Gallery. When writing this documentation (December 2023), the bug is not fixed. I encourage you to use the 6.3.0 version of the Az.Compute module as a temporary fix (and to uninstall all newer versions). You can install it with the following PowerShell command line (from an elevated PowerShell Host):  
`Install-Module -Name Az.Compute -RequiredVersion 6.3.0.0 -Force -Verbose -AllowClobber`

### Azure Connection

The script will ask you to connect to your Azure subscription and to you Microsoft Entra ID for you if you are not.

### Azure Key Vault for Credentials

You probably noticed the `$HostPoolSessionCredentialKeyVault` variable in the previous code snippet. This variable is used to define the Azure Key Vault where the credentials for the Session Hosts will be stored.
We have to store 4 secrets in the Azure Key Vault:

- `LocalAdminUserName`: The user name for the local administrator account on the Session Hosts
- `LocalAdminPassword`: The password for the local administrator account on the Session Hosts
- `ADJoinUserName`: The user name for the account used to join the Session Hosts to the Active Directory domain
- `ADJoinPassword`: The password for the account used to join the Session Hosts to the Active Directory domain

You can use your own KeyVault (with these 4 secret names) or let the script create one for you : We do this with the `New-AzHostPoolSessionCredentialKeyVault` function.

The `New-AzHostPoolSessionCredentialKeyVault` function have hard coded values for `LocalAdminUserName` and  `ADJoinUserName` (respectively `localadmin` and `adjoin` - feel free to customize to you needs). The value for the `LocalAdminPassword` is also hard coded for a simple reason : If the user specified as value of the `LocalAdminUserName` secret already exists in the Active Directory domain, we need to specify the right password. If the user doesn't exist, the script will create it in the Active Directory domain with the password specified in the `LocalAdminPassword` secret.
The value for the `ADJoinPassword` is randomly generated with the `New-RandomPassword` function (for information it will be written in the output).

### Azure Compute Gallery

I also create an Azure Compute Gallery with the `New-AzComputeGallery` function. All details are [here](../Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder#azureimagebuilderps1) (AzureImageBuilder.ps1 paragraph only - nevertheless you can read all the article to see  some posibilities an Azure Compute Gallery can offer). If you prefer use your own Azure Compute Gallery images, you can comment the call to `New-AzComputeGallery` function and adjust the Azure Compute Gallery to use in the lines starting with:
  
  ```powershell
$AzureComputeGallery = Get-AzGallery ...
...
$GalleryImageDefinition = Get-AzGalleryImageDefinition -GalleryName ...
```

## Cleanup

If you have already deployed an Azure Virtual Desktop environment with this script and want to do some cleanup  of the existing environment, you can use the `Remove-AzAvdHostPoolSetup` function. This function takes an HostPool array as parameter (so set the parameter values you used for the already deployed environement). It will remove all the resources created by the script (HostPool, Session Hosts, Application Groups, Workspace, etc.) based on the HostPool array. Some cleanup are also done in the Active Directory domain (removing the computer accounts of the Session Hosts and the Azure File Shares ...) and the Windows Credential Manager.
You can also use the `Remove-AzAvdHostPoolSetup` function after the deployment to remove the environment if you are not satisfied with the result or to save costs after testing the deployed resources.

## Deployment

The `New-AzAvdHostPoolSetup` function is the main function of the script. It takes an HostPool array as parameter (so set the parameter values you want for the HostPool(s) you want to deploy). It will deploy all the resources needed for the HostPool(s) based on the HostPool array.  
This function has a `-AsJob` parameter. When this switch is specified, the ressources will be deployed in parallel (via the [Start-ThreadJob](https://learn.microsoft.com/en-us/powershell/module/threadjob/start-threadjob?view=powershell-7.4&viewFallbackFrom=powershell-5.1) cmdlet) instead of sequentially. The processing time is greatly reduced from 4h to 1h (including the Azure Compute Gallery Setup if needed - wihout the Azure Compute Gallery Setup, the processing time are 3h30 in parallel and 30 minutes sequentially). Nevertheless, sometimes the setup fails in parallel mode (some error occurs) so I recommend to use the sequential mode if any error occurs ib this mode (or retry).
> [!NOTE]
> The impacted ressources by the parallel mode are the HostPools and the Session Hosts. The Job Management is done at the end of the The `New-AzAvdHostPoolSetup` function.

## Remote Desktop Connection Manager

At the end of the deployment an RDCMan (\<domain name\>.rdg) file generated on the Desktop will all information to connect to the deployed Azure VMs. You can use this file with the [Remote Desktop Connection Manager](https://download.sysinternals.com/files/RDCMan.zip) tool to connect to the Session Hosts. For the Azure AD/Microsoft Entra ID joined VM, the local admin credentials are stored in this file for an easier connection.

![Remote Desktop Connection Manager](docs/rdcman.jpg)

## Testing

After a successful deployment, you can connect to [Remote Desktop Web Client](https://client.wvd.microsoft.com/arm/webclient/index.html) or [Windows 365](https://windows365.microsoft.com/) site and use on the of the test users (available in the `OrgUsers` OU).

## Technical Details

If you want to know more about the `New-AzAvdHostPooledPoolSetup`, `New-AzAvdHostPersonalPoolSetup` and `New-AzAvdHostPoolSetup` functions, you can read the paragraph else happy testing ;)

### New-AzAvdHostPoolSetup.ps1

Ths function is the core function of the script. It proceeds as follows:

- The required DNS forwarders are created in the Active Directory DNS (if not already created) for the Azure File Shared and the Azure Key Vaults.
- The `AVD` Organization Unit (OU) is created in the Active Directory domain (if not already created). A GPO is created and linked to this OU. The following settings are configured:
  - Network Settings
  - Session Time Settings
  - Enabing [Screen Capture Protection](https://learn.microsoft.com/en-us/azure/virtual-desktop/screen-capture-protection)
  - Enabling [Watermarking](https://learn.microsoft.com/en-us/azure/virtual-desktop/watermarking)
  - Enabling and using the new [performance counters](https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay)
- The `AVD/PersonalDesktops` and `AVD/PooledDesktops` are also created
- The following Starter GPOs `Group Policy Reporting Firewall Ports` and `Group Policy Remote Update Firewall Ports` are also created and linked to the `AVD` OU
- The Desktop Virtualization Power On Contributor` role-based access control (RBAC) role is assigned to the Azure Virtual Desktop service principal with your Azure subscription as the assignable scope. More details [here](https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal).
- Every HostPool is processed based on its type (more details [here](HostPoolClasses.md)) by calling either the `New-AzAvdPersonalHostPoolSetup` or the `New-AzAvdPooledHostPoolSetup` function (sequentially or via a parallel processing if the `-AsJob` switch is specified).

### New-AzAvdPooledHostPoolSetup.ps1

This function is called by the `New-AzAvdHostPoolSetup` function for every HostPool of type Pooled. It proceeds as follows:

- A dedicated OU is created in the Active Directory domain (under the `AVD/PooledDesktops` OU) for the every Pooled HostPool. The OU name is the HostPool name.
- The ADJoin user (The related credentials are stored in the Azure Key Vault) is created if not already present and receive the required rights to add computer accounts to the Active Directory domain.
- A Security Global AD Group is created with the naming convention `<HostPoolName> - Users` (all test users - via the `AVD Users` AD security Group - are added to the created groups at the end of the script).
- A dedicated Azure Resource Group is created for the HostPool (a naming convention `rg-avd-<HostPoolName>`)
- If FSLogix is required:
  - A FSLogix file share (called `profiles`) is created in a dedicated Storage Account (a naming convention `fsl<HostPoolName without dashes and in lowercase>`) on the dedicated resource group, the [required NTFS permissions](https://learn.microsoft.com/en-us/fslogix/how-to-configure-storage-permissions#recommended-acls) are set and the account is registered in the Active Directory Domain. The credentials for the storage account are stored in Windows Credential Manager. A [redirections.xml](https://learn.microsoft.com/fr-fr/fslogix/tutorial-redirections-xml) file is also created in the file share.
    An `odfc` fileshare is also created for the Office Container but it is not used for the moment.
  - A Private Endpoint is created for the Storage Account and the required DNS configuration is also created.
  - 3 dedicated AD security groups are created and the required role assignments are done
    - `<HostPoolName> - FSLogix Contributor` (`Storage File Data SMB Share Contributor` role assignment on the Azure File Share): This AD group will contain the end-users that will have a FSLogix Profile Container.
    - `<HostPoolName> - FSLogix Elevated Contributor` (`Storage File Data SMB Share Elevated Contributor` role assignment on the Azure File Share)
    - `<HostPoolName> - FSLogix Reader` (`Storage File Data SMB Share Reader` role assignment on the Azure File Share)
  - A GPO is also created (name : `<HostPoolName> - FSLogix Settings`) with some settings for:
    - [Profile Container](https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration)
    - [Timezone redirection](https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection)
    - [Disabling automatic updates](https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates)
    - [Disabling Storage Sense](https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense)
    - [Setting antivirus exclusions](https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions)
    - A FSLogix Profile Container exclusion is set for the `Domain Admins` group
  
- If MSIX is required:
  - A MSIX file share (called `msix`) is created in a dedicated Storage Account (a naming convention `msix<HostPoolName without dashes and in lowercase>`) on the dedicated resource group, the [required NTFS permissions](https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#permissions) are set and the account is registered in the Active Directory Domain. The credentials for the storage account are stored in Windows Credential Manager.
  - A Private Endpoint is created for the Storage Account and the required DNS configuration is also created.
  - 3 dedicated AD security groups are created and the required role assignments are done
    - `<HostPoolName> - MSIX Hosts` (`Storage File Data SMB Share Contributor` role assignment on the Azure File Share). This AD group will contain the Session Hosts that will have a MSIX App Attach.
    - `<HostPoolName> - MSIX Share Admins` (`Storage File Data SMB Share Elevated Contributor` role assignment on the Azure File Share)
    - `<HostPoolName> - MSIX Users` (`Storage File Data SMB Share Contributor` role assignment on the Azure File Share). This AD group will contain the end users that will have a MSIX App Attach.
  - A GPO is also created (name : `<HostPoolName> - MSIX Settings`) with some settings for:
    - [Turning off automatic updates for MSIX app attach applications](https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications)
    - [Setting antivirus exclusions](https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions)
  - Some demo applications (and related certificate) are also deployed  from [here](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX)
- An Azure Key Vault is also created (with the naming convention `kv-<HostPoolName without dashes>`) on the dedicated resource group. This KeyVault is secure via a Private Endpoint and the required DNS configuration is also created. This KeyVault is deployed for testing purpose only and is not used for the moment.
- A Pooled Hostpool is also created (with `BreadthFirst` load balancer type)
- A Desktop Application Group is also created (with the naming convention `<HostPoolName>-DAG`) and the `Desktop Virtualization User` RBAC role is assigned to the `<HostPoolName> - Users` AD security group.
- A Remote Application Group is also created (with the naming convention `<HostPoolName>-RAG`) and the `Desktop Virtualization User` RBAC role is assigned to the `<HostPoolName> - Users` AD security group.
- A Workspace is also created (with the naming convention `ws-<HostPoolName>`)
- The Session Hosts are added to the HostPool and are AD Domain joined.
- A Log Analytics Workspace is also deployed (with the naming convention `opiw-<HostPoolName>`) and the Session Hosts are connected to it. More details can be found [here](https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor) and [here](https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021). Some event logs and performance counters are also configured to be collected.
- The Log Analytics Agent is also installed on the Session Hosts
- The VM insights are enabled by using PowerShell via [Data Collection Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview?tabs=portal)

### New-AzAvdPersonalHostPoolSetup

This function is called by the `New-AzAvdHostPoolSetup` function for every HostPool of type Personal. It proceeds as follows:

- A dedicated OU is created in the Active Directory domain (under the `AVD/PersonalDesktops` OU) for the every Personal HostPool. The OU name is the HostPool name.
- The ADJoin user (The related credentials are stored in the Azure Key Vault) is created if not already present and receive the required rights to add computer accounts to the Active Directory domain.
- A Security Global AD Group is created with the naming convention `<HostPoolName> - Users` (all test users - via the `AVD Users` AD security Group - are added to the created groups at the end of the script).
- A dedicated Azure Resource Group is created for the HostPool (a naming convention `rg-avd-<HostPoolName>`)
- An Azure Key Vault is also created (with the naming convention `kv-<HostPoolName without dashes>`) on the dedicated resource group. This KeyVault is secure via a Private Endpoint and the required DNS configuration is also created. This KeyVault is deployed for testing purpose only and is not used for the moment.
- A Personal Hostpool is also created
- A Desktop Application Group is also created (with the naming convention `<HostPoolName>-DAG`) and the `Desktop Virtualization User` RBAC role is assigned to the `<HostPoolName> - Users` AD security group.
- A Remote Application Group is also created (with the naming convention `<HostPoolName>-RAG`) and the `Desktop Virtualization User` RBAC role is assigned to the `<HostPoolName> - Users` AD security group.
- A Workspace is also created (with the naming convention `ws-<HostPoolName>`)
- The Session Hosts are added to the HostPool and are either Azure AD/Microsoft Entra ID or AD Domain joined. If the Session hosts are Azure AD/Microsoft Entra ID joined, the 'Virtual Machine Administrator Login' RBAC role is assigned to the `<HostPoolName> - Users` AD security group.
- A Log Analytics Workspace is also deployed (with the naming convention `opiw-<HostPoolName>`) and the Session Hosts are connected to it. More details can be found [here](https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor) and [here](https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021). Some event logs and performance counters are also configured to be collected.
- The Log Analytics Agent is also installed on the Session Hosts
- The VM insights are enabled by using PowerShell via [Data Collection Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview?tabs=portal)

### Helpers functions

Some helper functions are also available in the script but are not documented here.

### Deliverables

At the end of the deployment, the following deliverables are available (the following screenshots are with the default values):

- A timestamped transcript file in the script directory
- A .rdg file on the Desktop with all the information to connect to the Session Hosts (cf. [here](#remote-desktop-connection-manager))
- A dedicated Organization Unit (OU) in the Active Directory domain for every HostPool

![Organization Units](docs/ou.jpg)

- Some GPOs
  - 'AVD Global Settings' GPO linked to the `AVD` OU
  - '`<HostPoolName>` - FSLogix Settings' GPO linked to the `<HostPoolName>` OU for the FSLogix Settings (if FSLogix is required) per HostPool
  - '`<HostPoolName>` - MSIX Settings' GPO linked to the `<HostPoolName>` OU for the MSIX Settings (if MSIX is required) per HostPool
  - 2 starter GPOs linked to the `AVD` OU
    - 'Group Policy Reporting Firewall Ports'
    - 'Group Policy Remote Update Firewall Ports'

![GPOs](docs/gpo.jpg)

- Different HostPools (based on the HostPool type you setup)

![HostPools](docs/hostpool.jpg)
