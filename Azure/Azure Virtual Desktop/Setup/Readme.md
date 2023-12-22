# Azure Virtual Desktop -Proof Of Concept - PowerShell version

- [Azure Virtual Desktop -Proof Of Concept - PowerShell version](#azure-virtual-desktop--proof-of-concept---powershell-version)
  - [Prerequisites](#prerequisites)
  - [What this script does ?](#what-this-script-does-)
  - [Script Explanation](#script-explanation)
    - [HostPool PowerShell Classes](#hostpool-powershell-classes)
    - [Required PowerShell Modules](#required-powershell-modules)
    - [Azure Connection](#azure-connection)
    - [Azure Key Vault for Credentials](#azure-key-vault-for-credentials)
    - [Azure Compute Gallery](#azure-compute-gallery)
  - [Cleanup](#cleanup)
  - [Deployment](#deployment)
  - [Remote Desktop Connection Manager](#remote-desktop-connection-manager)
  - [Transcript](#transcript)
  - [Testing](#testing)
  - [New-AzAvdHostPoolSetup: Technical Details](#new-azavdhostpoolsetup-technical-details)

## Prerequisites

Before continuing, make sure you have a domain controller (Windows Server with the Active Directory Directory Services role installed and configured) available in your Azure subscription. If not, you can use one of the following links to create these resources (from the least preferred to the most preferred option):

- [https://aka.ms/m365avdws](https://aka.ms/m365avdws)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell) (Only the New-AAD-Hybrid-Lab.ps1: Step-by-step guide is needed - the rest optional)

## What this script does ?

The goal of this script is to deploy multiple full Azure Virtual Desktop environments in a few minutes. The script is based on the Microsoft documentation and best practices.
Every script execution will generate a timestamped transcript in the script directory.

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
This function has a -AsJob parameter. When this switch is specified, the ressources will be deployed in parallel (via the [Start-ThreadJob](https://learn.microsoft.com/en-us/powershell/module/threadjob/start-threadjob?view=powershell-7.4&viewFallbackFrom=powershell-5.1) cmdlet) instead of sequentially. The processing time is greatly reduced from 4h to 1h (including the Azure Compute Gallery Setup if needed - wihout the Azure Compute Gallery Setup, the processing time are 3h30 in parallel and 30 minutes sequentially). Nevertheless, sometimes the setup fails in parallel mode (some error occurs) so I recommend to use the sequential mode if any error occurs ib this mode (or retry).
> [!NOTE]
> The impacted ressources by the parallel mode are the HostPools and the Session Hosts. The Job Management is done at the end of the The `New-AzAvdHostPoolSetup` function.

## Remote Desktop Connection Manager

At the end of the deployment an RDCMan (<domain name>.rdg) file generated on the Desktop will all information to connect to the deployed Azure VMs. You can use this file with the [Remote Desktop Connection Manager](https://download.sysinternals.com/files/RDCMan.zip) tool to connect to the Session Hosts. For the Azure AD/Microsoft Entra ID joined VM, the local admin credentials are stored in this file for an easier connection.
![Remote Desktop Connection Manager](docs/rdcman.jpg)

## Transcript

Every run will generate a timestamped transcript in the script directory. 

## Testing

After a successful deployment, you can connect to [Remote Desktop Web Client](https://client.wvd.microsoft.com/arm/webclient/index.html) or [Windows 365](https://windows365.microsoft.com/) site and use on the of the test users (available in the `OrgUsers` OU).

## New-AzAvdHostPoolSetup: Technical Details

If you want to know more about the `New-AzAvdHostPoolSetup` function, you can read the paragraph else happy testing ;) 