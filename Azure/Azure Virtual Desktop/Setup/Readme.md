# Azure Virtual Desktop -Proof Of Concept - PowerShell version

- [Azure Virtual Desktop -Proof Of Concept - PowerShell version](#azure-virtual-desktop--proof-of-concept---powershell-version)
  - [Prerequisites](#prerequisites)
  - [What this script does ?](#what-this-script-does-)
  - [Script Explanation](#script-explanation)
    - [HostPool PowerShell Classes](#hostpool-powershell-classes)
    - [Azure Key Vault for Credentials](#azure-key-vault-for-credentials)
    - [Azure Compute Gallery](#azure-compute-gallery)
  - [Deployment](#deployment)

## Prerequisites

Before continuing, make sure you have a domain controller (Windows Server with the Active Directory Directory Services role installed and configured) available in your Azure subscription. If not, you can use one of the following links to create these resources (from the least preferred to the most preferred option):

- [https://aka.ms/m365avdws](https://aka.ms/m365avdws)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab)
- [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell) (Only the New-AAD-Hybrid-Lab.ps1: Step-by-step guide is needed - the rest optional)

## What this script does ?

The goal of this script is to deploy multiple full Azure Virtual Desktop environments in a few minutes. The script is based on the Microsoft documentation and best practices.

## Script Explanation

The script is around 4000 lines of code and is divided into differents regions and parts I need to explain.

### HostPool PowerShell Classes

At the start f the script, you'll see I created a PowerShell class for each HostPool type (Personal vs. Pooled). The both classes (PooledHostPool and PersonalHostPool) inherits from a base class (HostPool). The base class contains the common properties and methods for both HostPool types.
> [!NOTE]
> All details for these classes are available [here](./HostPoolClasses.md).

There are some use cases for every kind of HostPool type at the end of the script to define the HostPool type you want to deploy:

```powershell:
# Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and MSIX
[PooledHostPool]::new($HostPoolSessionCredentialKeyVault)
# Use case 2: Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined) without FSLogix and MSIX
[PersonalHostPool]::new($RandomNumber, $HostPoolSessionCredentialKeyVault, $false)
# Use case 3: Deploy a Personal HostPool with 3 (default value) Session Hosts (AD Domain joined) without FSLogix and MSIX
[PersonalHostPool]::new("hp-pd-ei-poc-mp-eu-{0:D2}" -f $RandomNumber, $null, "pepocmeu{0}" -f $RandomNumber, $null, $HostPoolSessionCredentialKeyVault, $true, $null, $null, $null, $null)
# Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with an Image coming from an Azure Compute Gallery and without FSLogix and MSIX
$PooledHostPool = [PooledHostPool]::new("hp-np-ad-poc-cg-eu-{0:D2}" -f $Index, "EastUS", "napocceu{0}" -f $Index, 5, 3, $HostPoolSessionCredentialKeyVault, "Standard_D2s_v3", $VMSourceImageId, $FSlogix, $MSIX)
```

This class is used to defined the HostPool objects you want to deploy in Azure and the code will do the rest for you.

### Azure Key Vault for Credentials

You probably noticed the `$HostPoolSessionCredentialKeyVault` variable in the previous code snippet. This variable is used to define the Azure Key Vault where the credentials for the Session Hosts will be stored.
We have to store 4 secrets in the Azure Key Vault:

- `LocalAdminUserName`: The user name for the local administrator account on the Session Hosts
- `LocalAdminPassword`: The password for the local administrator account on the Session Hosts
- `ADJoinUserName`: The user name for the account used to join the Session Hosts to the Active Directory domain
- `ADJoinPassword`: The password for the account used to join the Session Hosts to the Active Directory domain

You can use your own KeyVault (with these 4 secrets) or let the script create one for you : We do this with the `New-AzHostPoolSessionCredentialKeyVault` function.

The `New-AzHostPoolSessionCredentialKeyVault` function have hard coded values for `LocalAdminUserName` and  `ADJoinUserName` (respectively `localadmin` and `adjoin` - feel free to customize to you needs). The value for the `LocalAdminPassword` is also hard coded for a simple reason : If the user specified as value of the `LocalAdminUserName` secret already exists in the Active Directory domain, we need to specify the right password. If the user doesn't exist, the script will create it in the Active Directory domain with the password specified in the `LocalAdminPassword` secret.
The value for the `ADJoinPassword` is randomly generated with the `New-RandomPassword` function (for information it will be written in the output).

### Azure Compute Gallery

## Deployment
