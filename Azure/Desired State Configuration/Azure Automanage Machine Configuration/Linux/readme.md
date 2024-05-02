# Azure Automage Machine Configuration

The [1 - AzureVMWithAzureAutomanageMachineConfiguration](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1) script creates a Linux Azure VM. After, you'll have to run the [2 - Prerequisites.sh](2%20-%20Prerequisites.sh) script from the newly created Azure VM to deploy some DSC resources (Package, User, Group ...). The DSC configuration used is the `AzureArcJumpstart_Linux` configuration you can find [here](https://azurearcjumpstart.com/azure_arc_jumpstart/azure_arc_servers/day2/arc_automanage/arc_automanage_machine_configuration_custom_linux#custom-configuration-for-linux).

## Table of Contents

- [Azure Automage Machine Configuration](#azure-automage-machine-configuration)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
    - [Setup](#setup)

## Prerequisites

- An [Azure](https://portal.azure.com) Subscription

### Setup

- Run the [1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1) script (PowerShell 5.1 needed) wait for completion (~10 minutes).
- The required scripts (Shell Unix and Powershell) are copied on the newly created VM.
- A Shell session to the VM will open
- Run the [2 - Prerequisites.sh](2%20-%20Prerequisites.sh) script from this shell session to install some prerequisites and useful tools (Powershell modules, [PowerShell 7+](https://github.com/PowerShell/powershell/releases), [Visual Studio Code](https://code.visualstudio.com/), ...).  
- The [2 - Prerequisites.sh](2%20-%20Prerequisites.sh) script will also call the [3 - AzureAutomanageMachineConfiguration.ps1](3%20-%20AzureAutomanageMachineConfiguration.ps1) to apply the [Deploy prerequisites to enable Guest Configuration policies on virtual machines](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policySetDefinitions/Guest%20Configuration/GuestConfiguration_Prerequisites.json) initiative and will deploy your Desired State Configuration just after.

**Notes:**

- If you are already connected (via [Connect-Azaccount](https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount)) to Azure, you will be prompted to connect.
- The Azure VM will run the latest version of 'Ubuntu 22.04 LTS' Generation 2 in a [Standard_D4s_v5](https://learn.microsoft.com/en-us/azure/virtual-machines/dv5-dsv5-series) Azure VM.
- The Azure VM will be a [Spot Instance](https://learn.microsoft.com/en-us/azure/virtual-machines/spot-vms) with a 'Deallocate' [eviction policy](https://learn.microsoft.com/en-us/azure/architecture/guide/spot/spot-eviction#eviction-policy) based on capacity (not price) to save money. You can disable that if you want (around line 185 in the [1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1) script).
- The VM will be deployed on the eastus region (You can use the non Microsoft <https://cloudprice.net/> web site to compare cost in different regions for cost savings) . You can change  that if you want (around line 79 in the [[1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1) script).
- The VM name is randomly generated with the template vmdscamcYYYXXXX where YYY and a 3-letter acronym for the Azure location and X is a digit to avoid duplicate names (an availability test is done around line 82 in the [[1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1) script). A global naming convention is also set for all Azure resources.
- A DNS Name is set under the form \<VMName\>.\<Location\>.cloudapp.azure.com (for instance vmdscamcYYYXXXX.eastuse.cloudapp.azure.com) and used for the browser connection (the pblic IP is not directly used).
- A daily scheduled shutdown at 11:00 PM (in your local timezone) is set for the VM (no automatic start is set).
- The SSH and RDP connections are only accessible from the IP where you run the script (done via a query to <https://ipv4.seeip.org>) via a [Network Security Group](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works). If you want to give access to people from different IP you has to customize the SSH and RDP rules of the NSG or use the JIT access policy (next point).
![NSG](docs/nsg.jpg)
- A just-in-time access policy (3-hour long) is also set for SSH and RDP accesses.
![JIT](docs/jit.jpg)
- The HTTP and HTTPS connections (TCP/80 and TCP/443) are accessible from everywhere
- The password (for RDP connection) is randomly generated and displayed at the beginning and copied into your clipboard. The account name used is the same you are currently using (cf. the Username environment variable - so almost different for everyone). In addition these credentials will also be displayed at the end of the deployment process (in green) and added in the Credential Manager for an automatic connection in the upcoming RDP session (next point).
- The SSH connection is done via a SSH Public Key. You can specify the Path of this Key via the `SSHPublicKeyPath` parameter. If you omit it, we will look for this Key in your profile/home directory
- A SSH and a RDP sessions will be automatically opened at the end of the deployment process.
- After the DSC configuration is applied you can open a browser to the VM IP or FQDN and see NGinx has been installed.
![NGINX](docs/nginx.jpg)
