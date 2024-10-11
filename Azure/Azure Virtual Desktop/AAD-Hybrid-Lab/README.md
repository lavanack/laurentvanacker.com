# Azure Active Directory Hybrid Lab

This is lab is based on the the one available on [https://aka.ms/m365avdws](https://aka.ms/m365avdws) with some differences:

* Using Windows Server 2022 G2 image
* Using a Standard_D2s_v5 VM (instead of a Standard_D2s_v4)
* The "Internet Explorer Enhanced Security Configuration" is disabled for Administrators and Users
* Possibility to set the VM as Azure Spot Instance (deallocation based on capacity - not recommended in production. I use this to reduce my bill on my dev/test environments)
* More choices for the Azure resources names (based on a small naming convention - cf. [https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool](https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool))
* A DNS entry for reaching the Domain Controller (Azure VM) (\<VMName\>.\<location\>.cloudapp.azure.com).
* Adding the BGInfo extension
* The DSC Configuration has been optimized to use the latest version of the DSC modules (xActiveDirectory --> ActiveDirectoryDSC, xNetworking --> NetworkingDSC and xComputerManagement --> ComputerManagementDSC) and the Script DSC resources used return the right boolean value (instead of hard-coded $false value)
* Added an (empty) AVD Organizational Unit (for my needs)
* [Visual Studio Code](https://code.visualstudio.com) and [PowerShell (7+)](https://github.com/PowerShell/PowerShell) are also installed.
* All demo users are members of a "AVD Users" Domain Group (in their Organizational Unit)

## Quick Start

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flavanack%2Flaurentvanacker.com%2Fmaster%2FAzure%2FAzure%20Virtual%20Desktop%2FAAD-Hybrid-Lab%2Fdeploy.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

## Notes
A PowerShell version is available on [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell)
