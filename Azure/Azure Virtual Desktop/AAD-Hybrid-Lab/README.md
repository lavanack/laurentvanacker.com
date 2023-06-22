# Azure Active Directory Hybrid Lab

This is lab is based on the the one available on [https://aka.ms/m365avdws](https://aka.ms/m365avdws) with some differences:

* Using Windows Server 2022 G2 image
* Possibility to set the VM as Azure Spot Instance (deallocation based on capacity - not recommended in production. I use this to reduce my bill on my dev/test environements)
* More choices for the Azure resources names (based on a small naming convention - cf. [https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool](https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool))
* A DNS entry for reaching the Domain Controller (Azure VM) (\<VMName\>.\<location\>.cloudapp.azure.com).
* Adding the BGInfo extension
* The DSC Configuration has been optimized to use the latest version of the DSC modules (xActiveDirectory --> ActiveDirectoryDSC, xNetworking --> NetworkingDSC and xComputerManagement --> ComputerManagementDSC) and the Script DSC resources used return the right boolean value (instead of hard-coded $false value)
* Added an (empty) AVD Organizational Unit (for my needs)  

## Quick Start

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flavanack%2Flaurentvanacker.com%2Fmaster%2FAzure%2FAzure%20Virtual%20Desktop%2FAAD-Hybrid-Lab%2Fdeploy.json" target="_blank"><img src="http://azuredeploy.net/deploybutton.png"/></a>
