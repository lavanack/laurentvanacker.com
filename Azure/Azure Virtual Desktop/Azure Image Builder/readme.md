# Azure Image Builder

The [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script creates an [Azure Compute Gallery](https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery) with 2 image definitions as shown below:

![](docs/acg.jpg)

### Prerequisites 

  * An [Azure](https://portal.azure.com) Subscription

### Setup

Run the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script (PowerShell 5.1 needed) wait for completion (~40 minutes).

**Notes:**

* The first image definition is based on the [armTemplateAVD.json](armTemplateAVD.json) file.
  * Will use the latest Windows 11 Enterprise 22H2 Multi-Session (without Microsoft 365) image from the Azure Marketplace
  * The Azure VM will use the [Standard_D4s_v3](https://learn.microsoft.com/en-us/azure/virtual-machines/dv3-dsv3-series) Azure VM (127GB for the disk space).
  * The OS will be optimized for [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop). These optimisations come from the [RDS-Templates GitHub](https://github.com/Azure/RDS-Templates/tree/master/CustomImageTemplateScripts). These scripts are supported by the AVD Product Group. The [AVD Accelerator](https://github.com/Azure/avdaccelerator) scripts are maintained by the community/field and are not officially supported by Microsoft. 
  * [Visual Studio Code](https://code.visualstudio.com/) will be installed
  * The Windows latest updates will be installed
  * The autoupdate feature will be disabled
  * The TimeZone Redirection feature will be enabled
* The second image is based on a market place image
  * Will use the latest Windows 11 Enterprise 22H2 with Microsoft 365 optimized [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop) for image from the Azure Marketplace
  * [Visual Studio Code](https://code.visualstudio.com/) will be installed

**Remarks:**

The script [AzureImageBuilder with CMK.ps1](AzureImageBuilder%20with%20CMK.ps1) is an example to show how to use a customer-managed key to encrypt a VM Image Version. It was asked by a customer
