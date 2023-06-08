# Azure Image Builder

The [Azure-Image-Builder.ps1](Azure-Image-Builder.ps1) script creates an [Azure Compute Gallery](https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery) with 2 image definitions as shown below:

![](docs/acg.jpg)

### Prerequisites 

  * An [Azure](https://portal.azure.com) Subscription

### Setup

Run the [Azure-Image-Builder.ps1](Azure-Image-Builder.ps1) script (PowerShell 5.1 needed) wait for completion (~15 minutes).

**Notes:**
* The first image (as listed in the above screenshot - but second template in the [Azure-Image-Builder.ps1](Azure-Image-Builder.ps1) script)
  * Will use the latest Windows 11 Enterprise 22H2 with Office 365 optimized [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop) for image from the Azure Marketplace
  * [Visual Studio Code](https://code.visualstudio.com/) will be installed
* The second image definition is based on the [armTemplateAVD.json](armTemplateAVD.json) file. (as listed in the above screenshot - but first template in the Azure-Image-Builder.ps1 script)
  * Will use the latest Windows 11 Enterprise 22H2 image from the Azure Marketplace
  * The Azure VM will use the [Standard_D2s_v3](https://learn.microsoft.com/en-us/azure/virtual-machines/dv3-dsv3-series) Azure VM (127GB for the disk space).
  * [FSLogix](https://learn.microsoft.com/en-us/fslogix/overview) will be installed and configured
  * The OS will be optimized for [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop)
  * Teams will be installed and configured
  * [Visual Studio Code](https://code.visualstudio.com/) will be installed
  * The Windows updates will be installed
