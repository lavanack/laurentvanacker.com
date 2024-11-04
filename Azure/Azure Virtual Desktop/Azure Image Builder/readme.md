# Azure Image Builder

- [Azure Image Builder](#azure-image-builder)
  - [AzureImageBuilder.ps1](#azureimagebuilderps1)
    - [Prerequisites](#prerequisites)
    - [Setup](#setup)
  - [AzureImageBuilder-v2.ps1](#azureimagebuilder-v2ps1)
  - [AzureImageBuilder-v3.ps1](#azureimagebuilder-v3ps1)
  - [AzureImageBuilder-v4.ps1](#azureimagebuilder-v4ps1)
  - [AzureImageBuilder-v5.ps1](#azureimagebuilder-v5ps1)
  - [AzureImageBuilder-v6.ps1](#azureimagebuilder-v6ps1)
  - [AzureImageBuilder-v7.ps1](#azureimagebuilder-v7ps1)
  - [AzureImageBuilder-v8.ps1](#azureimagebuilder-v8ps1)
  - [AzureImageBuilder with CMK.ps1](#azureimagebuilder-with-cmkps1)
  - [New-AzureComputeGalleryVM.ps1](#new-azurecomputegalleryvmps1)
  - [Get-AzureVMImageBuilderCustomizationLog.ps1](#get-azurevmimagebuildercustomizationlogps1)
  - [Get-AzureVMImageBuilderData.ps1](#get-azurevmimagebuilderdataps1)

## AzureImageBuilder.ps1

The [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script creates an [Azure Compute Gallery](https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery) with 2 image definitions as shown below:

![Azure Compute Gallery](docs/acg.jpg)

### Prerequisites

- An [Azure](https://portal.azure.com) Subscription

### Setup

Run the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script (PowerShell 5.1 needed) wait for completion (~40 minutes).

**Notes:**

- The first image definition is based on the [armTemplateAVD.json](armTemplateAVD.json) file.
  - Will use the latest Windows 11 Enterprise 22H2 Multi-Session (without Microsoft 365) image from the Azure Marketplace
  - The Azure VM will use the [Standard_D4s_v5](https://learn.microsoft.com/en-us/azure/virtual-machines/dv5-dsv5-series#dsv5-serieshttps://learn.microsoft.com/en-us/azure/virtual-machines/dv3-dsv3-series) Azure VM (127GB for the disk space).
  - The OS will be optimized for [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop). These optimisations come from the [RDS-Templates GitHub](https://github.com/Azure/RDS-Templates/tree/master/CustomImageTemplateScripts). These scripts are supported by the AVD Product Group. The [AVD Accelerator](https://github.com/Azure/avdaccelerator) scripts are maintained by the community/field and are not officially supported by Microsoft.
  - [Visual Studio Code](https://code.visualstudio.com/) will be installed
  - The Windows latest updates will be installed
  - The autoupdate feature will be disabled
  - The TimeZone Redirection feature will be enabled
  - The image is replicated in the EastUS and EastUS2 regions
- The second image is based on a market place image
  - Will use the latest Windows 11 Enterprise 22H2 with Microsoft 365 optimized [Azure Virtual Desktop](https://azure.microsoft.com/en-us/products/virtual-desktop) for image from the Azure Marketplace
  - All others settings are the same as the first image definition

## AzureImageBuilder-v2.ps1

The [AzureImageBuilder-v2.ps1](AzureImageBuilder-v2.ps1) script is almost the same than the previous one but adds the French and German language packs to the generated images (via ARM and PowerShell like the [AzureImageBuilder.ps1](AzureImageBuilder.ps1)).

## AzureImageBuilder-v3.ps1

The [AzureImageBuilder-v3.ps1](AzureImageBuilder-v3.ps1) script is an evolution of the [AzureImageBuilder-v2.ps1](AzureImageBuilder-v2.ps1)). It downloads Notepad++ installer and store it in an Azure Container. In additon a simple PowerShell script is also added in the same location to silently install Notepad++ on the VM during the image build. The Notepad++ installation occurs only in the PowerShell version (not in the ARM version) because I dynamically built the process with Powershell (Thinking to a V4 version).
In this version we use a win10-22h2-ent-g2 image from the Azure Marketplace (This was requested for a customer demo) and I have increased the build time out from 180 to 240 minutes. In addition, the VM size was switched from Standard_D4s_v5 to Standard_D8s_v5 to speed up the build process.

## AzureImageBuilder-v4.ps1

The [AzureImageBuilder-v4.ps1](AzureImageBuilder-v4.ps1) script is an evolution of the [AzureImageBuilder-v3.ps1](AzureImageBuilder-v3.ps1))
The storage account (and its related container) is now in a dedicated resource group with also contains dedicated virtual network and subnet.
So the Azure VM Iage Builder is now deployed in this dedicated subnet and the storage account is only accessible from this subnet via a Private Endpoint (More details [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-networking) and [here](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-vnet)).

## AzureImageBuilder-v5.ps1

The [AzureImageBuilder-v5.ps1](AzureImageBuilder-v5.ps1) script is an evolution of the [AzureImageBuilder-v4.ps1](AzureImageBuilder-v4.ps1))
The main difference is [Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer) is also installed on the VM during the image build. But Instead of using a [File Customizer](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#file-customizer) to download the required sofwares to install on the VM we will use a PowerShell script with call [AZCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) under the hood. The reason is explained [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#file-customizer).
> [!NOTE]
> The file customizer is only suitable for small file downloads, < 20MB. For larger file downloads, use a script or inline command, then use code to download files, such as, Linux wget or curl, Windows, Invoke-WebRequest.
> The [Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer) setup file exceeds the 20MB limit so we need to use an alternative solution as mentionned above. I have chosen to use [AZCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) to download the setup file from the Azure Container.

## AzureImageBuilder-v6.ps1

The [AzureImageBuilder-v6.ps1](AzureImageBuilder-v6.ps1) script is almost the same than the [AzureImageBuilder-v2.ps1](AzureImageBuilder-v2.ps1) script but adds a [Windows restart customizer](<https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#windows-restart-customizer>) to restart the VM after the installation of Visual Studio Code as an example how to use this customizer.

## AzureImageBuilder-v7.ps1

The [AzureImageBuilder-v7.ps1](AzureImageBuilder-v7.ps1) script is almost the same than the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script but the image used is a Windows Server 2022 DataCenter Azure Edition.

## AzureImageBuilder-v8.ps1

The [AzureImageBuilder-v8.ps1](AzureImageBuilder-v8.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script because we also install the System Center Operations Manager agents.

## AzureImageBuilder with CMK.ps1

The script [AzureImageBuilder with CMK.ps1](AzureImageBuilder%20with%20CMK.ps1) is an example to show how to use a customer-managed key to encrypt a VM Image Version. It was asked by a customer

## New-AzureComputeGalleryVM.ps1

The script [New-AzureComputeGalleryVM.ps1](New-AzureComputeGalleryVM.ps1) allows you to setup a new Azure VM from an Azure Compute Gallery Image. You will be prompted (via the [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-5.1) cmdlet) to select the Azure Compute Gallery and the Image to use.

## Get-AzureVMImageBuilderCustomizationLog.ps1

The script [Get-AzureVMImageBuilderCustomizationLog.ps1](Get-AzureVMImageBuilderCustomizationLog.ps1) downloads in the script directory (can be customized via a parameter to the called function) the customization.log files used by [Azure VM Image Builder](https://learn.microsoft.com/en-us/azure/virtual-machines/image-builder-overview?tabs=azure-powershell). The downloaded files are timestamped (based on the current time). So every run will create a new local file (can be enabled/disabled via the -Timestamp switch). It can be useful for tracking the process evolution.
More details [here](https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-custom-image-templates) and [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot).

## Get-AzureVMImageBuilderData.ps1

The script [Get-AzureVMImageBuilderData.ps1](Get-AzureVMImageBuilderData.ps1) returns some data about the Azure VM Image Builder process. It can be useful for tracking the process evolution.
