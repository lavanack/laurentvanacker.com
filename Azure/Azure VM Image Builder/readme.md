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
  - [AzureImageBuilder-v9.ps1](#azureimagebuilder-v9ps1)
  - [AzureImageBuilder-v10.ps1](#azureimagebuilder-v10ps1)
  - [AzureImageBuilder-v11.ps1](#azureimagebuilder-v11ps1)
  - [AzureImageBuilder-v12.ps1](#azureimagebuilder-v12ps1)
  - [AzureImageBuilder-v13.ps1](#azureimagebuilder-v13ps1)
  - [AzureImageBuilder with CMK.ps1](#azureimagebuilder-with-cmkps1)
  - [New-AzureComputeGalleryVM.ps1](#new-azurecomputegalleryvmps1)
  - [Get-AzureVMImageBuilderCustomizationLog.ps1](#get-azurevmimagebuildercustomizationlogps1)
    - [Features](#features)
    - [Usage](#usage)
    - [Parameters](#parameters)
    - [What It Does](#what-it-does)
    - [Prerequisites](#prerequisites-1)
    - [Output Structure](#output-structure)
    - [Troubleshooting](#troubleshooting)
  - [Get-AzureVMImageBuilderData.ps1](#get-azurevmimagebuilderdataps1)

> [!NOTE]
> Almost of the listed scripts deployed two images definitions : One is done via an ARM template and the other one via Powershell. The purpose was just to show the 2 possibilities. Choose the one relevant to you.

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
So the Azure VM Image Builder is now deployed in this dedicated subnet and the storage account is only accessible from this subnet via a Private Endpoint (More details [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-networking) and [here](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-vnet)).

## AzureImageBuilder-v5.ps1

The [AzureImageBuilder-v5.ps1](AzureImageBuilder-v5.ps1) script is an evolution of the [AzureImageBuilder-v4.ps1](AzureImageBuilder-v4.ps1))
The main difference is [Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer) is also installed on the VM during the image build. But Instead of using a [File Customizer](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#file-customizer) to download the required sofwares to install on the VM we will use a PowerShell script with call [AZCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) under the hood. The reason is explained [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#file-customizer).
> [!NOTE]
> The file customizer is only suitable for small file downloads, < 20MB. For larger file downloads, use a script or inline command, then use code to download files, such as, Linux wget or curl, Windows, Invoke-WebRequest.
> The [Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer) setup file exceeds the 20MB limit so we need to use an alternative solution as mentionned above. I have chosen to use [AZCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10) to download the setup file from the Azure Container.

## AzureImageBuilder-v6.ps1

The [AzureImageBuilder-v6.ps1](AzureImageBuilder-v6.ps1) script is almost the same than the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script but adds a [Windows restart customizer](<https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#windows-restart-customizer>) to restart the VM after the installation of Visual Studio Code as an example how to use this customizer.

## AzureImageBuilder-v7.ps1

The [AzureImageBuilder-v7.ps1](AzureImageBuilder-v7.ps1) script is almost the same than the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script but the image used is a Windows Server 2022 DataCenter Azure Edition.

## AzureImageBuilder-v8.ps1

The [AzureImageBuilder-v8.ps1](AzureImageBuilder-v8.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script because we also install the System Center Operations Manager agents.

## AzureImageBuilder-v9.ps1

The [AzureImageBuilder-v9.ps1](AzureImageBuilder-v9.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script because we create two image versions of an image definition (we update the previous version by adding Powershell 7+ to the image).

## AzureImageBuilder-v10.ps1

The [AzureImageBuilder-v10.ps1](AzureImageBuilder-v10.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script because we add a second disk (ie. a data disk) during the Azure Image Builder process. We reuse the User Assigned Managed Identity created for Azure Image Builder as User Assigned Managed Identity for the generated VM (more details [here](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#user-assigned-identity-for-the-image-builder-build-vm)). We also add some role assignments to this identity (cf. [aibRoleImageCreation-v10.json](aibRoleImageCreation-v10.json) - you can compare with [aibRoleImageCreation.json](aibRoleImageCreation.json) for the differences)
> [!NOTE]
> Unfortunately, this data disk is not captured for Azure VM Image Builder. It is a limitation of the service. The data disk is attached to the VM but not captured in the image. The data disk is not captured because the data disk is not part of the image definition. The image definition is only for the OS disk. The data disk is attached to the VM during the build process.

## AzureImageBuilder-v11.ps1

The [AzureImageBuilder-v11.ps1](AzureImageBuilder-v11.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script but using a Windows Server 2016 image and with a [Windows restart customizer](<https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=json%2Cazure-powershell#windows-restart-customizer>) (like the [AzureImageBuilder-v6.ps1](AzureImageBuilder-v6.ps1) script) because we need to enable TLS 1.2 for this OS and we have to restart the VM after to apply this settings at the OS level. Without this restart the TLS 1.2 settings are not applied and the VM is not able to connect to GitHub and PowerShell Gallery fir the other customizations.
> [!WARNING]
> It was for testing purpose because Windows Server 2016 wasn't built to run an AVD environment and will not.

## AzureImageBuilder-v12.ps1

The [AzureImageBuilder-v12.ps1](AzureImageBuilder-v12.ps1) script is an update of the [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script but using a Windows 11 24h2 mono-session image (tested for a customer scenario).

## AzureImageBuilder-v13.ps1

The [AzureImageBuilder-v13.ps1](AzureImageBuilder-v13.ps1) script is similar to [AzureImageBuilder.ps1](AzureImageBuilder.ps1) script (with different customization scripts) but using an Ubuntu mono-session image (tested for a customer scenario).

## AzureImageBuilder with CMK.ps1

The script [AzureImageBuilder with CMK.ps1](AzureImageBuilder%20with%20CMK.ps1) is an example to show how to use a customer-managed key to encrypt a VM Image Version. It was asked by a customer

## New-AzureComputeGalleryVM.ps1

The script [New-AzureComputeGalleryVM.ps1](New-AzureComputeGalleryVM.ps1) allows you to setup a new Azure VM from an Azure Compute Gallery Image. You will be prompted (via the [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-5.1) cmdlet) to select the Azure Compute Gallery and the Image to use.

## Get-AzureVMImageBuilderCustomizationLog.ps1

The script [Get-AzureVMImageBuilderCustomizationLog.ps1](Get-AzureVMImageBuilderCustomizationLog.ps1) automates the retrieval and analysis of Azure VM Image Builder customization logs for troubleshooting purposes.

### Features

- **🔄 Automated Discovery**: Finds all Image Builder templates in the current subscription
- **📁 Organized Output**: Creates separate folders for each template's logs  
- **⏰ Timestamping Support**: Optional timestamp addition to prevent overwriting files
- **🔍 Intelligent Analysis**: Automatically opens logs and searches for key customization phases
- **🖥️ Verbose Logging**: Detailed progress information for troubleshooting

### Usage

```powershell
# Basic usage - downloads to current directory
.\Get-AzureVMImageBuilderCustomizationLog.ps1

# With custom destination and timestamping
.\Get-AzureVMImageBuilderCustomizationLog.ps1 -Destination "C:\AIB-Logs" -TimeStamp

# Maximum verbose output for troubleshooting
.\Get-AzureVMImageBuilderCustomizationLog.ps1 -Destination ".\Logs" -TimeStamp -Verbose

# Use as function after dot-sourcing
. .\Get-AzureVMImageBuilderCustomizationLog.ps1
$LogFiles = Get-AzureVMImageBuilderCustomizationLog -Destination "C:\Temp" -TimeStamp
```

### Parameters

| Parameter     | Type   | Description                                             | Default           |
| ------------- | ------ | ------------------------------------------------------- | ----------------- |
| `Destination` | String | Destination folder for downloaded logs                  | Current directory |
| `TimeStamp`   | Switch | Add timestamp to log filenames (format: yyyyMMddHHmmss) | Disabled          |

### What It Does

1. **Discovery Phase**: Automatically finds all Image Builder templates in your subscription
2. **Log Retrieval**: Downloads `customization.log` files from staging resource group storage accounts  
3. **Organization**: Creates separate folders for each template (named after staging resource groups)
4. **Analysis**: Opens downloaded logs and searches for key patterns like:
   - `Starting provisioner` - Customization phase starts
   - `Starting AVD AIB Customization` - AVD-specific customizations
   - `AVD AIB CUSTOMIZER PHASE` - Major customization milestones
5. **Cleanup**: Removes empty directories when no logs are found

### Prerequisites

- PowerShell 5.0+ with Azure PowerShell modules: `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.ImageBuilder`
- Azure authentication with Reader access to Image Builder templates and staging resource groups
- Storage Blob Data Reader permissions on staging storage accounts

### Output Structure

```
📁 Destination Directory
├── 📁 IT_rg-staging-xxxxxxxxx/          # Staging resource group name
│   └── 📄 customization.log             # Downloaded log file
├── 📁 IT_rg-staging-yyyyyyyyy/
│   └── 📄 customization_20241224120000.log  # Timestamped version
└── 📁 IT_rg-staging-zzzzzzzzz/
    └── 📄 customization.log
```

### Troubleshooting

**No logs found**: Check if Image Builder templates exist and have been executed
```powershell
Get-AzImageBuilderTemplate
```

**Authentication errors**: Verify Azure context and permissions
```powershell
Get-AzContext
Set-AzContext -SubscriptionName "Your-Subscription-Name"
```

The downloaded files are timestamped (when `-TimeStamp` switch is used) based on the current time, so every run creates a new local file. This is useful for tracking the build process evolution and comparing logs between different runs.

More details: [Troubleshoot Custom Image Templates](https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-custom-image-templates) | [Image Builder Troubleshooting](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot)

## Get-AzureVMImageBuilderData.ps1

The script [Get-AzureVMImageBuilderData.ps1](Get-AzureVMImageBuilderData.ps1) returns some data about the Azure VM Image Builder process. It can be useful for tracking the process evolution.
