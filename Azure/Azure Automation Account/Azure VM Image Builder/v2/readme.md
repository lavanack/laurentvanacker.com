# Azure VM Image Builder via Azure Automation Account

This folder contains PowerShell scripts to automate the creation of Azure VM images using [Azure VM Image Builder (AIB)](https://learn.microsoft.com/azure/virtual-machines/image-builder-overview), orchestrated through an [Azure Automation Account](https://learn.microsoft.com/azure/automation/overview) runbook on a recurring schedule.

## Overview

The solution builds custom Windows 11 (25H2) Azure Virtual Desktop (AVD) images on a monthly schedule (2nd Wednesday of the month — Patch Tuesday) by:

1. Provisioning an Azure Automation Account with a custom **PowerShell 7.4** runtime environment (`PowerShell-74-AIB`) that includes the required Az modules.
2. Publishing a runbook that builds two Azure Compute Gallery image definition versions **in parallel**:
   - **ARM-based template** — uses a customized ARM/JSON template ([armTemplateAVD-v14.json](https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20VM%20Image%20Builder/armTemplateAVD-v14.json)) with Windows 11 AVD customizations (source: `MicrosoftWindowsDesktop / Windows-11 / win11-25h2-avd`).
   - **PowerShell-based template** — uses `Az.ImageBuilder` cmdlets with Windows 11 + Microsoft 365 Apps (source: `MicrosoftWindowsDesktop / Office-365 / win11-25h2-avd-m365`) plus additional software (VS Code, Notepad++, PuTTY, WinSCP, PowerShell cross-platform, Windows Update, Timezone Redirection, Disable AutoUpdates).

## Files

| File                                   | Description                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **New-AzureVMImageBuilderRunBook.ps1** | **Setup / orchestration script** — run this interactively to provision all Azure infrastructure: resource group, Automation Account, PowerShell 7.4 runtime environment, runbook, monthly schedule, staging resource groups, RBAC role assignments, and an optional test invocation.                                                           |
| **AzureVMImageBuilderRunBook.ps1**     | **Automation runbook** — the script that runs *inside* the Automation Account. It connects via system-assigned managed identity, resolves the gallery / managed identity / staging resource groups passed as parameters, builds two image templates (ARM + PowerShell) in parallel, waits for completion, and cleans up the staging resources. |

## Prerequisites

- An Azure subscription with sufficient permissions to create resource groups, an Automation Account and to assign the **Contributor** RBAC role at the resource group scope.
- An existing [Azure Compute Gallery](https://learn.microsoft.com/azure/virtual-machines/azure-compute-gallery) and a [User-Assigned Managed Identity](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview) with the appropriate Image Builder permissions.
- To run the **setup script** locally: PowerShell 5+ with `Az.Automation` and `Az.Resources`.
- The **runbook** runs on the custom `PowerShell-74-AIB` runtime environment, which imports `Az.Accounts`, `Az.Compute`, `Az.ImageBuilder`, `Az.ManagedServiceIdentity` and `Az.Resources`.

## How It Works

### 1. Setup (`New-AzureVMImageBuilderRunBook.ps1`)

- Builds resource names from the [Azure Naming Tool](https://github.com/mspnp/AzureNamingTool) location/resource short names.
- Creates a resource group and Automation Account (with a system-assigned identity) in the specified Azure region (default: `CentralUS`, replicating to `EastUS2`).
- Provisions the custom **PowerShell 7.4** runtime environment `PowerShell-74-AIB` and imports the required Az modules (via the Azure Automation REST API).
- Publishes `AzureVMImageBuilderRunBook.ps1` as a runbook (fetched from this GitHub repo) and assigns it the custom runtime environment.
- Defines the ARM and PowerShell source images, image definition / template names, and creates the two **staging resource groups** (ARM + PowerShell).
- Creates a **monthly schedule** (2nd Wednesday of the month at 08:00 local time) and registers the runbook with its parameters.
- Assigns the **Contributor** RBAC role to the Automation Account's system-assigned managed identity (on the gallery resource group and both staging resource groups) and to the User-Assigned Managed Identity (on both staging resource groups). This v2 version requires less privileges (in terms of RBAC assignments) than the [v1](../v1/) version.
- Optionally runs a **test invocation** of the runbook and waits for the result.

### 2. Runbook Execution (`AzureVMImageBuilderRunBook.ps1`)

When triggered (by schedule or manually):

1. Authenticates using the Automation Account's **system-assigned managed identity**.
2. Resolves the target Azure Compute Gallery, the User-Assigned Managed Identity and the staging resource groups from the provided resource IDs.
3. Computes the target regions (gallery location is always included) and the day's image version (`YYYY.MM.DD`).
4. Checks that the version doesn't already exist for either image definition (stops if it does).
5. **Template #1 (ARM):** Downloads and customizes a JSON ARM template, creates the gallery image definition, deploys the template, and starts the image build as a background job.
6. **Template #2 (PowerShell):** Creates the gallery image definition, builds the source/distributor/customizer objects (Timezone Redirection, PowerShell cross-platform, PuTTY, WinSCP, Notepad++, VS Code, Windows Update, Disable AutoUpdates), creates the image builder template (VM size `Standard_D8s_v6`, 127 GB OS disk, 240 min build timeout), and starts the build as a background job.
7. Waits for both jobs to complete, reports each template's status, removes the image builder templates, and cleans up the staging resource groups.

## Parameters (Runbook)

| Parameter                          | Required | Description                                                                                  |
| ---------------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| `GalleryId`                        | Yes      | Azure resource ID of the target Azure Compute Gallery.                                       |
| `UserAssignedManagedIdentityId`    | Yes      | Azure resource ID of the User-Assigned Managed Identity for AIB.                             |
| `StagingResourceGroupARMId`        | Yes      | Azure resource ID of the staging resource group used by the ARM build.                       |
| `StagingResourceGroupPowerShellId` | Yes      | Azure resource ID of the staging resource group used by the PowerShell build.                |
| `SrcParamsARM`                     | Yes      | JSON string with the source image (Publisher/Offer/Sku/Version) for the ARM template.        |
| `SrcParamsPowerShell`              | Yes      | JSON string with the source image (Publisher/Offer/Sku/Version) for the PowerShell template. |
| `imageDefinitionNameARM`           | Yes      | Name of the Azure Compute Gallery image definition for the ARM build.                        |
| `imageDefinitionNamePowerShell`    | Yes      | Name of the Azure Compute Gallery image definition for the PowerShell build.                 |
| `imageTemplateNameARM`             | Yes      | Name of the Azure Image Builder template for the ARM build.                                  |
| `imageTemplateNamePowerShell`      | Yes      | Name of the Azure Image Builder template for the PowerShell build.                           |
| `TargetRegions`                    | No       | Array of Azure regions for image replication (gallery location is always added).             |
| `ReplicaCount`                     | No       | Number of replicas per target region (default: `1`).                                         |
| `excludeFromLatest`                | No       | Whether to exclude the new version from being considered "latest" (default: `$false`).       |

if you need to create these prerequisites you can use the [following](https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20VM%20Image%20Builder/AzureImageBuilder-v17.ps1) script.

## Naming Convention

Resource names follow the [Azure Naming Tool](https://github.com/mspnp/AzureNamingTool) convention (`{prefix}-{project}-{role}-{locationShortName}-{instance}`).
