# Azure VM Image Builder via Azure Automation Account

This folder contains PowerShell scripts to automate the creation of Azure VM images using [Azure VM Image Builder (AIB)](https://learn.microsoft.com/azure/virtual-machines/image-builder-overview), orchestrated through an [Azure Automation Account](https://learn.microsoft.com/azure/automation/overview) runbook on a recurring schedule.

## Overview

The solution builds custom Windows 11 Azure Virtual Desktop (AVD) images on a monthly schedule (2nd Wednesday — Patch Tuesday) by:

1. Provisioning an Azure Automation Account with a custom PowerShell 7.4 runtime environment.
2. Publishing a runbook that creates two Azure Compute Gallery image definition versions in parallel:
   - **ARM-based template** — uses a customized ARM/JSON template with Windows 11 AVD customizations.
   - **PowerShell-based template** — uses Az.ImageBuilder cmdlets with Windows 11 + Microsoft 365 Apps and additional software (VS Code, Notepad++, PuTTY, WinSCP, PowerShell cross-platform, Windows Update, etc.).

## Files

| File                                   | Description                                                                                                                                                                                                                                                           |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **New-AzureVMImageBuilderRunBook.ps1** | **Setup / orchestration script** — run this interactively to provision all Azure infrastructure: resource group, Automation Account, PowerShell 7.4 runtime environment, runbook, monthly schedule, RBAC role assignments, and an optional test invocation.           |
| **AzureVMImageBuilderRunBook.ps1**     | **Automation runbook** — the script that runs *inside* the Automation Account. It connects via managed identity, creates staging resource groups, builds two image templates (ARM + PowerShell) in parallel, waits for completion, and cleans up temporary resources. |

## Prerequisites

- An Azure subscription with sufficient permissions (Contributor + Role Based Access Control Administrator at the subscription level).
- An existing [Azure Compute Gallery](https://learn.microsoft.com/azure/virtual-machines/azure-compute-gallery) and a [User-Assigned Managed Identity](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview) with the appropriate Image Builder permissions.
- PowerShell Az modules: `Az.Automation`, `Az.Resources`, `Az.Accounts`, `Az.Compute`, `Az.ImageBuilder`, `Az.ManagedServiceIdentity`.

## How It Works

### 1. Setup (`New-AzureVMImageBuilderRunBook.ps1`)

- Creates a resource group and Automation Account in the specified Azure region (default: `EastUS2`).
- Provisions a custom **PowerShell 7.4** runtime environment with the required Az modules.
- Publishes `AzureVMImageBuilderRunBook.ps1` as a runbook (fetched from this GitHub repo).
- Creates a **monthly schedule** (2nd Wednesday of the month at 08:00 local time).
- Assigns **Contributor** and **Role Based Access Control Administrator** roles to the Automation Account's system-assigned managed identity.

### 2. Runbook Execution (`AzureVMImageBuilderRunBook.ps1`)

When triggered (by schedule or manually):

1. Authenticates using the Automation Account's **system-assigned managed identity**.
2. Resolves the target Azure Compute Gallery and User-Assigned Managed Identity from the provided resource IDs.
3. Creates temporary staging resource groups with RBAC assignments.
4. Checks that the day's image version (`YYYY.MM.DD`) doesn't already exist.
5. **Template #1 (ARM):** Downloads and customizes a JSON ARM template, deploys it, and starts the image build as a background job.
6. **Template #2 (PowerShell):** Defines customizers (Timezone Redirection, PowerShell cross-platform, PuTTY, WinSCP, Notepad++, VS Code, Windows Update, Disable AutoUpdates), creates the image builder template via cmdlets, and starts the build as a background job.
7. Waits for both jobs to complete, reports status, removes the image builder templates, and cleans up staging resource groups.

## Parameters (Runbook)

| Parameter                       | Required | Description                                                                            |
| ------------------------------- | -------- | -------------------------------------------------------------------------------------- |
| `GalleryId`                     | Yes      | Azure resource ID of the target Azure Compute Gallery.                                 |
| `UserAssignedManagedIdentityId` | Yes      | Azure resource ID of the User-Assigned Managed Identity for AIB.                       |
| `TargetRegions`                 | No       | Array of Azure regions for image replication (defaults to gallery location).           |
| `excludeFromLatest`             | No       | Whether to exclude the new version from being considered "latest" (default: `$false`). |

if you need to create these prerequisites you can use the [following](https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20VM%20Image%20Builder/AzureImageBuilder-v17.ps1) script.
## Naming Convention

Resource names follow the [Azure Naming Tool](https://github.com/mspnp/AzureNamingTool) convention (`{prefix}-{project}-{role}-{locationShortName}-{instance}`).
