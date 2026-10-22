# Azure Local Jumpstart LocalBox deployment script

[`New-JumpstartLocalBox.ps1`](./New-JumpstartLocalBox.ps1) automates deployment
and initial configuration of an Azure Local Jumpstart LocalBox environment. It
uses the upstream Arc Jumpstart Bicep templates to build a nested Azure Local
lab in an Azure subscription, then configures monitoring and creates Azure Local
VM images and VMs for Azure Virtual Desktop (AVD) scenarios.

LocalBox is intended as a self-contained sandbox for learning, demonstrations,
proofs of concept, and integration testing. It is not a production deployment
template. See the official [LocalBox Getting Started
guide](https://jumpstart.azure.com/azure_jumpstart_localbox/getting_started)
and [Azure Arc Jumpstart LocalBox
documentation](https://github.com/Azure/arc_jumpstart_docs/tree/main/docs/azure_jumpstart_localbox)
for the supported architecture and deployment guidance.

> **Important:** Running this script starts the end-to-end workflow. It creates
> Azure resources, can incur significant ongoing charges, changes subscription
> resource-provider registrations, opens an RDP session, and adds a
> `CanNotDelete` lock to a successful deployment's resource group. Review the
> script and the cautions below before running it.

## What the script does

At a high level, the script:

1. Sets its working directory to the script's folder and starts a timestamped
   PowerShell transcript beside the script.
2. Signs in to Azure if the current Az PowerShell context cannot obtain an
   access token, registers the resource providers it needs, and waits for
   registration to finish.
3. Checks that the Bicep CLI is installed, then clones or updates the
   [Microsoft `azure_arc` repository](https://github.com/microsoft/azure_arc)
   containing the LocalBox Bicep templates.
4. Checks regional VM quota for the configured VM size and prompts for the
   LocalBox Windows administrator credentials.
5. Creates a uniquely named resource group and deploys the LocalBox Bicep
   template. The deployment creates the Azure-hosted LocalBox client and the
   supporting infrastructure for its nested Azure Local environment.
6. Configures the client VM's DNS name, stores its RDP credentials in Windows
   Credential Manager, configures Just-in-Time (JIT) VM access, and opens an
   RDP session.
7. Waits for the two Azure Arc machines and the Azure Local cluster to become
   ready, configures Azure Monitor data collection, and sets up the LocalBox
   VM logical network.
8. Starts imports for Windows 11 Azure Virtual Desktop Marketplace images and
   the latest Azure Compute Gallery image versions. These images are used to
   create sample Azure Local VMs for exploring AVD-related image and VM
   workflows. After the imports finish, the script removes temporary export
   disks, creates a VM for each successfully imported image, and applies a
   `CanNotDelete` lock to the resource group.

## AVD scenario scope

The image and VM portion of this script is intended for exploring Azure Virtual
Desktop scenarios on Azure Local. It imports Windows 11 multi-session AVD
Marketplace images and Azure Compute Gallery images, then creates Azure Local
VMs from the successfully imported images.

Creating these images and VMs does **not** by itself deploy or configure Azure
Virtual Desktop: the script does not create a host pool, workspace, or
application group, and it does not register the VMs as AVD session hosts. Use
the [LocalBox usage guide](https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox)
and the relevant [Azure Virtual Desktop on Azure Local
documentation](https://learn.microsoft.com/azure/virtual-desktop/azure-virtual-desktop-azure-local)
to complete and validate an AVD environment.

Some provisioning and image-import stages can take a long time. The Arc machine
and cluster readiness checks poll every five minutes and do not have a timeout.

## Before you run it

### Prerequisites

- A Windows environment with **Windows PowerShell 5.1 or later**. The script
  declares PowerShell 5 as its minimum. It uses Windows-specific features
  including the clipboard, Credential Manager, `mstsc`, and window automation.
- An Azure subscription and tenant in which you are authorized to create the
  LocalBox resources, assign the required permissions, register resource
  providers, and create a resource lock. Subscription Owner or Contributor
  access is typically needed for the deployment and provider registration;
  confirm role requirements with your administrator.
- Azure PowerShell modules compatible with the Azure services and commands used
  in the script. These include Az.Accounts, Az.Resources, Az.Compute, Az.Quota,
  Az.StackHCI, Az.StackHCIVM, and the modules that provide the Azure Monitor,
  Connected Machine, networking, and VM commands. The script does not install
  or pin module versions.
- The **Bicep CLI** and **Git** available on the machine running this script.
  The script checks for Bicep and uses Git to clone or update the template
  repository. Azure CLI is used by the configuration script running inside the
  deployed LocalBox client.
- Internet connectivity to Azure, the upstream Arc Jumpstart and Azure Naming
  Tool GitHub content, the Marketplace, and the external services the script
  calls. The script checks Marketplace disk-image URLs and uses an external
  service to discover the caller's public IPv4 address for JIT access.
- Sufficient regional quota and capacity for the configured VM size. The
  current script sets `Standard_E32s_v6` and checks quota before deploying.

Follow the official [Azure Bicep deployment
guide](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az) to
review current software prerequisites, permissions, supported regions, quota,
and resource-provider requirements. Requirements can change as the upstream
templates and Azure services evolve.

### Review the configuration in this copy

Several values in the script's main section are fixed in code and may not match
the defaults or parameters documented by upstream Jumpstart:

- `$VMSize` is set to `Standard_E32s_v6`.
- `$GitDir` is set to `C:\Source Control\GitHub\Cloned repositories`.
  Change it to a writable directory if that path does not exist or is not
  appropriate for your environment.
- The script's `Location` and `azureLocalInstanceLocation` parameters both
  default to `centralindia`. They are separate settings: `Location` selects the
  deployment and Log Analytics region, while `azureLocalInstanceLocation`
  selects the Azure Local instance region. The sample region assignments in the
  main section are comments and do not override the parameters.
- The deployment call enables Azure Spot pricing and automatic cluster-resource
  upgrades. Spot capacity may be unavailable or the VM may be evicted.
- `New-JumpstartLocalBox` defaults `governResourceTags` to `true`. In the
  upstream template, the related governance tags are intended for Microsoft
  internal lab tenants. Review this setting and the `tags` parameter before
  deploying to any other tenant.
- The script defaults to creating resources without Azure Bastion and uses
  RDP/JIT access for the LocalBox client.

To use different supported regions, pass them when launching the script.
Changing the VM size still requires editing the `$VMSize` assignment in the
script's main section. The parameters below are the only top-level inputs to
the script; the numerous parameters documented for `New-JumpstartLocalBox`
belong to an internal function and are not individually exposed by the
standalone script.

### Script input parameters

The script exposes two top-level parameters:

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `Location` | `string[]` | `centralindia` | Deployment region, including the Log Analytics workspace. Each value must be available for Log Analytics in the current Azure context. |
| `azureLocalInstanceLocation` | `string[]` | `centralindia` | Azure Local instance registration region. Each value must be one of `australiaeast`, `southcentralus`, `eastus`, `westeurope`, `southeastasia`, `canadacentral`, `japaneast`, or `centralindia`. |

Both parameters accept one or more regions. They can be different because
`Location` controls where the Azure-hosted deployment resources are created,
while `azureLocalInstanceLocation` controls the Azure Local instance's
registration region. The script processes each `Location` in order and, for
each one, tries each `azureLocalInstanceLocation` in order. Supplying two
values to each parameter therefore provides up to four deployment combinations:

```powershell
.\New-JumpstartLocalBox.ps1 `
  -Location @('centralindia', 'eastus') `
  -azureLocalInstanceLocation @('centralindia', 'southcentralus')
```

For each `Location`, the script first checks whether the subscription has
remaining quota for at least one VM of the fixed `$VMSize`. A location with no
reported quota is skipped; a positive quota check does not guarantee that Azure
has capacity to deploy the VM. If deployment fails, the script requests removal
of that attempt's generated resource group and tries the next
`azureLocalInstanceLocation`. If those combinations fail, it moves to the next
`Location` and checks quota there. It stops at the first successful deployment
and continues with LocalBox configuration; it does not try the remaining
regions after success.

The script can therefore make multiple deployment attempts before completing.
Cleanup of a failed attempt is started asynchronously, so verify failed
resource groups and any remaining resources in the Azure portal before
re-running the script; leftover resources can continue to incur charges. If no
configured combination succeeds, the LocalBox configuration and AVD image/VM
steps do not have a successful deployment to continue with.

These are the only parameters accepted by the script when launched. Other
deployment choices, including the VM size, Spot pricing, automatic cluster
resource upgrades, and Git checkout path, are currently set in the script and
must be changed there.

## Run the deployment

1. Read the official [Getting Started](https://jumpstart.azure.com/azure_jumpstart_localbox/getting_started)
   and [Azure Bicep deployment](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az)
   guides.
2. Review the configuration and security/cost notes in this README and in the
   script. Confirm the active Azure tenant and subscription before proceeding.
3. Open a PowerShell session in this folder and run:

   ```powershell
   .\New-JumpstartLocalBox.ps1
   ```

4. Complete the credential prompt and any Azure sign-in or RDP prompts. Monitor
   the deployment in the Azure portal and the PowerShell transcript. The script
   copies the deployment blade URL to the clipboard when it starts the Bicep
   deployment.

The command above uses `centralindia` for both regions. To select another
deployment region and Azure Local instance region, provide the parameters
explicitly. For example:

```powershell
.\New-JumpstartLocalBox.ps1 -Location 'centralus' -azureLocalInstanceLocation 'southcentralus'
```

The Log Analytics region must pass the script's runtime validation, and the
Azure Local instance region must be in the parameter's supported-region
`ValidateSet`. Check the latest official Jumpstart guidance for current regional
availability before deploying.

## Outputs and deployed resources

- **Azure resources:** A uniquely named resource group, the Azure-hosted
  LocalBox client and supporting infrastructure, Azure Local and Arc resources,
  monitoring resources, images and VMs intended for AVD scenarios, and other
  resources required by the deployment.
- **PowerShell transcript:** A timestamped `.txt` file beside the script.
- **Bicep parameters:** A generated `main.bicepparam` file in the cloned
  `azure_arc\azure_jumpstart_localbox\bicep` directory.
- **RDP session:** A full-screen connection to the LocalBox client. Its
  credentials are saved in Windows Credential Manager.
- **Resource lock:** A `CanNotDelete` lock on the successful deployment's
  resource group.

The generated Bicep parameter file includes the Windows administrator
credentials supplied to the deployment. Protect this file, the transcript,
clipboard contents, and any terminal output as sensitive. Review the generated
file and remove it securely when it is no longer needed, subject to your
organization's retention requirements.

## Security and cost considerations

- **Azure charges continue while resources exist.** Compute, storage, networking,
  monitoring, and other resources can incur charges even when the lab is idle.
  Review the [LocalBox FAQ](https://jumpstart.azure.com/azure_jumpstart_localbox/faq)
  and remove the deployment when finished.
- **Successful deployments are protected by a resource lock.** Remove the
  `CanNotDelete` lock before deleting the resource group. Check for other locks,
  dependencies, and resources created outside the group before cleanup.
- **RDP/JIT access is enabled.** The script creates a JIT policy for the RDP
  port, discovers the caller's public IP through an external service, requests
  temporary access, stores credentials in Credential Manager, and opens RDP.
  Verify the port, access policy, and network exposure meet your organization's
  requirements.
- **Credentials are handled in multiple places.** The Windows administrator
  password is passed to the Bicep deployment and written to the generated
  parameter file. The helper `Add-RDPCredential` also writes the user name and
  plain-text password to host output. Keep the transcript and console private.
- **Spot VMs can be interrupted.** This copy enables Spot pricing for the
  LocalBox client VM; confirm that this is suitable for the workload.
- **Resource providers are registered at subscription scope.** Provider
  registrations are not automatically undone when the LocalBox resource group
  is deleted.

## Functions in the script

The file defines helper functions for:

- Generating and checking VM passwords (`New-RandomPassword`).
- Querying regional VM and vCPU quota (`Get-AzVMQuota`, `Get-AzCoreQuota`) and
  estimating capacity for a VM SKU (`Get-AzAvailableComputeResourceSku`).
- Creating the LocalBox resource group and deploying the Bicep template
  (`New-JumpstartLocalBox`).
- Waiting for Azure Arc machines and the Azure Local cluster
  (`Wait-AzConnectedMachine`).
- Configuring Azure Monitor collection (`Set-LocalClusterInsightSetup`).
- Configuring the LocalBox VM logical network (`New-VMLogicalNetwork`).
- Importing Windows 11 AVD Marketplace and Compute Gallery images and creating
  Azure Local VMs for AVD scenarios (`New-AzLocalAVDVMImage`,
  `New-AzureLocalVMImageFromAzureComputeGalleryImage`, and `New-AzLocalAVDVM`).

These functions are defined in a script that also runs the full workflow at the
end of the file. It is therefore **not a function-only module**: dot-sourcing
the file to import functions also executes its deployment workflow.

## Troubleshooting and further reading

- [LocalBox Getting Started](https://jumpstart.azure.com/azure_jumpstart_localbox/getting_started)
- [Deploy LocalBox with Azure Bicep](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az)
- [Connect to and complete cloud deployment](https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment)
- [Use LocalBox](https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox)
- [LocalBox FAQ](https://jumpstart.azure.com/azure_jumpstart_localbox/faq)
- [LocalBox troubleshooting](https://jumpstart.azure.com/azure_jumpstart_localbox/troubleshooting)
- [Azure Arc Jumpstart LocalBox documentation source](https://github.com/Azure/arc_jumpstart_docs/tree/main/docs/azure_jumpstart_localbox)
- [Arc Jumpstart deployment templates](https://github.com/microsoft/azure_arc/tree/main/azure_jumpstart_localbox)
