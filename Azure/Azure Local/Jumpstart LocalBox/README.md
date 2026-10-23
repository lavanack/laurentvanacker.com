# Automated deployment for Azure Arc Jumpstart LocalBox

[`New-JumpstartLocalBox.ps1`](./New-JumpstartLocalBox.ps1) provides an automated
deployment and initial configuration workflow for
[Azure Arc Jumpstart LocalBox](https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox),
as described in the official
[`Azure/arc_jumpstart_docs` LocalBox documentation](https://github.com/Azure/arc_jumpstart_docs/tree/main/docs/azure_jumpstart_localbox).
It uses the upstream Arc Jumpstart Bicep templates to build a nested Azure Local
lab in an Azure subscription, then configures monitoring. With the optional
`-AVD` switch, it also creates Azure Local VM images and VMs for Azure Virtual
Desktop (AVD) scenarios.

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
3. Checks that both the Bicep CLI and Git are available, then clones or updates the
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
8. Only when `-AVD` is supplied, starts imports for Windows 11 Azure Virtual
   Desktop Marketplace images and the latest Azure Compute Gallery image
   versions (if any). These images are used to create sample Azure Local VMs for
   exploring AVD-related image and VM workflows. After the imports finish, the
   script removes temporary export disks and creates VMs in background jobs
   for images in the resource group whose provisioning state is `Succeeded`.
9. Applies a `CanNotDelete` lock to the successful deployment's resource group,
   whether or not `-AVD` was supplied.

## AVD scenario scope

The image and VM portion of this script is optional and intended for exploring
Azure Virtual Desktop scenarios on Azure Local. Supply `-AVD` to import Windows
11 multi-session AVD Marketplace images (with and without Microsoft 365) and the
latest version of each discovered Azure Compute Gallery image definition, then
create Azure Local VMs from images whose provisioning state is `Succeeded`.

Without `-AVD`, the script still deploys LocalBox, configures monitoring and the
VM logical network, and applies the resource-group lock. It skips the additional
image imports, temporary export-disk cleanup, and sample VM creation.

Generated sample VM names use a shortened image identifier (up to 10 characters)
and the resource group's trailing instance number. The identifier removes the
trailing timestamp and optional three-digit suffix, abbreviates `win` followed
by any digits to `w` and `acg` to `a`, and removes `avd` and non-word characters.

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
  providers, and create a resource lock. The required Azure role-based access
  control (RBAC) roles and assignment scopes are those described in the official
  [Azure Arc Jumpstart LocalBox deployment
  documentation](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az).
  Follow that documentation when assigning permissions for this automated
  deployment.
- Azure PowerShell modules compatible with the Azure services and commands used
  in the script. These include Az.Accounts, Az.Resources, Az.Compute, Az.Quota,
  Az.StackHCI, Az.StackHCIVM, and the modules that provide the Azure Monitor,
  Connected Machine, networking, and VM commands. The script does not install
  or pin module versions.
- The **Bicep CLI** and **Git** available on the machine running this script.
  The script checks both commands with `Get-Command` and stops with an
  installation message if either is missing. It uses Git to clone or update
  the template repository. Azure CLI is used by the configuration script
  running inside the deployed LocalBox client.
- Internet connectivity to Azure, the upstream Arc Jumpstart and Azure Naming
  Tool GitHub content, the Marketplace, and the external services the script
  calls. The script checks Marketplace disk-image URLs and uses an external
  service to discover the caller's public IPv4 address for JIT access.
- Sufficient regional quota and capacity for the configured VM size. The
  current script sets `Standard_E32s_v6` and checks quota before deploying.

If Bicep or Git is missing, the script suggests these installation commands.
Install the missing tools before running the deployment:

```powershell
winget install -e --id Microsoft.Bicep
winget install -e --id Git.Git
```

Follow the official [Azure Bicep deployment
guide](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az) to
review current software prerequisites, permissions, supported regions, quota,
and resource-provider requirements. Requirements can change as the upstream
templates and Azure services evolve.

### Review the configuration in this copy

Several values in the script's main section are fixed in code and may not match
the defaults or parameters documented by upstream Jumpstart:

- `$VMSize` is set to `Standard_E32s_v6` and is used for both the regional
  quota check and the `New-JumpstartLocalBox -vmSize` deployment argument.
  The function accepts `Standard_E32s_v5` or `Standard_E32s_v6`; changing the
  assignment therefore changes both the checked and deployed VM SKU.
- `$GitDir` is set to `C:\Source Control\GitHub\Cloned repositories`.
  Change it to a writable directory if that path does not exist or is not
  appropriate for your environment.
- The script's `Location` and `azureLocalInstanceLocation` parameters are
  optional and have no fixed defaults. When omitted, the script discovers
  Log Analytics-compatible deployment regions and uses its built-in list of
  eight Azure Local instance regions. They are separate settings: `Location`
  selects the deployment and Log Analytics region, while
  `azureLocalInstanceLocation` selects the Azure Local instance region. The
  sample region assignments in the main section are comments and do not
  override the parameters or automatic region selection.
- The deployment call enables Azure Spot pricing and automatic cluster-resource
  upgrades. Spot capacity may be unavailable or the VM may be evicted.
- `New-JumpstartLocalBox` defaults `governResourceTags` to `true`. In the
  upstream template, the related governance tags are intended for Microsoft
  internal lab tenants. Review this setting and the `tags` parameter before
  deploying to any other tenant.
- The script defaults to creating resources without Azure Bastion and uses
  RDP/JIT access for the LocalBox client.

To restrict deployment attempts to specific supported regions, pass them when
launching the script.
Changing the VM size still requires editing the `$VMSize` assignment in the
script's main section. The parameters below are the only top-level inputs to
the script; the numerous parameters documented for `New-JumpstartLocalBox`
belong to an internal function and are not individually exposed by the
standalone script.

### Script input parameters

The script exposes three optional top-level parameters:

| Parameter                    | Type       | Behavior when omitted                                                                                                                                 | Purpose                                                                                                                                                                                                   |
| ---------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Location`                   | `string[]` | Discovers and sorts regions that list `Microsoft.OperationalInsights` as a provider and whose display names match the provider's workspace locations. | Deployment region, including the Log Analytics workspace. Each supplied value must be available for Log Analytics in the current Azure context.                                                           |
| `azureLocalInstanceLocation` | `string[]` | Tries the eight supported regions in the order listed here.                                                                                           | Azure Local instance registration region. Each supplied value must be one of `australiaeast`, `southcentralus`, `eastus`, `westeurope`, `southeastasia`, `canadacentral`, `japaneast`, or `centralindia`. |
| `AVD`                        | `switch`   | Disabled; skips the additional AVD image and VM workflow.                                                                                             | Enables Marketplace and Azure Compute Gallery image imports, temporary export-disk cleanup, and sample Azure Local VM creation after LocalBox configuration.                                              |

You can omit either region parameter independently: the omitted parameter uses its
automatic region list, while the supplied parameter restricts that side of the
deployment combinations. Omitting both parameters enables the broadest search;
it does not select `centralindia` by default.

Both region parameters accept one or more regions. They can be different because
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
configured combination succeeds, the LocalBox configuration and any requested
AVD image/VM steps do not have a successful deployment to continue with.

These are the only parameters accepted by the script when launched. Other
deployment choices, including the VM size, Spot pricing, automatic cluster
resource upgrades, and Git checkout path, are currently set in the script and
must be changed there. The script also accepts common PowerShell parameters
such as `-Verbose`; `-vmSize` is an internal function parameter, not a
top-level script parameter.

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

   This runs the LocalBox workflow without the additional AVD image imports
   and sample VMs.

4. Complete the credential prompt and any Azure sign-in or RDP prompts. Monitor
   the deployment in the Azure portal and the PowerShell transcript. The script
   copies the deployment blade URL to the clipboard when it starts the Bicep
   deployment.

To enable timestamped diagnostics, run with the common `-Verbose` parameter:

```powershell
.\New-JumpstartLocalBox.ps1 -Verbose
```

Verbose output includes Bicep and Git command discovery details, resource-provider
registration wait messages, the selected region lists, and quota-check results.
It can also be enabled when supplying explicit region parameters.

The commands above use automatic region selection for both region lists and
can attempt deployments across multiple combinations. To limit attempts to
one deployment region and one Azure Local instance region, provide both
parameters explicitly. For example:

```powershell
.\New-JumpstartLocalBox.ps1 -Location 'centralus' -azureLocalInstanceLocation 'southcentralus'
```

To use `centralindia` for both regions, specify it explicitly:

```powershell
.\New-JumpstartLocalBox.ps1 -Location 'centralindia' -azureLocalInstanceLocation 'centralindia'
```

To include the optional AVD image and VM workflow, add `-AVD`. For example,
with explicit regions and verbose diagnostics:

```powershell
.\New-JumpstartLocalBox.ps1 `
  -Location 'centralindia' `
  -azureLocalInstanceLocation 'centralindia' `
  -AVD -Verbose
```

The switch adds image and VM provisioning to the deployment; it does not
register the VMs with Azure Virtual Desktop. Image imports and VM builds can
take hours and incur additional compute and storage charges.

The Log Analytics region must pass the script's runtime validation, and the
Azure Local instance region must be in the parameter's supported-region
`ValidateSet`. Check the latest official Jumpstart guidance for current regional
availability before deploying.

## Outputs and deployed resources

- **Azure resources:** A uniquely named resource group, the Azure-hosted
  LocalBox client and supporting infrastructure, Azure Local and Arc resources,
  monitoring resources, and other resources required by the deployment.
  Additional images and sample VMs intended for AVD scenarios are created only
  when `-AVD` is supplied.
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
