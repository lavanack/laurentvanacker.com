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
3. Checks that both the Bicep CLI and Git are available, then calls the
   `New-JumpstartLocalBox` coordinator with the explicitly supplied script
   parameters. The coordinator clones or updates the
   [Microsoft `azure_arc` repository](https://github.com/microsoft/azure_arc)
   containing the LocalBox Bicep templates.
4. Prompts for the LocalBox Windows administrator credentials, then checks
   regional VM quota for the configured VM size before each region's deployment
   attempts.
5. Calls `New-JumpstartLocalBoxDeployment` for each deployment attempt to create
   a uniquely named resource group and deploy the LocalBox Bicep template. The
   deployment creates the Azure-hosted LocalBox client and the supporting
   infrastructure for its nested Azure Local environment.
6. Configures the client VM's DNS name, stores its RDP credentials in Windows
   Credential Manager, configures Just-in-Time (JIT) VM access, and opens an
   RDP session.
7. Waits for the two Azure Arc machines and the Azure Local cluster to become
   ready, configures Azure Monitor data collection, and sets up the LocalBox
   VM logical network.
8. Only when `-AVD` is supplied, calls `New-AzLocalAVD -AsAJob` to coordinate
   imports for Windows 11 Azure Virtual Desktop Marketplace images and the latest
   Azure Compute Gallery image versions (if any). It opens the cluster's VM
   images blade in the Azure portal, waits for the import jobs, revokes access
   to and removes temporary export disks, reports failed image builds, and
   creates sample VMs in background jobs for images in the resource group whose
   provisioning state is `Succeeded`. It waits for these VM jobs before
   continuing.
9. Applies a `CanNotDelete` lock to the successful deployment's resource group,
   whether or not `-AVD` was supplied.
10. Stops the PowerShell transcript when the workflow reaches its normal end.

## AVD scenario scope

The image and VM portion of this script is optional and intended for exploring
Azure Virtual Desktop scenarios on Azure Local. Supply `-AVD` to import Windows
11 25H2 multi-session AVD Marketplace images (with and without Microsoft 365) and
the latest version of each discovered Azure Compute Gallery image definition in
the current subscription, then create Azure Local VMs from images whose
provisioning state is `Succeeded`.

Without `-AVD`, the script still deploys LocalBox, configures monitoring and the
VM logical network, and applies the resource-group lock. It skips the additional
image imports, temporary export-disk cleanup, and sample VM creation.

### Image imports and VM creation

The `New-AzLocalAVD` helper coordinates the optional workflow using the
credentials and logical network established by the main script:

- **Marketplace images:** The default URNs are
  `MicrosoftWindowsDesktop:office-365:win11-25h2-avd-m365:latest` and
  `MicrosoftWindowsDesktop:windows-11:win11-25h2-avd:latest`.
  The import helper now uses `Get-MicrosoftEdgeMarketPlaceImage` to query
  offers available to the Azure Local cluster through the
  `Microsoft.EdgeMarketplace` API, rather than the regional `Get-AzVMImage`
  catalog. `latest` resolves to the first version in the descending version
  name list; an explicitly supplied version is retained if available.
  If that version is unavailable, the helper warns and substitutes the newest
  listed version. The previous second-newest-version workaround is no longer used.
- **Compute Gallery images:** The workflow uses `-All` to select the latest
  numerically sorted version of each discovered image definition without an
  interactive picker. Each selected version is exported to a temporary managed
  disk tagged `ToBeCleaned=true` and imported through a read-only SAS URL, valid
  for 100000 seconds by default. The import helper sets the OS type to Windows;
  review the discovered gallery images for suitability before enabling `-AVD`.
- **Completion and cleanup:** Although the main script supplies `-AsAJob`, the
  coordinator waits for the image jobs and then revokes access to and deletes
  the tagged temporary disks in the target resource group. It reports failed
  image results with `Write-Error` and, with the default error preference,
  continues to VM creation for successfully provisioned images. That selection
  includes existing successful images in the resource group, not only images
  imported by this run.
- **Sample VMs:** One background job is started per successful image, using
  `Standard_D2s_v5`, the prompted administrator credentials, and the configured
  LocalBox logical network. The coordinator waits for all VM jobs and receives
  their results before returning. `-AVD` therefore does not make the overall
  script fire-and-forget.

Generated sample VM names use a shortened image identifier (up to 10 characters)
and the resource group's trailing instance number. The identifier removes the
trailing timestamp and optional three-digit suffix, abbreviates `win` followed
by any digits to `w` and `acg` to `a`, and removes `avd` and non-word characters.

The VM helper checks whether the generated VM name already exists in the
resource group. If it does, the helper warns and switches to the VM prefix
followed by a `yyMMddHHmmss` timestamp. The NIC name is derived from the resulting
VM name. After creating a VM,
the helper uses `Update-AzTag -Operation Merge` to add an `Image` tag containing
the source image's name to the associated **Azure Arc machine**, not the nested
Azure Stack HCI resource. It derives the Arc machine resource ID by removing the
`/providers/Microsoft.AzureStackHCI/...` suffix from the returned VM ID and
preserves unrelated existing tags.

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
- The Azure PowerShell modules declared in the script's `#requires` directive:
  Az.Accounts, Az.Resources, Az.Compute, Az.Network, Az.Quota, Az.Security,
  Az.ConnectedMachine, Az.Monitor, Az.OperationalInsights, Az.StackHCI, and
  Az.StackHCIVM. PowerShell checks these requirements before running the script,
  including its Azure sign-in loop. The script does not install or pin module
  versions.
- The **Bicep CLI** and **Git** available on the machine running this script.
  The script checks both commands with `Get-Command` and stops with an
  installation message if either is missing. It uses Git to clone or update
  the template repository. Azure CLI is used by the configuration script
  running inside the deployed LocalBox client.
- Internet connectivity to Azure, the upstream Arc Jumpstart and Azure Naming
  Tool GitHub content, the Marketplace, and the external services the script
  calls. The script queries cluster-specific Marketplace offers through Azure
  Resource Manager and uses an external service to discover the caller's public
  IPv4 address for JIT access.
- Sufficient regional quota and capacity for the configured VM size. The
  script defaults to `Standard_E32s_v6`, accepts `Standard_E32s_v5` through
  `-vmSize`, and checks quota before deploying.

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

The script exposes deployment-selection settings as parameters, while other
choices remain fixed in its helper functions and may not match the defaults
documented by upstream Jumpstart:

- `-vmSize` defaults to `Standard_E32s_v6` and accepts `Standard_E32s_v5`
  or `Standard_E32s_v6`. The selected value is used for both the regional
  quota check and the actual deployment.
- `-GitDir` defaults to `C:\Source Control\GitHub\Cloned repositories`.
  Supply a writable directory appropriate for your environment. The coordinator
  clones `azure_arc` there if its Bicep directory is missing, or runs `git pull`
  on an existing checkout.
- `-SubscriptionId` defaults to the active Az context's subscription ID and
  selects the subscription used for quota checks. It does **not** switch the
  active Azure context; deployment and provider registration use that context.
  Sign in and select the intended subscription before launching the script.
- The script's `Location` and `azureLocalInstanceLocation` parameters are
  optional and have no fixed defaults. When omitted, the script discovers
  Log Analytics-compatible deployment regions and uses its built-in list of
  eight Azure Local instance regions. They are separate settings: `Location`
  selects the deployment and Log Analytics region, while
  `azureLocalInstanceLocation` selects the Azure Local instance region. The
  sample region assignments in the coordinator are comments and do not
  override the parameters or automatic region selection.
- The deployment call enables Azure Spot pricing and automatic cluster-resource
  upgrades. Spot capacity may be unavailable or the VM may be evicted.
- `New-JumpstartLocalBoxDeployment` defaults `governResourceTags` to `true`. In the
  upstream template, the related governance tags are intended for Microsoft
  internal lab tenants. Review this setting and the `tags` parameter before
  deploying to any other tenant.
- The script defaults to creating resources without Azure Bastion and uses
  RDP/JIT access for the LocalBox client.

To restrict deployment attempts to specific supported regions, pass them when
launching the script.
Use `-vmSize`, `-GitDir`, and `-SubscriptionId` to customize the other exposed
settings without editing the script. The additional Bicep settings accepted by
`New-JumpstartLocalBoxDeployment` are not individually exposed by the standalone
script.

### Script input parameters

The script exposes six optional top-level parameters:

| Parameter                    | Type       | Behavior when omitted                                                                                                                                 | Purpose                                                                                                                                                                                                   |
| ---------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Location`                   | `string[]` | Discovers and sorts regions that list `Microsoft.OperationalInsights` as a provider and whose display names match the provider's workspace locations. | Deployment region, including the Log Analytics workspace. Each supplied value must be available for Log Analytics in the current Azure context.                                                           |
| `azureLocalInstanceLocation` | `string[]` | Tries the eight supported regions in the order listed here.                                                                                           | Azure Local instance registration region. Each supplied value must be one of `australiaeast`, `southcentralus`, `eastus`, `westeurope`, `southeastasia`, `canadacentral`, `japaneast`, or `centralindia`. |
| `vmSize` | `string` | Uses `Standard_E32s_v6`. | LocalBox host VM SKU for both quota checks and deployment. Accepts `Standard_E32s_v5` or `Standard_E32s_v6`. |
| `SubscriptionId` | `string` | Uses `(Get-AzContext).Subscription.Id`. | Subscription used for quota checks; does not change the active deployment context. Keep it aligned with the active subscription. |
| `GitDir` | `string` | Uses `C:\Source Control\GitHub\Cloned repositories`. | Parent directory for the `azure_arc` Git checkout containing the LocalBox Bicep templates. |
| `AVD`                        | `switch`   | Disabled; skips the additional AVD image and VM workflow.                                                                                             | Enables Marketplace and Azure Compute Gallery image imports, temporary export-disk cleanup, and sample Azure Local VM creation after LocalBox configuration.                                              |

You can omit either region parameter independently: the omitted parameter uses its
automatic region list, while the supplied parameter restricts that side of the
deployment combinations. Omitting both parameters enables the broadest search;
it does not select `centralindia` by default.
Only explicitly supplied parameters are forwarded to the coordinator;
omitted parameters use the coordinator's defaults, omitted regions are not
passed as null values, and the two region inputs are forwarded independently.
The main section calls `New-JumpstartLocalBox @PSBoundParameters`, also forwarding
explicit common parameters such as `-Verbose`. The coordinator handles template
checkout, region selection, quota checks, deployment retries, and post-deployment
configuration; `New-JumpstartLocalBoxDeployment` performs each Bicep deployment.

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
remaining quota for at least one VM of the selected `-vmSize`. A location with no
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

These are the only application-specific parameters accepted by the script when
launched. Other deployment choices, including Spot pricing, automatic cluster
resource upgrades, Bastion, and governance tags, remain set inside the helper
functions and must be changed there. The script also accepts common PowerShell
parameters such as `-Verbose`.

## Run the deployment

1. Read the official [Getting Started](https://jumpstart.azure.com/azure_jumpstart_localbox/getting_started)
   and [Azure Bicep deployment](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az)
   guides.
2. Review the configuration and security/cost notes in this README and in the
   script. Confirm the active Azure tenant and subscription before proceeding.
   Sign in and select the intended subscription first, particularly when using
   explicit regions or `-SubscriptionId`: region validation and subscription
   defaults are evaluated before the main section's sign-in loop.

   ```powershell
   Connect-AzAccount
   Set-AzContext -Subscription '<subscription-id>'
   ```
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
It also lists resource-group deployment names and provisioning states after the
Bicep deployment, after the initial five-minute post-deployment wait, and during
the Arc machine and cluster readiness polling. During those readiness checks,
it includes step progress read from the LocalBox client's deployment log.
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

To choose the v5 host VM SKU and a different template checkout directory:

```powershell
.\New-JumpstartLocalBox.ps1 `
  -Location 'centralus' `
  -azureLocalInstanceLocation 'southcentralus' `
  -vmSize 'Standard_E32s_v5' `
  -GitDir 'C:\Jumpstart' `
  -SubscriptionId (Get-AzContext).Subscription.Id `
  -Verbose
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
  requirements. The RDP helper waits for the client's window title before
  attempting foreground activation and connection-prompt automation; exceptions
  in that automation are reported as warnings. Verify the connection manually
  if the prompts are not completed.
- **Credentials are handled in multiple places.** The Windows administrator
  password is passed to the Bicep deployment and written to the generated
  parameter file. The helper `Add-RDPCredential` also writes the user name and
  plain-text password to host output. Keep the transcript and console private.
- **Gallery exports grant temporary disk access.** The AVD workflow revokes
  disk SAS access and deletes export disks after receiving the image-job
  results. If the workflow is interrupted, check the target resource group
  for managed disks tagged `ToBeCleaned=true`, revoke their access, and remove
  them when no longer needed. Verbose output can include SAS URLs; protect it
  and the transcript accordingly.
- **Spot VMs can be interrupted.** This copy enables Spot pricing for the
  LocalBox client VM; confirm that this is suitable for the workload.
- **Resource providers are registered at subscription scope.** Provider
  registrations are not automatically undone when the LocalBox resource group
  is deleted.

## Functions in the script

The file defines helper functions for:

- Generating VM passwords (`New-RandomPassword`) and checking them through its
  nested `Test-PwnedPassword` helper. The breach check uses the Have I Been Pwned
  range API, sending only the first five hexadecimal characters of the password's
  SHA-1 hash and comparing the returned suffixes locally.
- Storing Windows RDP credentials and optionally opening a connection
  (`Add-RDPCredential`).
- Querying regional VM and vCPU quota (`Get-AzVMQuota`, `Get-AzCoreQuota`) and
  estimating capacity for a VM SKU (`Get-AzAvailableComputeResourceSku`).
- Coordinating template checkout, region selection, quota checks, deployment
  retries, and post-deployment configuration (`New-JumpstartLocalBox`).
- Creating the LocalBox resource group and deploying the Bicep template for
  each attempt (`New-JumpstartLocalBoxDeployment`).
- Waiting for Azure Arc machines and the Azure Local cluster
  (`Wait-AzConnectedMachine`).
- Configuring Azure Monitor collection (`Set-LocalClusterInsightSetup`).
- Configuring the LocalBox VM logical network (`New-VMLogicalNetwork`).
- Coordinating the optional image imports, portal image-status view,
  temporary-disk access revocation and cleanup, failure reporting, and sample
  VM jobs (`New-AzLocalAVD`).
- Discovering cluster-specific Marketplace image versions as URN strings or
  structured objects (`Get-MicrosoftEdgeMarketPlaceImage`).
- Importing Windows 11 AVD Marketplace and Compute Gallery images and creating
  Azure Local VMs for AVD scenarios (`New-AzLocalAVDVMImage`,
  `New-AzureLocalVMImageFromAzureComputeGalleryImage`, and `New-AzLocalAVDVM`).

These functions are defined in a script that also runs the full workflow at the
end of the file. It is therefore **not a function-only module**: dot-sourcing
the file to import functions also executes its deployment workflow.

### Function help

All 16 helpers, including the `New-JumpstartLocalBox` coordinator and the nested
`Test-PwnedPassword` helper, have
comment-based help with a synopsis, description, documentation for every declared
parameter, and at least one example. The deployment helper also documents its
`Credential` parameter set as an alternative to separate administrator username
and password parameters.

Read the help blocks in [`New-JumpstartLocalBox.ps1`](./New-JumpstartLocalBox.ps1)
without running the deployment. In a session where the relevant helper definitions
are already loaded, use PowerShell's help commands:

```powershell
Get-Help New-JumpstartLocalBox -Full
Get-Help New-JumpstartLocalBoxDeployment -Full
Get-Help Get-MicrosoftEdgeMarketPlaceImage -Examples
Get-Help New-AzLocalAVD -Parameter AsAJob
```

Do not dot-source the script solely to load help: doing so starts the deployment.
The nested password-check helper is local to `New-RandomPassword`, not a
standalone command available after loading the outer function.

### Marketplace discovery helper

`Get-MicrosoftEdgeMarketPlaceImage` accepts either `ResourceGroupName` with an
optional `ClusterName` (default: `localboxcluster`), or one or more Azure Stack HCI
cluster objects through `-Cluster` or the pipeline. It uses the current Azure
context and queries offers through the Azure Resource Manager batch endpoint.
Use clusters in the active subscription.

Without `-URN`, it lists every available SKU version. `-URN` accepts one or more
`publisher:offer:sku:version` identifiers and applies the version-resolution rules
described above. The default output is URN strings; `-AsObject` returns objects
with `ClusterId`, `PublisherName`, `Offer`, `Sku`, and `Version`, which the import
helper uses directly.

## Troubleshooting and further reading

- [LocalBox Getting Started](https://jumpstart.azure.com/azure_jumpstart_localbox/getting_started)
- [Deploy LocalBox with Azure Bicep](https://jumpstart.azure.com/azure_jumpstart_localbox/deployment_az)
- [Connect to and complete cloud deployment](https://jumpstart.azure.com/azure_jumpstart_localbox/cloud_deployment)
- [Use LocalBox](https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox)
- [LocalBox FAQ](https://jumpstart.azure.com/azure_jumpstart_localbox/faq)
- [LocalBox troubleshooting](https://jumpstart.azure.com/azure_jumpstart_localbox/troubleshooting)
- [Azure Arc Jumpstart LocalBox documentation source](https://github.com/Azure/arc_jumpstart_docs/tree/main/docs/azure_jumpstart_localbox)
- [Arc Jumpstart deployment templates](https://github.com/microsoft/azure_arc/tree/main/azure_jumpstart_localbox)
