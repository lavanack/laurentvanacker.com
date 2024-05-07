# Moving Azure VM to Another Resource Group with PowerShell

- [Moving Azure VM to Another Resource Group with PowerShell](#moving-azure-vm-to-another-resource-group-with-powershell)
  - [New-AzCMKVM.ps1](#new-azcmkvmps1)
  - [Move-AzResourceScript.ps1](#move-azresourcescriptps1)

## New-AzCMKVM.ps1

The [New-AzCMKVM.ps1](New-AzCMKVM.ps1) script creates 25 (By default) Azure VMs with Customer Managed Key (CMK) encryption enabled. It is a variant of the [following](../../Azure%20Key%20Vault/Azure%20Key%20Vault%20for%20Disk%20Encryption%20with%20Generated%20Customer%20Managed%20Key.ps1) script.

There are two optional parameters

- `$VMNumber`: The number of VMs to create (Default is 25 - Standard_D2s_v5 VM size is used - beware of you quota)
- `JIT`: If present, the Just-In-Time (JIT) VM Access is enabled for RDP access to the VMs

## Move-AzResourceScript.ps1

The [Move-AzResourceScript.ps1](Move-AzResourceScript.ps1) script move all VMS (and related resources like Disks, NICs and Public IPs) from a resource group to another one.

There are two mandatory parameters and an optional one (switch)

- `$SourceResourceGroupName`: The source resource group name
- `DestinationResourceGroupName`: The destination resource group name
- `Start`: If present, the VMs will be automatically started after the move
