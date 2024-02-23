# Azure Site Recovery

- [Azure Site Recovery](#azure-site-recovery)
  - [Preliminary note](#preliminary-note)
  - [Azure Site Recovery - VM Replication.ps1](#azure-site-recovery---vm-replicationps1)
  - [Azure Site Recovery - VM Replication via Azure Policy.ps1](#azure-site-recovery---vm-replication-via-azure-policyps1)

## Preliminary note

> [!NOTE]
> I used "East US" and "East US2" as source and target regions in both scripts. You can change the regions in the variables `$PrimaryLocation` and `$RecoveryLocation` at the beginning of the scripts.

## Azure Site Recovery - VM Replication.ps1

The script [Azure Site Recovery - VM Replication.ps1](./Azure%20Site%20Recovery%20-%20VM%20Replication.ps1) is based on [https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-powershell](https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-powershell).
It will mainly do the following:

- Create two resource groups (1 in a source region and 1 in a target region)
- Create two virtual networks (1 in a source region and 1 in a target region)
- Create an Azure VM in the source region
- Create a Recovery Services Vault in the target region
- Create some Azure resources in the source and target regions required for the VM replication
- Enable replication for the VM
- Replicate the VM to the target region
- Doing a test Failover of the VM to the target region
- Failover the VM to the target region (to the latest recovery point)
- Failing back the VM to the source region
- Disabling the replication

The cleanup of the resources is commented at the end of script. If you want to clean up the resources, just uncomment the last lines of the script.

## Azure Site Recovery - VM Replication via Azure Policy.ps1

The script [Azure Site Recovery - VM Replication via Azure Policy.ps1](<Azure Site Recovery - VM Replication via Azure Policy.ps1>) is based on [https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-powershell](https://learn.microsoft.com/en-us/azure/site-recovery/.azure-to-azure-powershell).

It will mainly do the following:

- Create two resource groups (1 in a source region and 1 in a target region)
- Create a virtual network (1 in a source region)
- Create an Azure VM in the source region
- Enable replication for the VM via the [Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery](https://github.com/Azure/azure-policy/blob/f3ebdd272fca516d9e904052b3f486388d6b0d55/built-in-policies/policyDefinitions/Compute/VirtualMachineReplication_AzureSiteRecovery_DINE.json) Azure Policy
- Create a remediation task for the Azure Policy with all required (and optional) parameters

Just wait and see (time the Azure Policy applies) ...

The cleanup of the resources is commented at the end of script. If you want to clean up the resources, just uncomment the last lines of the script.
