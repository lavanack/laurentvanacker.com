#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
)

#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject $AzureContext
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject $AzureContext
#endregion

#region Set Disk Configuration
$OldDiskSku = "Standard_LRS"
$NewDiskSku = "StandardSSD_LRS"
$StoppedVM = Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "VM deallocated" }
$HDDDisks = ($StoppedVM.StorageProfile.OsDisk | Get-AzDisk) | Where-Object -FilterScript { $_.Sku.Name -eq $OldDiskSku }
if ($StoppedVM.StorageProfile.DataDisks) {
    $HDDDisks += ($StoppedVM.StorageProfile.DataDisks | Get-AzDisk) | Where-Object -FilterScript { $_.Sku.Name -eq $OldDiskSku }
}

foreach ($CurrentHDDDisk in $HDDDisks) {
    Write-Output -InputObject "`$CurrentHDDDisk : $($CurrentHDDDisk.Name)"
    $CurrentHDDDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($NewDiskSku)
    $CurrentHDDDisk | Update-AzDisk
}
#endregion