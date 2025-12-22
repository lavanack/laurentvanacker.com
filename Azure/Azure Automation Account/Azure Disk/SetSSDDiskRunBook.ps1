#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
)

Clear-Host

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


#region Upgrade Exception
#Tags with name in the list Standard_LRS, StandardSSD_LRS, StandardSSD_ZRS, Premium_LRS, Premium_ZRS, UltraSSD_LRS, PremiumV2_LRS
#And a value set to a disk name
#For instace Tag Premium_LRS=vmalhypvuse2326-DataDisk01 will upgrade the vmalhypvuse2326-DataDisk01 disk to Premium_LRS 
#By default every disk will be set to StandardSSD_LRS
$RegExPattern = "(^.*_.RS$)"
#$DiskUpgradeTagHT = (Get-AzVM | Where-Object -FilterScript {$_.Tags.Keys -match $RegExPattern}).Tags | ForEach-Object -Process { $_.GetEnumerator() | Where-Object -FilterScript {$_.Key -match $RegExPattern}} | ForEach-Object -Process { foreach ($CurrentValue in $($_.Value -split ', ')) { [PSCustomObject]@{DiskName = $CurrentValue.Trim(); DiskSku = $_.Key}}} | Group-Object -Property DiskName -AsHashTable -AsString
$DiskUpgradeTagHT = @{}
(Get-AzVM | Where-Object -FilterScript {$_.Tags.Keys -match $RegExPattern}).Tags | ForEach-Object -Process { 
    $_.GetEnumerator() | Where-Object -FilterScript {$_.Key -match $RegExPattern}
} | ForEach-Object -Process { 
    foreach ($CurrentValue in $($_.Value -split '\s*,s*')) { 
        $DiskUpgradeTagHT[$CurrentValue.Trim()] = $_.Key
    }
}
#rendregion

#region Set Disk Configuration
$OldDiskSku = "Standard_LRS"
$NewDefaultDiskSku = "StandardSSD_LRS"
$StoppedVM = Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "VM deallocated" }
[array] $HDDDisks = ($StoppedVM.StorageProfile.OsDisk | Get-AzDisk) | Where-Object -FilterScript { $_.Sku.Name -eq $OldDiskSku }
if ($StoppedVM.StorageProfile.DataDisks) {
    $HDDDisks += ($StoppedVM.StorageProfile.DataDisks | Get-AzDisk) | Where-Object -FilterScript { $_.Sku.Name -eq $OldDiskSku }
}
Write-Output -InputObject "`$HDDDisks : $($HDDDisks.Name -join ', ')"

foreach ($CurrentHDDDisk in $HDDDisks) {
    Write-Output -InputObject "`$CurrentHDDDisk : $($CurrentHDDDisk.Name) - $($CurrentHDDDisk.Sku.Name)"
    $DiskUpgradeSku = $DiskUpgradeTagHT[$CurrentHDDDisk.Name]#.DiskSku
    if ($DiskUpgradeSku) {
        try {
            if ($CurrentHDDDisk.Sku.Name -ne $DiskUpgradeSku) {
                Write-Output -InputObject "Converting '$($CurrentHDDDisk.Name)' to '$DiskUpgradeSku'"
                $CurrentHDDDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($DiskUpgradeSku)
                $null = $CurrentHDDDisk | Update-AzDisk
            }
            else {
                Write-Output -InputObject "'$($CurrentHDDDisk.Name)' is already using '$DiskUpgradeSku'"
            }
        }
        catch {
            if ($CurrentHDDDisk.Sku.Name -ne $NewDefaultDiskSku) {
                Write-Warning -InputObject "Unable to convert '$($CurrentHDDDisk.Name)' to '$DiskUpgradeSku, Converting '$($CurrentHDDDisk.Name)' to '$NewDefaultDiskSku' as fallback"
                $CurrentHDDDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($NewDefaultDiskSku)
                $null = $CurrentHDDDisk | Update-AzDisk
            }
            else {
                Write-Output -InputObject "'$($CurrentHDDDisk.Name)' is already using '$NewDefaultDiskSku'"
            }
        }
    }
    else {
        if ($CurrentHDDDisk.Sku.Name -ne $NewDefaultDiskSku) {
            Write-Output -InputObject "Converting '$($CurrentHDDDisk.Name)' to '$NewDefaultDiskSku'"
            $CurrentHDDDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($NewDefaultDiskSku)
            $null = $CurrentHDDDisk | Update-AzDisk
        }
        else {
            Write-Output -InputObject "'$($CurrentHDDDisk.Name)' is already using '$NewDefaultDiskSku'"
        }
    }
}
#endregion