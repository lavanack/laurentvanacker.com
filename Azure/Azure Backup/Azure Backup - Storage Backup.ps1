<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage

[CmdletBinding()]
param
(
)


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
$null = Update-AzConfig -DisplayBreakingChangeWarning $false

#region Defining variables 
$SubscriptionName = "Cloud Solution Architect"
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}

$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$RecoverySiteVaultPrefix = "rsv"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$Project = "bkp"
$Role = "storage"
$DigitNumber = 4
$StorageAccountSkuName = "Standard_GRS"
$ShareName = "fileshare001"

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance
} While (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$RecoveryServicesVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoverySiteVaultPrefix, $Project, $Role, $LocationShortName, $Instance

$StorageAccountName = $StorageAccountName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$RecoveryServicesVaultName = $RecoveryServicesVaultName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region Create a storage account and Azure FileShare
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName
Write-Host -Object "Creating the Share '$ShareName' in the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
#Create a share 
#$StorageAccountShare = New-AzRmStorageShare -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Name $ShareName -AccessTier Hot -QuotaGiB 200
$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -AccountName $StorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
$storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey.Value
$StorageAccountShare = New-AzStorageShare -Name $ShareName -Context $storageContext
#endregion

#region Create a Recovery Services vault
#Create a new Recovery services vault
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is creating ..."
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $Location -ResourceGroupName $ResourceGroupName
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is created ..."
#endregion
 
#region Setting the vault context.
Write-Host -Object "Setting the vault context ..."
$null = Set-AzRecoveryServicesVaultContext -Vault $RecoveryServicesVault
#endregion

#region Configure the backup for Azure File share
$SchPol = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType AzureFiles -BackupManagementType AzureStorage -PolicySubType Standard -ScheduleRunFrequency Daily
$RetPol = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType AzureFiles -BackupManagementType AzureStorage
$RetPol.DailySchedule.DurationCountInDays = 30
$RetPol.IsDailyScheduleEnabled = $true
$RetPol.IsMonthlyScheduleEnabled = $false
$RetPol.IsWeeklyScheduleEnabled = $false
$RetPol.IsYearlyScheduleEnabled = $false
$RecoveryServicesBackupProtectionPolicy = New-AzRecoveryServicesBackupProtectionPolicy -Name "DailyPolicy" -WorkloadType AzureFiles -BackupManagementType AzureStorage -RetentionPolicy $RetPol -SchedulePolicy $SchPol

$RecoveryServicesBackupProtection = Enable-AzRecoveryServicesBackupProtection -StorageAccountName $StorageAccount.StorageAccountName -Name $StorageAccountShare.Name -Policy $RecoveryServicesBackupProtectionPolicy

$RecoveryServicesBackupContainer = Get-AzRecoveryServicesBackupContainer -FriendlyName $StorageAccountName -ContainerType AzureStorage
$RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureFiles -VaultId $RecoveryServicesVault.ID
$Job = Backup-AzRecoveryServicesBackupItem -Item $RecoveryServicesBackupItem
Wait-AzRecoveryServicesBackupJob -Job $Job -Timeout 43200
#endregion

<#
#region Cleanup
Stop-AzRecoveryServicesBackupJob -Job $Job
$RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureFiles | Where-Object -FilterScript  {$_.DeleteState -eq "NotDeleted"}
foreach ($item in $RecoveryServicesBackupItem) { Disable-AzRecoveryServicesBackupProtection -Item $item -VaultId $RecoveryServicesVault.ID -RemoveRecoveryPoints -Force -Verbose }
Get-AzResourceLock -ResourceGroupName $ResourceGroupName | Remove-AzResourceLock -Force
Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob
#endregion
#>