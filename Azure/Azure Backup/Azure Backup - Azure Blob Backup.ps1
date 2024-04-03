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

#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = "Microsoft.DataProtection"
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
$Jobs | Remove-Job -Force
#endregion

$Location = "eastus"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$BackupVaultPrefix = "bvault"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$Project = "bkp"
$Role = "storage"
$DigitNumber = 4
$StorageAccountSkuName = "Standard_GRS"
$ContainerName = "container001"

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance
} While (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$BackupVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $BackupVaultPrefix, $Project, $Role, $LocationShortName, $Instance

$StorageAccountName = $StorageAccountName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$BackupVaultName = $BackupVaultName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region Create a storage account and Azure Container
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -AllowCrossTenantReplication $true

Write-Host -Object "Creating the Share '$ContainerName' in the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
#Create a container
$StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $StorageAccount.Context

#endregion

#region Uploading MS Edge to the container
$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"
$FileName = "MicrosoftEdgeEnterpriseX64.msi"
$Destination = Join-Path -Path $CurrentDir -ChildPath $FileName
Start-BitsTransfer -Source $MSEdgeEntUri -Destination $Destination 

# Upload the file to the blob container
Set-AzStorageBlobContent -File $Destination -Container $StorageContainer.Name -Blob $FileName -Context $StorageAccount.Context
Remove-Item -Path $Destination -Force
#endregion

#region Create a Backup vault
#Create a new Backup vault in the recovery region
Write-Host -Object "The '$BackupVaultName' Backup Vault is creating ..."
$storageSetting = New-AzDataProtectionBackupVaultStorageSettingObject -Type LocallyRedundant -DataStoreType VaultStore
$BackupVault = New-AzDataProtectionBackupVault -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName -Location $Location -StorageSetting $storageSetting -IdentityType SystemAssigned -SoftDeleteState Off
Write-Host -Object "The '$BackupVaultName' Backup Vault is created ..."
#endregion

#region Create a Backup policy
$BackupPolicyName = "BlobBkpPol{0}" -f $Instance
$DataProtectionPolicyTemplate = Get-AzDataProtectionPolicyTemplate -DatasourceType AzureBlob
$DataProtectionBackupPolicy = New-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -Name $BackupPolicyName -Policy $DataProtectionPolicyTemplate
#endregion

#region RBAC Assignement
# Assign users to the application group
$parameters = @{
    ObjectId           = $BackupVault.Identity.PrincipalId
    Scope              = $StorageAccount.Id
    RoleDefinitionName = 'Storage Account Backup Contributor'
    Verbose            = $true
}

Write-Verbose -Message "Assigning the '$($parameters.RoleDefinitionName)' RBAC role to '$($BackupVault.Name)' Backup Vault on the '$($StorageAccount.StorageAccountName)' Storage Account ..."
$null = New-AzRoleAssignment @parameters
#endregion

#region Prepare the request for enabling Azure Backup for blobs
$DataProtectionBackupInstance = Initialize-AzDataProtectionBackupInstance -DatasourceType AzureBlob -DatasourceLocation $BackupVault.Location -PolicyId $DataProtectionBackupPolicy.Id -DatasourceId $StorageAccount.Id
New-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupInstance $DataProtectionBackupInstance -NoWait
#endregion

<#
#region Cleanup
Get-AzResourceLock -ResourceGroupName $ResourceGroupName | Remove-AzResourceLock -Force
Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupInstance
Get-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupPolicy
Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob
#endregion
#>