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
#requires -Version 5 -Modules Az.Accounts, Az.Aks, Az.Compute, Az.DataProtection, Az.KubernetesConfiguration, Az.Network, Az.ResourceGraph, Az.Resources, Az.Security, Az.Storage

#From https://learn.microsoft.com/en-us/azure/aks/learn/quick-kubernetes-deploy-powershell
#From https://learn.microsoft.com/en-us/azure/backup/azure-kubernetes-service-cluster-manage-backups

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

#region Pre-requisites
try {
    $null = kubectl
}
catch {
    Write-Warning -Message "kubectl not found. We will install it via winget"
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Kubernetes.kubectl" -Wait
    #Install-AzAksCliTool
    Write-Warning -Message "kubectl installed. Re-run this script from a NEW PowerShell host !"
    break
}


try {
    $null = az
}
catch {
    Write-Warning -Message "az cli not found. We will install it via winget"
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Microsoft.AzureCLI" -Wait
    Write-Warning -Message "az cli installed. Re-run this script from a NEW PowerShell host !"
    break
}


#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = "Microsoft.ContainerService", "Microsoft.KubernetesConfiguration", "Microsoft.DataProtection"
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
}
$Jobs | Remove-Job -Force


Register-AzProviderFeature -FeatureName TrustedAccessPreview -ProviderNamespace Microsoft.ContainerService
While (Get-AzProviderFeature -FeatureName TrustedAccessPreview -ProviderNamespace Microsoft.ContainerService | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
}
#refreshing the Microsoft.ContainerService resource provider registration
Register-AzResourceProvider -ProviderNamespace 'Microsoft.ContainerService'
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace 'Microsoft.ContainerService' | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
}
#endregion

#engregion

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


$Location = "eastus2"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$BackupVaultPrefix = "bvault"
$AKSClusterPrefix = "aks"
$StorageAccountPrefix = "sa"
$ResourceGroupPrefix = "rg"
$Project = "bkp"
$Role = "aks"
$DigitNumber = 4
$StorageAccountSkuName = "Standard_GRS"
$ContainerName  ="backup"
$AKSStoreQuickstartURI = 'https://raw.githubusercontent.com/Azure-Samples/aks-store-demo/main/aks-store-quickstart.yaml'

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance
} While (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$AKSClusterName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AKSClusterPrefix, $Project, $Role, $LocationShortName, $Instance
$BackupVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $BackupVaultPrefix, $Project, $Role, $LocationShortName, $Instance

$StorageAccountName = $StorageAccountName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$AKSClusterName = $AKSClusterName.ToLower()
$BackupVaultName = $BackupVaultName.ToLower()

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region AKS Cluster Setup
#region Create AKS cluster
$SshKeyValue = Join-Path -Path $HOME -ChildPath '.ssh\id_rsa.pub'
if (Test-Path -Path $SshKeyValue -PathType Leaf) {
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 1 -EnableManagedIdentity -SshKeyValue $SshKeyValue -Force
}
else {
    $AksCluster = New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 1 -EnableManagedIdentity -GenerateSshKey -Force
}

#endregion

#region Connect to the cluster
Import-AzAksCredential -ResourceGroupName $ResourceGroupName -Name $AKSCluster.Name -Force

#Verify the connection to the cluster
kubectl get nodes
#endregion

#region Deploy the application
$AKSClusterFile = Join-Path -Path $CurrentDir -ChildPath "aks-store-quickstart.yaml"
Invoke-RestMethod -Uri $AKSStoreQuickstartURI -OutFile $AKSClusterFile
kubectl apply -f $AKSClusterFile
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "kubectl apply -f `"$AKSClusterFile`"" -Wait
Remove-Item -Path $AKSClusterFile -Force
#endregion

#region Test the application
#Check the status of the deployed pods 
kubectl get pods
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "kubectl get pods" -Wait

#Check for a public IP address for the store-front applicatio
While (kubectl get service store-front | Select-String -Pattern "pending") {
    Start-Sleep -Seconds 30
}
$ExternalIP = ((kubectl get service store-front | Select-Object -Skip 1) -split "\s+")[3]
Start-Process $("http://{0}" -f $ExternalIP)
#endregion
#endregion

#region Backup Management

#region Create a Backup vault
#Create a new Backup vault in the recovery region
Write-Host -Object "The '$BackupVaultName' Backup Vault is creating ..."
$storageSetting = New-AzDataProtectionBackupVaultStorageSettingObject -Type GeoRedundant -DataStoreType VaultStore
$BackupVault = New-AzDataProtectionBackupVault -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName -Location $Location -StorageSetting $storageSetting -IdentityType SystemAssigned -SoftDeleteState Off -CrossRegionRestoreState Enabled
Write-Host -Object "The '$BackupVaultName' Backup Vault is created ..."
#endregion

#region Create a Backup policy
$BackupPolicyName = "AKSBkpPol{0}" -f $Instance
$DataProtectionPolicyTemplate = Get-AzDataProtectionPolicyTemplate -DatasourceType AzureKubernetesService
$DataProtectionBackupPolicy = New-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -Name $BackupPolicyName -Policy $DataProtectionPolicyTemplate
#endregion

#region Prepare AKS cluster for backup
#region Create a storage account and blob container
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName
#Getting context for blob upload
$StorageContext = $StorageAccount.Context

#Create a Container 
Write-Host -Object "Creating the Container '$ContainerName' in the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
if(-not(Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue)) {
    $StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $StorageContext
}
#endregion

#region Install Backup Extension
Register-AzResourceProvider -ProviderNamespace 'Microsoft.KubernetesConfiguration'
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace 'Microsoft.KubernetesConfiguration' | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
}

$AzContext = Get-AzContext
$SubscriptionId = $AzContext.Subscription.Id

$ConfigurationSetting = @{
    "configuration.backupStorageLocation.bucket" = $ContainerName
    "configuration.backupStorageLocation.config.storageAccount" = $StorageAccountName
    "configuration.backupStorageLocation.config.resourceGroup"  = $ResourceGroupName
    "configuration.backupStorageLocation.config.subscriptionId" = $SubscriptionId
    #"configuration.backupStorageLocation.config.useAAD" = $true
    "credentials.tenantId" = $AzContext.Tenant.Id
    #"configuration.backupStorageLocation.config.storageAccountURI" = $("https://{0}.blob.core.windows.net/" -f $StorageAccountName)
} 

$KubernetesExtension = New-AzKubernetesExtension -Name azure-aks-backup -ExtensionType microsoft.dataprotection.kubernetes -ClusterType ManagedClusters -ClusterName $AKSCluster.Name -ResourceGroupName $ResourceGroupName -ReleaseTrain stable -ConfigurationSetting $ConfigurationSetting -Verbose
#$KubernetesExtension = Get-AzKubernetesExtension -ClusterName $AKSCluster.Name -ResourceGroupName $ResourceGroupName -ClusterType ManagedClusters -Name azure-aks-backup

<#
#Az Cli version
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "az config set extension.use_dynamic_install=yes_without_prompt" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "az k8s-extension create --name azure-aks-backup --extension-type microsoft.dataprotection.kubernetes --scope cluster --cluster-type managedClusters --cluster-name $($AKSCluster.Name) --resource-group $ResourceGroupName --release-train stable --configuration-settings blobContainer=$ContainerName storageAccount=$StorageAccountName storageAccountResourceGroup=$ResourceGroupName storageAccountSubscriptionId=$SubscriptionId --verbose" -Wait
#>

if (-not(Get-AzRoleAssignment -ObjectId $KubernetesExtension.AkAssignedIdentityPrincipalId -RoleDefinitionName "Storage Account Contributor" -Scope $StorageAccount.Id)) {
    Write-Verbose -Message "Assigning the 'Storage Account Contributor' RBAC role to the user identity created in the AKS cluster's Node Pool Resource Group on the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group)  ..."
    $null = New-AzRoleAssignment -ObjectId $KubernetesExtension.AkAssignedIdentityPrincipalId -RoleDefinitionName "Storage Account Contributor" -Scope $StorageAccount.Id
}
#endregion

#region Enable Trusted Access
#Enable the feature flag

Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "az extension add --name aks-preview" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "az extension update --name aks-preview" -Wait
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "az aks trustedaccess rolebinding create -g $ResourceGroupName --cluster-name $($AKSCluster.Name) -n $($AKSCluster.Name) --source-resource-id $($BackupVault.Id) --roles Microsoft.DataProtection/backupVaults/backup-operator" -Wait
az aks trustedaccess rolebinding create -g $ResourceGroupName --cluster-name $($AKSCluster.Name) -n $($AKSCluster.Name) --source-resource-id $($BackupVault.Id) --roles Microsoft.DataProtection/backupVaults/backup-operator
#endregion

#endregion

#region Configure backups
#region Key entities
#region Snapshot resource group
$SnapshotResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}-snap" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SnapshotResourceGroupName = $SnapshotResourceGroupName.ToLower()
$SnapshotResourceGroup = Get-AzResourceGroup -Name $SnapshotResourceGroupName -ErrorAction Ignore 
if ($SnapshotResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $SnapshotResourceGroup | Remove-AzResourceGroup -Force
}

$SnapshotResourceGroup = New-AzResourceGroup -Name $SnapshotResourceGroupName -Location $Location -Force
#endregion
#endregion

#region Prepare the request
$BackupConfig = New-AzDataProtectionBackupConfigurationClientObject -SnapshotVolume $true -IncludeClusterScopeResource $true -DatasourceType AzureKubernetesService -LabelSelector "env=prod"
$FriendlyName = $AKSCluster.Name
$BackupInstance = Initialize-AzDataProtectionBackupInstance -DatasourceType AzureKubernetesService  -DatasourceLocation $Location -PolicyId $DataProtectionBackupPolicy.Id -DatasourceId $AksCluster.Id -SnapshotResourceGroupId $SnapshotResourceGroup.ResourceId -FriendlyName $FriendlyName -BackupConfiguration $BackupConfig
#endregion

#region Assign required permissions and validate
Set-AzDataProtectionMSIPermission -BackupInstance $BackupInstance -VaultResourceGroup $ResourceGroupName -VaultName $BackupVault.Name -PermissionsScope "ResourceGroup" -Confirm:$false

Start-Sleep -Seconds 60

Test-AzDataProtectionBackupInstanceReadiness -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupInstance $BackupInstance.Property #-Debug

$Instance = New-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupInstance $BackupInstance
#endregion

#region Run an on-demand backup
#$Instance = Get-AzDataProtectionBackupInstance -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -Name $BackupInstance.BackupInstanceName

Do {
    $AllInstances = Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
} While (($AllInstances).Property.CurrentProtectionState -ne "ProtectionConfigured")


#From https://learn.microsoft.com/en-us/powershell/module/az.dataprotection/backup-azdataprotectionbackupinstanceadhoc?view=azps-11.1.0#example-2-backup-a-protected-backup-instance
$Jobs = foreach ($CurrentInstance in $AllInstances)
{
    Backup-AzDataProtectionBackupInstanceAdhoc -BackupInstanceName $CurrentInstance.Name -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupRuleOptionRuleName $DataProtectionBackupPolicy.Property.PolicyRule[0].Name
}

Do
{
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
    $Jobs = Get-AzDataProtectionJob -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName
} while($Jobs.Status -ne "Completed")
#endregion

#region Tracking jobs
#$Job = Search-AzDataProtectionJobInAzGraph -Subscription $SubscriptionId -ResourceGroup $ResourceGroupName -Vault $BackupVault.Name -DatasourceType AzureKubernetesService  -Operation OnDemandBackup
#endregion

#endregion

#endregion

<#
#Cleanup
Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupInstance
Get-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupPolicy
Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob
#>

            