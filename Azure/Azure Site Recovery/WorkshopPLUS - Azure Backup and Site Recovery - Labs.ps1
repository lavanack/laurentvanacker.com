<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Monitor, Az.Network, Az.RecoveryServices, Az.Resources, Az.Security, Az.Sql, Az.Storage
[CmdletBinding(PositionalBinding = $false)]
param (
)

#region Variables
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$ResourceGroupName = "rg-ad-eastus-01"
$Location = "eastus"
$ClearTextPassword = "BCDR\@zureL\@b2023!"
$SecurePassword = $(ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force)
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$StorageAccountSkuName = "Standard_GRS"
$ShareName = "fileshare001"
$DigitNumber = 4
$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org").Content

$Error.Clear()
#endregion

#region Resource Group Cleanup
$Jobs = foreach ($CurrentResourceGroup in "rg-ad-eastus-01", "rg-bcdr-primary-region", "rg-bcdr-dr-region") {
    Get-AzResourceGroup -ResourceGroupName $CurrentResourceGroup -ErrorAction Ignore | Remove-AzResourceGroup -AsJob -Force
}
$null = $Jobs | Wait-Job
#endregion

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Host -Object "Account : $((Get-AzContext).Account)"
    Write-Host -Object "Subscription : $((Get-AzContext).Subscription.Name)"
}
#endregion

#region Azure Backup
#region Azure Backup : Lab 1

#region Azure Backup : Lab 1 : Exercise 1
#region Azure Backup : Lab 1 : Exercise 1 : Task 2
#region Azure Provider Registration
$RequiredResourceProviders = "Microsoft.Network", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.RecoveryServices", "Microsoft.BackupSolutions"
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Host -Object "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
$Jobs | Remove-Job -Force
#endregion
#endregion
#endregion

#region Azure Backup : Lab 1 : Exercise 2
#region Azure Backup : Lab 1 : Exercise 2 : Task 1
$TemplateFile = Join-Path -Path $CurrentDir -ChildPath LabsDeploymentTemplate.json
Write-Verbose -Message "`$TemplateFilePath: $TemplateFilePath  ..."
Write-Host -Object "Starting Subscription Deployment from '$TemplateFile' ..."
$TemplateParameterObject = @{
    "vmAdminPassword"  = $ClearTextPassword
    "sqlAdminPassword" = $ClearTextPassword
}
$SubscriptionDeployment = New-AzSubscriptionDeployment -Location $Location -TemplateFile $TemplateFile -TemplateParameterObject $TemplateParameterObject -Verbose
#endregion
#endregion

#region Azure Backup : Lab 1 : Exercise 3
<#
#Only needed if you don't use the previous template for deploying Azure resources
#region Azure Backup : Lab 1 : Exercise 3 : Task 1
if (Get-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Ignore) {
    Write-Host -Object "Removing '$ResourceGroupName' Resource Group Name ..."
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
}
Write-Host -Object "Creating '$ResourceGroupName' Resource Group Name ..."
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force


$TemplateURL = "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/quickstarts/microsoft.compute/vm-simple-windows/azuredeploy.json"
$TemplateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $TemplateURL -Leaf)
#Generate a unique file name 
Write-Verbose -Message "`$TemplateFilePath: $TemplateFilePath  ..."
Invoke-WebRequest -Uri $TemplateUrl -OutFile $TemplateFilePath -UseBasicParsing

$TemplateParameterObject = @{
    "adminUsername" = "azadmin"
    "adminPassword" = $ClearTextPassword
}
Write-Host -Object "Starting Resource Group Deployment from '$TemplateFilePath' ..."
$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameterObject -Verbose

#region JIT Access Management
$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name "simple-vm"
#region Enabling JIT Access
$NewJitPolicy = (@{
        id    = $VM.Id
        ports = (@{
                number                     = $RDPPort;
                protocol                   = "*";
                allowedSourceAddressPrefix = "*";
                maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
            })   
    })

Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
$ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
$UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
$UpdatedJITPolicy.Add($NewJitPolicy)
	
# Enable Access to the VM including management Port, and Time Range in Hours
Write-Host "Enabling Just in Time VM Access Policy for ($($VM.Name)) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
$null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
#endregion

#region Requesting Temporary Access : 3 hours
$JitPolicy = (@{
        id    = $VM.Id
        ports = (@{
                number                     = $RDPPort;
                endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                allowedSourceAddressPrefix = @($MyPublicIP) 
            })
    })
$ActivationVM = @($JitPolicy)
Write-Host "Requesting Temporary Acces via Just in Time for ($($VM.Name)) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
#endregion
#endregion
#endregion
#>

#region Azure Backup : Lab 1 : Exercise 3 : Task 2
$TemplateURL = "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json"
$TemplateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $TemplateURL -Leaf)
#Generate a unique file name 
Write-Verbose -Message "`$TemplateFilePath: $TemplateFilePath  ..."
Invoke-WebRequest -Uri $TemplateUrl -OutFile $TemplateFilePath -UseBasicParsing

$TemplateParameterObject = @{
    "administratorLogin"         = "azadmin"
    "administratorLoginPassword" = $ClearTextPassword
}
Write-Host -Object "Starting Resource Group Deployment from '$TemplateFilePath' ..."
$ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $TemplateFilePath -TemplateParameterObject $TemplateParameterObject -Verbose
#endregion

#region Azure Backup : Lab 1 : Exercise 3 : Task 3
Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "saadeastus{0:D$DigitNumber}" -f $Instance                       
} While (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName
Write-Host -Object "Creating the Share '$ShareName' in the Storage Account '$StorageAccountName' (in the '$ResourceGroupName' Resource Group) ..."
#Create a share 
#$StorageAccountShare = New-AzRmStorageShare -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Name $ShareName -AccessTier Hot -QuotaGiB 200
$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -AccountName $StorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
$storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey.Value
$StorageAccountShare = New-AzStorageShare -Name $ShareName -Context $storageContext


#endregion
#endregion

#endregion

#region Azure Backup : Lab 2

#region Azure Backup : Lab 2 : Exercise 1

#region Azure Backup : Lab 2 : Exercise 1 : Task 1
#region Create a Recovery Services vault
$RecoveryServicesVaultName = "rsv-bcdr-primary"
$ResourceGroupName = "rg-bcdr-primary-region"
#Create a new Recovery services vault in the recovery region
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is creating ..."
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $Location -ResourceGroupName $ResourceGroupName
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is created ..."
#endregion

#region Setting the vault context.
Write-Host -Object "Setting the vault context ..."
$null = Set-AzRecoveryServicesVaultContext -Vault $RecoveryServicesVault
#endregion
#endregion

#region Azure Backup : Lab 2 : Exercise 1 : Task 2
Set-AzRecoveryServicesBackupProperty -Vault $RecoveryServicesVault -BackupStorageRedundancy GeoRedundant
#endregion

#region Azure Backup : Lab 2 : Exercise 1 : Task 3
$SchPol = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType AzureVM -BackupManagementType AzureVM -PolicySubType Enhanced -ScheduleRunFrequency Hourly
$RetPol = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType AzureVM -BackupManagementType AzureVM
$RetPol.DailySchedule.DurationCountInDays = 180
$RetPol.IsDailyScheduleEnabled = $true
$RetPol.IsMonthlyScheduleEnabled = $false
$RetPol.IsWeeklyScheduleEnabled = $false
$RetPol.IsYearlyScheduleEnabled = $false
$RecoveryServicesBackupProtectionPolicy = New-AzRecoveryServicesBackupProtectionPolicy -Name "WorkshopPolicy" -WorkloadType AzureVM -BackupManagementType AzureVM -RetentionPolicy $RetPol -SchedulePolicy $SchPol
#endregion

#region Azure Backup : Lab 2 : Exercise 1 : Task 4
$ResourceGroupName = "rg-bcdr-primary-region"
$VM = Get-AzVM -ResourceGroupName $ResourceGroupName
$RecoveryServicesBackupProtections = foreach ($CurrentVM in $VM) {
    Enable-AzRecoveryServicesBackupProtection -VaultId $RecoveryServicesVault.ID -Policy $RecoveryServicesBackupProtectionPolicy -Name $CurrentVM.Name -ResourceGroupName $ResourceGroupName
}
$RecoveryServicesBackupProtections
#endregion

#region Azure Backup : Lab 2 : Exercise 1 : Task 5
$Jobs = foreach ($CurrentVM in $VM) {
    $RecoveryServicesBackupContainer = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -FriendlyName $CurrentVM.Name
    $RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID
    $EndDate = (Get-Date).AddDays(60).ToUniversalTime()
    Backup-AzRecoveryServicesBackupItem -Item $RecoveryServicesBackupItem -VaultId $RecoveryServicesVault.ID -ExpiryDateTimeUTC $EndDate
}
#endregion

#endregion
#endregion

#region Azure Backup : Lab 3

#region Azure Backup : Lab 3 : Exercise 1

#region Azure Backup : Lab 3 : Exercise 1 : Task 1
foreach ($CurrentVM in $VM) {
    # Get the container
    $RecoveryServicesBackupContainer = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -FriendlyName $CurrentVM.Name -VaultId $RecoveryServicesVault.ID

    # Get the backup item
    $RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID
    $RecoveryServicesBackupItem | Format-List -Property * -Force
}
#endregion

#region Azure Backup : Lab 3 : Exercise 1 : Task 2
$Jobs
#endregion

#region Azure Backup : Lab 3 : Exercise 1 : Task 3
#Enabling the Built-in Azure Monitor alerts for job failures
Update-AzRecoveryServicesVault -ResourceGroupName $ResourceGroupName -Name $RecoveryServicesVault.Name -DisableAzureMonitorAlertsForJobFailure $false -Verbose
#endregion

#region Azure Backup : Lab 3 : Exercise 1 : Task 4
Import-Module -Name Az.Monitor
# Define the name of your resource group and action group, and the email receiver
$ResourceGroupName = "rg-bcdr-primary-region"
$ActionGroupName = "ag-bcdr-primary-region"
$EmailAddress = "lavanack@microsoft.com"
# Define the short name of the action group
$ShortName = "MyActionGrp"

# Create an action group for an email notification
$EmailReceiver = New-AzActionGroupEmailReceiverObject -EmailAddress $EmailAddress -Name $EmailAddress
$ActionGroup = New-AzActionGroup -Name $ActionGroupName -ResourceGroupName $ResourceGroupName -ShortName $ShortName -EmailReceiver $EmailReceiver -Location global

#create the Action Rule
$azContext = Get-AzContext
$SubcriptionID = $azContext.Subscription.Id
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.AccessToken
}
#endregion
$Body = @{
    location   = "Global"
    name       = "My Rule Name"
    properties = @{
        scopes  = @($RecoveryServicesVault.ID)
        actions = @(
            @{
                actionGroupIds = @($ActionGroup.Id)
                actionType     = "AddActionGroups"
            }
        )
        enabled = $true
    }
}
$URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.AlertsManagement/actionRules/My Rule Name?api-version=2021-08-08"
try {
    # Invoke the REST API
    $Response = Invoke-RestMethod -Method PUT -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
    if (-not([string]::IsNullOrEmpty($Response.message))) {
        Write-Warning -Message $Response.message
    }
}
finally {
    $Response
}


#endregion
#endregion

#region Azure Backup : Lab 4

#region Azure Backup : Lab 4 : Exercise 1

#region Azure Backup : Lab 4 : Exercise 1 : Task 1

#region Waiting the Job backups complete
$Jobs = Get-AzRecoveryServicesBackupJob -Operation Backup -VaultId $RecoveryServicesVault.ID
Wait-AzRecoveryServicesBackupJob -Job $Jobs -Timeout 43200
<#
#while ($null -ne ($Jobs | Where-Object -FilterScript { $_.Status -eq "InProgress"})) {
while ($Jobs.Status -eq "InProgress"}) {
    #If the job hasn't completed, sleep for 30 seconds before checking the job status again
    Start-Sleep -Seconds 30
    $Jobs = Get-AzRecoveryServicesBackupJob -Operation Backup -VaultId $RecoveryServicesVault.ID
}
#>
#endregion 

#Selecting the VM
$VMName = $VM[0].Name
$RecoveryServicesBackupContainer = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -FriendlyName $VMName -VaultId $RecoveryServicesVault.ID
$RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID
#Choosing the latest recovery point
$LatestRecoveryServicesBackupRecoveryPoint = Get-AzRecoveryServicesBackupRecoveryPoint -Item $RecoveryServicesBackupItem | Sort-Object -Property RecoveryPointTime -Descending | Select-Object -First 1

$ResourceGroupName = "rg-ad-eastus-01"
$TargetVMName = "vm-restore"
$TargetVNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName
#$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName | Where-Object -FilterScript { $_.StorageAccountName -match "^boot" }
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$Restorejob = Restore-AzRecoveryServicesBackupItem -RecoveryPoint $LatestRecoveryServicesBackupRecoveryPoint -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountResourceGroupName $ResourceGroupName -TargetResourceGroupName $ResourceGroupName -VaultId $RecoveryServicesVault.ID -TargetVMName $TargetVMName -TargetVNetResourceGroup $ResourceGroupName -TargetVNetName $TargetVNet.Name -TargetSubnetName $TargetVNet.Subnets[0].Name
Wait-AzRecoveryServicesBackupJob -Job $Restorejob -Timeout 43200
$RecoveryServicesBackupJobDetail = Get-AzRecoveryServicesBackupJobDetail -Job $Restorejob -VaultId $RecoveryServicesVault.ID
#endregion

#region Azure Backup : Lab 4 : Exercise 1 : Task 2
$VMName = $VM[-1].Name
$RecoveryServicesBackupContainer = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -FriendlyName $VMName -VaultId $RecoveryServicesVault.ID
$RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -Container $RecoveryServicesBackupContainer -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID
#Choosing the latest recovery point
$LatestRecoveryServicesBackupRecoveryPoint = Get-AzRecoveryServicesBackupRecoveryPoint -Item $RecoveryServicesBackupItem | Sort-Object -Property RecoveryPointTime -Descending | Select-Object -First 1

$ResourceGroupName = "rg-ad-eastus-01"
#$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName | Where-Object -FilterScript { $_.StorageAccountName -match "^boot" }
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$DataDisks = (Get-AzVM -Name $VMName).StorageProfile.DataDisks.Lun
$Restorejob = Restore-AzRecoveryServicesBackupItem -RecoveryPoint $LatestRecoveryServicesBackupRecoveryPoint -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountResourceGroupName $ResourceGroupName -TargetResourceGroupName $ResourceGroupName -VaultId $RecoveryServicesVault.ID -RestoreDiskList $DataDisks
Wait-AzRecoveryServicesBackupJob -Job $Restorejob -Timeout 43200
$RecoveryServicesBackupJobDetail = Get-AzRecoveryServicesBackupJobDetail -Job $Restorejob -VaultId $RecoveryServicesVault.ID
#endregion

#endregion

#region Azure Backup : Lab 4 : Exercise 2

#region Azure Backup : Lab 4 : Exercise 2 : Task 1
Set-AzRecoveryServicesBackupProperty -Vault $RecoveryServicesVault -EnableCrossRegionRestore
#endregion

#region Azure Backup : Lab 4 : Exercise 2 : Task 2
#Nothing to script
#endregion

#region Azure Backup : Lab 4 : Exercise 2 : Task 3
Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID -UseSecondaryRegion | Format-List -Property * -Force
#endregion

#region Azure Backup : Lab 4 : Exercise 2 : Task 4
Get-AzRecoveryServicesBackupJob -UseSecondaryRegion -VaultLocation $RecoveryServicesVault.Location
#endregion

#endregion


#endregion

#region Azure Backup : Lab 5

#region Azure Backup : Lab 5 : Exercise 1

#region Azure Backup : Lab 5 : Exercise 1 : Task 1
$ResourceGroupName = "rg-ad-eastus-01"
$LogAnalyticsWorkSpaceName = "opiw-ad-eastus-01"
Write-Host -Object "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$ResourceGroupName' Resource Group) ..."
$LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroupName -Force
Do {
    Write-Host -Object "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
    $LogAnalyticsWorkSpace = $null
    $LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkSpaceName -ResourceGroupName $ResourceGroupName
} While ($null -eq $LogAnalyticsWorkSpace)
Write-Host -Object "Sleeping 30 seconds ..."
Start-Sleep -Seconds 30
#endregion

#region Azure Backup : Lab 5 : Exercise 1 : Task 2
Write-Host -Object "Enabling Diagnostics Setting for the '$($RecoveryServicesVault.Name)' Host Pool (in the '$ResourceGroupName' Resource Group) ..."
$DiagnosticSetting = Set-AzDiagnosticSetting -Name $RecoveryServicesVault.Name -ResourceId $RecoveryServicesVault.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "CoreAzureBackup", "AddonAzureBackupJobs", "AddonAzureBackupPolicy", "AddonAzureBackupStorage", "AddonAzureBackupProtectedInstance"
#endregion

#region Azure Backup : Lab 5 : Exercise 1 : Task 3
#Nothing to script
#endregion

#region Azure Backup : Lab 5 : Exercise 1 : Task 4
#Nothing to script
#endregion

#endregion
#endregion

#region Azure Backup : Lab 6

#region Azure Backup : Lab 6 : Exercise 1

#region Azure Backup : Lab 6 : Exercise 1 : Task 1
$SchPol = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType AzureVM -BackupManagementType AzureVM -PolicySubType Enhanced -ScheduleRunFrequency Hourly
$RetPol = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType AzureVM -BackupManagementType AzureVM
$RetPol.DailySchedule.DurationCountInDays = 180
$RetPol.IsDailyScheduleEnabled = $true
$RetPol.IsMonthlyScheduleEnabled = $false
$RetPol.IsWeeklyScheduleEnabled = $false
$RetPol.IsYearlyScheduleEnabled = $false
$RecoveryServicesBackupProtectionPolicy = New-AzRecoveryServicesBackupProtectionPolicy -Name "WorkshopPolicyLab6" -WorkloadType AzureVM -BackupManagementType AzureVM -RetentionPolicy $RetPol -SchedulePolicy $SchPol
#endregion

#region Azure Backup : Lab 6 : Exercise 1 : Task 2
$SchPol = Get-AzRecoveryServicesBackupSchedulePolicyObject -WorkloadType AzureVM 
$SchPol.ScheduleRunTimes.Clear()
$Time = Get-Date
$Time1 = Get-Date -Year $Time.Year -Month $Time.Month -Day $Time.Day -Hour $Time.Hour -Minute 0 -Second 0 -Millisecond 0
$Time1 = $Time1.ToUniversalTime()
$SchPol.ScheduleRunTimes.Add($Time1)
$SchPol.ScheduleRunDays = "Sunday"
$SchPol.ScheduleRunFrequency.Clear
$SchPol.ScheduleRunFrequency = "Weekly"
$RetPol = Get-AzRecoveryServicesBackupRetentionPolicyObject -WorkloadType AzureVM 
$RetPol.IsMonthlyScheduleEnabled = $true
$RetPol.IsYearlyScheduleEnabled = $false
$RetPol.IsDailyScheduleEnabled = $false
$RetPol.DailySchedule.DurationCountInDays = 0
$RetPol.IsWeeklyScheduleEnabled = $true 
$RetPol.WeeklySchedule.DaysOfTheWeek = "Sunday"
$RetPol.WeeklySchedule.DurationCountInWeeks = 12
$RetPol.MonthlySchedule.DurationCountInMonths = 60

$RecoveryServicesBackupProtectionPolicy = Get-AzRecoveryServicesBackupProtectionPolicy -Name "DefaultPolicy" -VaultId $RecoveryServicesVault.ID
$RecoveryServicesBackupProtectionPolicy.SnapshotRetentionInDays = 5
Set-AzRecoveryServicesBackupProtectionPolicy -Policy $RecoveryServicesBackupProtectionPolicy -SchedulePolicy $SchPol -RetentionPolicy $RetPol
#endregion

#region Azure Backup : Lab 6 : Exercise 2 : Task 1
$RecoveryServicesBackupItem = Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $RecoveryServicesVault.ID | Where-Object { $_.DeleteState -eq "NotDeleted" }

foreach ($CurrentRecoveryServicesBackupItem in $RecoveryServicesBackupItem) {
    Disable-AzRecoveryServicesBackupProtection -Item $CurrentRecoveryServicesBackupItem -VaultId $RecoveryServicesVault.ID -RemoveRecoveryPoints -Force -Verbose
}
#endregion

#endregion
#endregion

#region Azure Backup : Lab 7

#region Azure Backup : Lab 7 : Exercise 1

#region Azure Backup : Lab 7 : Exercise 1 : Task 1
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

#endregion
#endregion

#region Azure Backup : Lab 8

#region Azure Backup : Lab 8 : Exercise 1

#region Azure Backup : Lab 8 : Exercise 1 : Task 1
$ResourceGroupName = "rg-ad-eastus-01"
#Using the Instance number to create a unique SQL Server
$SqlServerName = "mysqldblab{0:D$DigitNumber}" -f $Instance   
$SqlServerDatabaseName = "MySQLDBLab"
$WhoAmI = $azContext.Account.Id
$SqlServer = New-AzSqlServer -ResourceGroupName $ResourceGroupName -Location $Location -ServerName $SqlServerName -ExternalAdminName $WhoAmI -EnableActiveDirectoryOnlyAuthentication
$SqlDatabase = New-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName -DatabaseName $SqlServerDatabaseName -Edition "GeneralPurpose" -Vcore 2 -ComputeGeneration "Gen5" #-AsJob

#Retention Policy
$SqlDatabaseBackupShortTermRetentionPolicy = Get-AzSqlDatabaseBackupShortTermRetentionPolicy -ServerName $SqlServerName -DatabaseName $SqlServerDatabaseName -ResourceGroupName $ResourceGroupName
$SqlDatabaseBackupShortTermRetentionPolicy

$SqlDatabaseBackupLongTermRetentionPolicy = Get-AzSqlDatabaseBackupLongTermRetentionPolicy -ServerName $SqlServerName -DatabaseName $SqlServerDatabaseName -ResourceGroupName $ResourceGroupName
$SqlDatabaseBackupLongTermRetentionPolicy
#endregion

#region Azure Backup : Lab 8 : Exercise 1 : Task 1
#Waiting the Backup completes
While ($null -eq (Get-AzSqlDatabaseRestorePoint -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName -DatabaseName $SqlServerDatabaseName)) {
    Start-Sleep -Seconds 60
}

$TargetDatabaseName = "nmw-app-db_restore"
$10MinutesAgoUTC = $([datetime]::UtcNow).AddMinutes(-10)
$SqlDatabase = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServer.ServerName -DatabaseName $SqlServerDatabaseName
Restore-AzSqlDatabase -FromPointInTimeBackup -PointInTime $10MinutesAgoUTC -ResourceGroupName $SqlDatabase.ResourceGroupName -ServerName $SqlDatabase.ServerName -TargetDatabaseName $TargetDatabaseName -ResourceId $SqlDatabase.ResourceID -Edition "Standard" -ServiceObjectiveName "S3"
#endregion

#endregion
#endregion
#endregion

#region Azure Site Recovery

#region Azure Site Recovery : Lab 1

#region Azure Site Recovery : Lab 1 : Exercise 1

#region Azure Site Recovery : Lab 1 : Exercise 1 : Task 1
#region Create a Recovery Services vault
$PrimaryLocation = "eastus"
$RecoveryLocation = "eastus2"
$RecoveryServicesVaultName = "rsv-bcdr-dr"
$PrimaryLocationResourceGroupName = "rg-bcdr-primary-region"
$RecoveryLocationResourceGroupName = "rg-bcdr-dr-region"
$RecoveryLocationResourceGroup = Get-AzResourceGroup -Name $RecoveryLocationResourceGroupName 

#Create a new Recovery services vault in the recovery region
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is creating ..."
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $RecoveryLocation -ResourceGroupName $RecoveryLocationResourceGroupName
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is created ..."
#endregion
#endregion

#region Azure Site Recovery : Lab 1 : Exercise 1 : Task 2
#region Variables
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
$PrimaryLocationShortName = $shortNameHT[$PrimaryLocation].shortName
$RecoveryLocationShortName = $shortNameHT[$RecoveryLocation].shortName
$RecoveryServicesAsrFabricPrefix = "rsaf"
$RecoveryServicesAsrProtectionContainerPrefix = "rsapc"
$RecoverySiteVaultPrefix = "rsv"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$Project = "bcdr"
$Role = "dr"

$PrimaryLocationRecoveryServicesAsrFabricName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrFabricPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance
$RecoveryLocationRecoveryServicesAsrFabricName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrFabricPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance               
$PrimaryLocationRecoveryServicesAsrProtectionContainerName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrProtectionContainerPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance
$RecoveryLocationRecoveryServicesAsrProtectionContainerName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrProtectionContainerPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance


Do {
    #Create Cache storage account for replication logs in the primary region
    $PrimaryLocationCacheStorageAccountName = "{0}{1}{2}cache{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
    #Create Cache storage account for replication logs in the recovery region
    $RecoveryLocationCacheStorageAccountName = "{0}{1}{2}cache{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
    $RecoveryLocationStorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
} While ((-not(Get-AzStorageAccountNameAvailability -Name $PrimaryLocationCacheStorageAccountName).NameAvailable) -or (-not(Get-AzStorageAccountNameAvailability -Name $RecoveryLocationCacheStorageAccountName).NameAvailable) -or (-not(Get-AzStorageAccountNameAvailability -Name $RecoveryLocationStorageAccountName).NameAvailable))
#endregion

#region Setting the vault context.
Write-Host -Object "Setting the vault context ..."
$null = Set-AzRecoveryServicesAsrVaultContext -Vault $RecoveryServicesVault
#endregion

#region Prepare the vault to start replicating Azure Virtual Machines
Write-Host -Object "Preparing the '$RecoveryServicesVaultName' Recovery Services Vault to start replicating Azure Virtual Machines ..."

#region Create a Site Recovery fabric object to represent the primary (source) region
Write-Host -Object "Creating a Site Recovery fabric object to represent the primary (source) region ('$PrimaryLocation') ..."
#Create Primary ASR fabric
$TempASRJob = New-AzRecoveryServicesAsrFabric -Azure -Location $PrimaryLocation -Name $PrimaryLocationRecoveryServicesAsrFabricName

# Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    #If the job hasn't completed, sleep for 10 seconds before checking the job status again
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Site Recovery fabric creation status: $($TempASRJob.State) ..."

$PrimaryLocationFabric = Get-AzRecoveryServicesAsrFabric -Name $PrimaryLocationRecoveryServicesAsrFabricName
#endregion

#region Create a Site Recovery fabric object to represent the recovery region
Write-Host -Object "Creating a Site Recovery fabric object to represent the recovery region ('$RecoveryLocation') ..."
#Create Recovery ASR fabric
$TempASRJob = New-AzRecoveryServicesAsrFabric -Azure -Location $RecoveryLocation -Name $RecoveryLocationRecoveryServicesAsrFabricName

# Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Site Recovery fabric creation status: $($TempASRJob.State) ..."

$RecoveryLocationFabric = Get-AzRecoveryServicesAsrFabric -Name $RecoveryLocationRecoveryServicesAsrFabricName
#endregion

#region Create a Protection container in the primary Azure region (within the Primary fabric)
Write-Host -Object "Creating a Protection container in the primary Azure region ('$PrimaryLocation')(within the Primary fabric)"
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainer -InputObject $PrimaryLocationFabric -Name $PrimaryLocationRecoveryServicesAsrProtectionContainerName

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Protection container creation status: $($TempASRJob.State) ..."

$PrimaryProtectionContainer = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $PrimaryLocationFabric -Name $PrimaryLocationRecoveryServicesAsrProtectionContainerName
#endregion

#region Create a Protection container in the recovery Azure region (within the Recovery fabric)
Write-Host -Object "Creating a Protection container in the recovery Azure region ('$RecoveryLocation')(within the Recovery fabric)"
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainer -InputObject $RecoveryLocationFabric -Name $RecoveryLocationRecoveryServicesAsrProtectionContainerName

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Protection container creation status: $($TempASRJob.State) ..."
$RecoveryProtectionContainer = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $RecoveryLocationFabric -Name $RecoveryLocationRecoveryServicesAsrProtectionContainerName
#endregion

#region Create replication policy
Write-Host -Object "Creating replication policy ..."
$RecoveryServicesAsrPolicyName = "{0} - A2APolicy" -f $RecoveryServicesVaultName
$TempASRJob = New-AzRecoveryServicesAsrPolicy -AzureToAzure -Name $RecoveryServicesAsrPolicyName -RecoveryPointRetentionInHours 24 -ApplicationConsistentSnapshotFrequencyInHours 0

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Replication policy creation status: $($TempASRJob.State) ..."

$ReplicationPolicy = Get-AzRecoveryServicesAsrPolicy -Name $RecoveryServicesAsrPolicyName
#endregion

#region Create Protection container mapping between the Primary and Recovery Protection Containers with the Replication policy
Write-Host "Creating Protection container mapping between the Primary and Recovery Protection Containers with the Replication policy ..."
$PrimaryToRecoveryPCMappingName = "{0} - A2APrimaryToRecovery" -f $RecoveryServicesVaultName
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainerMapping -Name $PrimaryToRecoveryPCMappingName -Policy $ReplicationPolicy -PrimaryProtectionContainer $PrimaryProtectionContainer -RecoveryProtectionContainer $RecoveryProtectionContainer 

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Protection container mapping creation status: $($TempASRJob.State) ..."

$PrimaryToRecoveryPCMapping = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $PrimaryProtectionContainer -Name $PrimaryToRecoveryPCMappingName
#endregion

#region Create Protection container mapping (for fail back) between the Recovery and Primary Protection Containers with the Replication policy
Write-Host -Object "Creating Protection container mapping (for fail back) between the Recovery and Primary Protection Containers with the Replication policy..." 
$RecoveryToPrimaryPCMappingName = "{0} - A2ARecoveryToPrimary" -f $RecoveryServicesVaultName
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainerMapping -Name $RecoveryToPrimaryPCMappingName -Policy $ReplicationPolicy -PrimaryProtectionContainer $RecoveryProtectionContainer  -RecoveryProtectionContainer $PrimaryProtectionContainer

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Protection container mapping creation status: $($TempASRJob.State) ..."


$RecoveryToPrimaryPCMapping = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $RecoveryProtectionContainer -Name $RecoveryToPrimaryPCMappingName
#endregion

#endregion

#region Create cache storage account and target storage account
Write-Host -Object "Creating cache storage account and target storage account ..."

#region Create Cache storage account for replication logs in the primary region
Write-Host -Object "Creating cache storage account for replication logs in the primary region ('$PrimaryLocation') ..."
$PrimaryLocationCacheStorageAccount = New-AzStorageAccount -Name $PrimaryLocationCacheStorageAccountName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -SkuName Standard_LRS -Kind Storage
#endregion

#region Create Cache storage account for replication logs in the recovery region
Write-Host -Object "Creating cache storage account for replication logs in the recovery region ('$RecoveryLocation') ..."
$RecoveryLocationCacheStorageAccount = New-AzStorageAccount -Name $RecoveryLocationCacheStorageAccountName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -SkuName Standard_LRS -Kind Storage
#endregion

<#
#region Create Target storage account in the recovery region. In this case a Standard Storage account for virtual machines not using managed disks
Write-Host -Object "Creating Target storage account in the recovery region ('$RecoveryLocation'). In this case a Standard Storage account..."
$RecoveryLocationStorageAccount = New-AzStorageAccount -Name $RecoveryLocationStorageAccountName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -SkuName Standard_LRS -Kind Storage
#endregion
#>
#endregion

#region Primary Location
$PrimaryLocationVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $PrimaryLocationResourceGroupName
#endregion

#region Recovery Location
$RecoveryLocationVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $RecoveryLocationResourceGroupName
#endregion

#region Create network mappings
#region Create an ASR network mapping between the primary Azure virtual network and the recovery Azure virtual network
#region Create network mappings
Write-Host "Creating an ASR network mapping between the primary Azure virtual network and the recovery Azure virtual network ..."
$RecoveryServicesAsrNetworkMappingName = "A2A{0}To{1}NWMapping" -f $PrimaryLocationShortName, $RecoveryLocationShortName
$TempASRJob = New-AzRecoveryServicesAsrNetworkMapping -AzureToAzure -Name $RecoveryServicesAsrNetworkMappingName -PrimaryFabric $PrimaryLocationFabric -PrimaryAzureNetworkId $PrimaryLocationVirtualNetwork.Id -RecoveryFabric $RecoveryLocationFabric -RecoveryAzureNetworkId $RecoveryLocationVirtualNetwork.Id

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "ASR network mapping creation status: $($TempASRJob.State) ..."

#Create an ASR network mapping for fail back between the recovery Azure virtual network and the primary Azure virtual network
Write-Host "Creating ASR network mapping for fail back between the recovery Azure virtual network and the primary Azure virtual network ..."
$RecoveryServicesAsrNetworkMappingName = "A2A{0}To{1}NWMapping" -f $RecoveryLocationShortName, $PrimaryLocationShortName
$TempASRJob = New-AzRecoveryServicesAsrNetworkMapping -AzureToAzure -Name $RecoveryServicesAsrNetworkMappingName -PrimaryFabric $RecoveryLocationFabric -PrimaryAzureNetworkId $RecoveryLocationVirtualNetwork.Id -RecoveryFabric $PrimaryLocationFabric -RecoveryAzureNetworkId $PrimaryLocationVirtualNetwork.Id

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "ASR network mapping creation status: $($TempASRJob.State) ..."
#endregion
#endregion
#endregion

#region Replicate Azure Virtual Machine(s) with managed disks.
$VM = Get-AzVM -ResourceGroupName $PrimaryLocationResourceGroupName
$Jobs = foreach ($CurrentVM in $VM) {
    Write-Host -Object "'$($CurrentVM.Name)' Azure Virtual Machine - Replicating with managed disks ..."
    #Specify replication properties for each disk of the VM that is to be replicated (create disk replication configuration)

    #region OS Disk
    $OSdiskId = $CurrentVM.StorageProfile.OsDisk.ManagedDisk.Id
    $RecoveryOSDiskAccountType = $CurrentVM.StorageProfile.OsDisk.ManagedDisk.StorageAccountType
    $RecoveryReplicaDiskAccountType = $CurrentVM.StorageProfile.OsDisk.ManagedDisk.StorageAccountType
    $OSDiskReplicationConfig = New-AzRecoveryServicesAsrAzureToAzureDiskReplicationConfig -ManagedDisk -LogStorageAccountId $PrimaryLocationCacheStorageAccount.Id -DiskId $OSdiskId -RecoveryResourceGroupId  $RecoveryLocationResourceGroup.ResourceId -RecoveryReplicaDiskAccountType  $RecoveryReplicaDiskAccountType -RecoveryTargetDiskAccountType $RecoveryOSDiskAccountType
    #endregion
 
    #region Data Disk(s)
    $DataDisksReplicationConfig = foreach ($CurrentVMDataManagedDisk in $CurrentVM.StorageProfile.DataDisks.ManagedDisk) {
        $RecoveryReplicaDiskAccountType = $CurrentVMDataManagedDisk.StorageAccountType
        $RecoveryTargetDiskAccountType = $CurrentVMDataManagedDisk.StorageAccountType
        New-AzRecoveryServicesAsrAzureToAzureDiskReplicationConfig -ManagedDisk -LogStorageAccountId $PrimaryLocationCacheStorageAccount.Id -DiskId $CurrentVMDataManagedDisk.Id -RecoveryResourceGroupId $RecoveryLocationResourceGroup.ResourceId -RecoveryReplicaDiskAccountType $RecoveryReplicaDiskAccountType -RecoveryTargetDiskAccountType $RecoveryTargetDiskAccountType
    }
    #endregion

    #Create a list of disk replication configuration objects for the disks of the virtual machine that are to be replicated.
    $DiskConfigs = @($OSDiskReplicationConfig) + $DataDisksReplicationConfig

    #Start replication by creating replication protected item. Using a GUID for the name of the replication protected item to ensure uniqueness of name.
    Write-Host "'$($CurrentVM.Name)' Azure Virtual Machine - Starting replication by creating replication protected item ..."
    New-AzRecoveryServicesAsrReplicationProtectedItem -AzureToAzure -AzureVmId $CurrentVM.Id -Name (New-Guid).Guid -ProtectionContainerMapping $PrimaryToRecoveryPCMapping -AzureToAzureDiskReplicationConfiguration $DiskConfigs -RecoveryResourceGroupId $RecoveryLocationResourceGroup.ResourceId -ReplicationGroupName "VM-BCDR"
}

#Track Job status to check for completion
while (($Jobs.State -contains "InProgress") -or ($Jobs.State -contains "NotStarted")) {
        Start-Sleep -Seconds 10
        $Jobs = foreach ($CurrentJob in $Jobs) {
            Get-AzRecoveryServicesAsrJob -Job $CurrentJob
        }
}

foreach ($CurrentJob in $Jobs) {
    #Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
    Write-Host -Object "'$($CurrentJob.TargetObjectName)' Azure Virtual Machine - Replication protected item creation status: $($CurrentJob.State) ..."
    #Monitor the replication state and replication health
}
Write-Host -Object "Waiting the replication state of the replicated items ($($Jobs.TargetObjectName -join ', ')) be 'protected' ..." 
Write-Host -Object "Replication state of the replicated items ($($Jobs.TargetObjectName -join ', ')): $(Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer | Select-Object -Property FriendlyName, ProtectionState, ReplicationHealth | Out-String)"


Write-Host -Object "Waiting the replication state of the replicated items ($($Jobs.TargetObjectName -join ', ')) completes ..."
while ((Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer).ProtectionState -ne "Protected") {
    Start-Sleep -Seconds 60
}

#Monitor the replication state and replication health
Write-Host -Object "Replication state of the replicated items ($($Jobs.TargetObjectName -join ', ')): $(Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer | Select-Object -Property  FriendlyName, ProtectionState, ReplicationHealth | Out-String)"
#endregion

#endregion

#endregion
#endregion

#region Azure Site Recovery : Lab 2

#region Azure Site Recovery : Lab 2 : Exercise 1

#region Azure Site Recovery : Lab 2 : Exercise 1 : Task 1
#region Create replication policy
Write-Host -Object "Creating replication policy ..."
$RecoveryServicesAsrPolicyName = "{0} - A2APolicy2" -f $RecoveryServicesVaultName
$TempASRJob = New-AzRecoveryServicesAsrPolicy -AzureToAzure -Name $RecoveryServicesAsrPolicyName -RecoveryPointRetentionInHours 24 -ApplicationConsistentSnapshotFrequencyInHours 0

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Replication policy creation status: $($TempASRJob.State) ..."

$ReplicationPolicy = Get-AzRecoveryServicesAsrPolicy -Name $RecoveryServicesAsrPolicyName
#endregion
#endregion

#region Azure Site Recovery : Lab 2 : Exercise 1 : Task 2
# Create the recovery plan
Write-Host -Object "Creating Recovery Plan ..."
$RecoveryServicesAsrPolicyName = "{0}-recovery-plan" -f $RecoveryServicesVaultName
$RecoveryServicesAsrReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer
$RecoveryServicesAsrRecoveryPlan = New-AzRecoveryServicesAsrRecoveryPlan -Name $RecoveryServicesAsrPolicyName -PrimaryFabric $PrimaryLocationFabric -RecoveryFabric $RecoveryLocationFabric -ReplicationProtectedItem $RecoveryServicesAsrReplicationProtectedItem
#endregion

#endregion

#endregion

#region Azure Site Recovery : Lab 3

#region Azure Site Recovery : Lab 3 : Exercise 1

#region Azure Site Recovery : Lab 3 : Exercise 1 : Task 1
$RecoveryServicesAsrReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer
#endregion

#region Azure Site Recovery : Lab 3 : Exercise 1 : Task 2

#region Do a test failover
$TestFailOverVirtualNetworkAddressSpace = "10.3.0.0/16"
$TestFailOverSubnetIPRange = "10.3.0.0/24" # Format 10.0.0.0/20
#Create a separate network for test failover (not connected to my DR network)
$PrimaryLocationVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $PrimaryLocationResourceGroupName
$TFOVirtualNetworkName = "{0}-a2aTFOvnet" -f $PrimaryLocationVirtualNetwork.Name 
$TFOVirtualNetwork = New-AzVirtualNetwork -Name $TFOVirtualNetworkName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -AddressPrefix $TestFailOverVirtualNetworkAddressSpace
$null = Add-AzVirtualNetworkSubnetConfig -Name "default" -VirtualNetwork $TFOVirtualNetwork -AddressPrefix $TestFailOverSubnetIPRange | Set-AzVirtualNetwork
$RecoveryServicesAsrRecoveryPlan = Get-AzRecoveryServicesAsrRecoveryPlan -Name $RecoveryServicesAsrPolicyName

#region Do a test failover.
Write-Host -Object "Doing a test failover ..."
$TFOJob = Start-AzRecoveryServicesAsrTestFailoverJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan -Direction PrimaryToRecovery -AzureVMNetworkId $TFOVirtualNetwork.Id 

Write-Host -Object "Waiting the test failover completes ..." 
while (($TFOJob.State -eq "InProgress") -or ($TFOJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TFOJob = Get-AzRecoveryServicesAsrJob -Job $TFOJob
}
Write-Host -Object "Test failover status: $($TFOJob.State) ..."
#endregion

#endregion
#endregion

#region Azure Site Recovery : Lab 3 : Exercise 1 : Task 3
#region Starting the cleanup test failover operation
Write-Host -Object "Starting the cleanup test failover operation ..."
$Job_TFOCleanup = Start-AzRecoveryServicesAsrTestFailoverCleanupJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan
Write-Host -Object "Waiting cleanup test failover operation completes ..." 
while (($Job_TFOCleanup.State -eq "InProgress") -or ($TFOJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $Job_TFOCleanup = Get-AzRecoveryServicesAsrJob -Job $Job_TFOCleanup 
}
Write-Host -Object "Cleanup test failover operation status: $($Job_TFOCleanup.State) ..."
$null = $TFOVirtualNetwork | Remove-AzVirtualNetwork -AsJob -Force
#endregion
#endregion

#endregion

#region Azure Site Recovery : Lab 3 : Exercise 2

#region Azure Site Recovery : Lab 3 : Exercise 2 : Task 1
Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer | Select-Object -Property FriendlyName, ProtectionState
#endregion

#region Azure Site Recovery : Lab 3 : Exercise 2 : Task 2
#region Fail over to Azure
$VM = Get-AzVM -ResourceGroupName $PrimaryLocationResourceGroupName
$Jobs = $VM | Stop-AzVM -Force -AsJob
$null = $Jobs | Wait-Job
#Start the fail over job
$Job_Failover = Start-AzRecoveryServicesAsrUnplannedFailoverJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan -Direction PrimaryToRecovery
Write-Host -Object "Waiting the Failover to Azure to the latest recovery point completes ..." 
while (($Job_Failover.State -eq "InProgress") -or ($JobFailover.State -eq "NotStarted")) {
    $Job_Failover = Get-AzRecoveryServicesAsrJob -Job $Job_Failover;
    Start-Sleep -Seconds 30
} 
Write-Host -Object "Failover to Azure status: $($Job_Failover.State) ..."

#When the failover job is successful, you can commit the failover operation.
Write-Host -Object "Committing the failover operation ..." 
$CommitFailoverJob = Start-AzRecoveryServicesAsrCommitFailoverJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan

Write-Host -Object "Waiting the Failover commit completes ..." 
while (($CommitFailoverJob.State -eq "InProgress") -or ($CommitFailoverJob.State -eq "NotStarted")) {
    $CommitFailoverJob = Get-AzRecoveryServicesAsrJob -Job $CommitFailoverJob;
    Start-Sleep -Seconds 30
}

Write-Host -Object "Failover commit status: $($CommitFailoverJob.State) ..."

#endregion
#endregion

#region Azure Site Recovery : Lab 3 : Exercise 2 : Task 3
#region Reprotect
Write-Host -Object "Reprotecting ..." 
$RecoveryServicesAsrReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer
#Use the recovery protection container, new cache storage account in recovery location and the source region VM resource group
$PrimaryLocationResourceGroup = Get-AzResourceGroup -Name $PrimaryLocationResourceGroupName
$ReprotectJobs = foreach ($CurrentRecoveryServicesAsrReplicationProtectedItem in $RecoveryServicesAsrReplicationProtectedItem) {
    Update-AzRecoveryServicesAsrProtectionDirection -ReplicationProtectedItem $CurrentRecoveryServicesAsrReplicationProtectedItem -AzureToAzure -ProtectionContainerMapping $RecoveryToPrimaryPCMapping -LogStorageAccountId $RecoveryLocationCacheStorageAccount.Id -RecoveryResourceGroupID $PrimaryLocationResourceGroup.ResourceId
}

Write-Host -Object "Waiting the reprotection completes ..." 
while (($ReprotectJobs.State -eq "InProgress") -or ($ReprotectJobs.State -eq "NotStarted")) {
    $ReprotectJobs = foreach ($CurrentReprotectJob in $ReprotectJobs) {
        Get-AzRecoveryServicesAsrJob -Job $CurrentReprotectJob[0]
    }
    Start-Sleep -Seconds 30
}

Write-Host -Object "Reprotection status: $($ReprotectJobs | Select-Object -Property TargetObjectName, State | Out-String)"
#endregion
#endregion

#endregion

#region Azure Site Recovery : Lab 3 : Exercise 3

#region Azure Site Recovery : Lab 3 : Exercise 3 : Task 1
#region Failback to the primary region
$VM = Get-AzVM -ResourceGroupName $RecoveryLocationResourceGroupName
$Jobs = $VM | Stop-AzVM -Force -AsJob
$null = $Jobs | Wait-Job
#Start the fail over job
$Job_Failover = Start-AzRecoveryServicesAsrUnplannedFailoverJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan -Direction RecoveryToPrimary
Write-Host -Object "Waiting the Failover to Azure to the latest recovery point completes ..." 
while (($Job_Failover.State -eq "InProgress") -or ($JobFailover.State -eq "NotStarted")) {
    $Job_Failover = Get-AzRecoveryServicesAsrJob -Job $Job_Failover;
    Start-Sleep -Seconds 30
} 
Write-Host -Object "Failover to Azure status: $($Job_Failover.State) ..."

#When the failover job is successful, you can commit the failover operation.
Write-Host -Object "Committing the failover operation ..." 
$CommitFailoverJob = Start-AzRecoveryServicesAsrCommitFailoverJob -RecoveryPlan $RecoveryServicesAsrRecoveryPlan

Write-Host -Object "Waiting the Failover commit completes ..." 
while (($CommitFailoverJob.State -eq "InProgress") -or ($CommitFailoverJob.State -eq "NotStarted")) {
    $CommitFailoverJob = Get-AzRecoveryServicesAsrJob -Job $CommitFailoverJob;
    Start-Sleep -Seconds 30
}

Write-Host -Object "Failover commit status: $($CommitFailoverJob.State) ..."

#endregion
#endregion

#region Azure Site Recovery : Lab 3 : Exercise 3 : Task 2
#region Reprotect
Write-Host -Object "Reprotecting ..." 
$RecoveryServicesAsrReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $RecoveryProtectionContainer
#Use the recovery protection container, new cache storage account in recovery location and the source region VM resource group
$RecoveryLocationResourceGroup = Get-AzResourceGroup -Name $RecoveryLocationResourceGroupName
$ReprotectJobs = foreach ($CurrentRecoveryServicesAsrReplicationProtectedItem in $RecoveryServicesAsrReplicationProtectedItem) {
    Update-AzRecoveryServicesAsrProtectionDirection -ReplicationProtectedItem $CurrentRecoveryServicesAsrReplicationProtectedItem -AzureToAzure -ProtectionContainerMapping $PrimaryToRecoveryPCMapping -LogStorageAccountId $PrimaryLocationCacheStorageAccount.Id -RecoveryResourceGroupID $RecoveryLocationResourceGroup.ResourceId
}

Write-Host -Object "Waiting the reprotection completes ..." 
while (($ReprotectJobs.State -eq "InProgress") -or ($ReprotectJobs.State -eq "NotStarted")) {
    $ReprotectJobs = foreach ($CurrentReprotectJob in $ReprotectJobs) {
        Get-AzRecoveryServicesAsrJob -Job $CurrentReprotectJob[0]
    }
    Start-Sleep -Seconds 30
}

Write-Host -Object "Reprotection status: $($ReprotectJobs | Select-Object -Property TargetObjectName, State | Out-String)"
#endregion
#endregion

#endregion

#endregion

#region Azure Site Recovery : Lab 4

#region Azure Site Recovery : Lab 4 : Exercise 1

#region Azure Site Recovery : Lab 4 : Exercise 1 : Task 1
#Nothing to script
#endregion

#region Azure Site Recovery : Lab 4 : Exercise 1 : Task 2
$null = Set-AzRecoveryServicesAsrVaultContext -Vault $RecoveryServicesVault
 
#Set Site Recovery Service Alert Notifications
Set-AzRecoveryServicesAsrAlertSetting -CustomEmailAddress "lavanack@microsoft.com" -EnableEmailSubscriptionOwner

#endregion

#endregion

#region Azure Site Recovery : Lab 4 : Exercise 2

#region Azure Site Recovery : Lab 4 : Exercise 2 : Task 1
$DiagnosticSettingCategory = Get-AzDiagnosticSettingCategory -ResourceId $RecoveryServicesVault.ID | Where-Object -FilterScript { $_.Name -match "^AzureSiteRecovery"}
$DiagnosticSetting = Set-AzDiagnosticSetting -Name $RecoveryServicesVault.Name -ResourceId $RecoveryServicesVault.ID -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category $DiagnosticSettingCategory.Name
#endregion

#region Azure Site Recovery : Lab 4 : Exercise 2 : Task 2
$KQLQueries = @(
@"
AzureDiagnostics  
| where replicationProviderName_s == "A2A"   
| where isnotempty(name_s) and isnotnull(name_s)  
| summarize hint.strategy=partitioned arg_max(TimeGenerated, *) by name_s  
| project name_s , replicationHealth_s  
| summarize count() by replicationHealth_s  
| render piechart
"@
@"
AzureDiagnostics 
| where replicationProviderName_s == "A2A"   
| where isnotempty(name_s) and isnotnull(name_s)  
| extend RPO = case(rpoInSeconds_d <= 900, "<15Min",   
rpoInSeconds_d <= 1800, "15-30Min", ">30Min")  
| summarize hint.strategy=partitioned arg_max(TimeGenerated, *) by name_s  
| project name_s , RPO  
| summarize Count = count() by RPO  
| render barchart"@
"@
@"
AzureDiagnostics  
| where replicationProviderName_s == "A2A"   
| where isnotempty(name_s) and isnotnull(name_s)  
| where isnotempty(failoverHealth_s) and isnotnull(failoverHealth_s)  
| summarize hint.strategy=partitioned arg_max(TimeGenerated, *) by name_s  
| project name_s , Resource, failoverHealth_s  
| summarize count() by failoverHealth_s  
| render piechart
"@
@"
AzureDiagnostics   
| where Category in ("AzureSiteRecoveryProtectedDiskDataChurn", "AzureSiteRecoveryReplicationDataUploadRate")   
| extend CategoryS = case(Category contains "Churn", "DataChurn",   
Category contains "Upload", "UploadRate", "none")  
| extend InstanceWithType=strcat(CategoryS, "_", InstanceName_s)   
| where TimeGenerated > ago(24h)   
| where InstanceName_s startswith "ContosoVM123"   
| project TimeGenerated , InstanceWithType , Churn_MBps = todouble(Value_s)/1048576   
| render timechart
"@
)
foreach ($CurrentKQLQuery in $KQLQueries)
{
    $OperationalInsightsQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkSpace.CustomerId -Query $CurrentKQLQuery
    $OperationalInsightsQuery.Results
}
#endregion

#endregion

#endregion

#region Azure Site Recovery : Lab 5

#region Azure Site Recovery : Lab 5 : Exercise 1

#region Azure Site Recovery : Lab 5 : Exercise 1 : Task 1
#region Azure Policy Management
$PolicyDefinition = Get-AzPolicyDefinition | Where-Object -FilterScript { $_.Properties.DisplayName -eq "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery" }
$PolicyAssignment = New-AzPolicyAssignment -Name "$($PrimaryLocationResourceGroupName)-enableAzureVMReplicationViaASR" -DisplayName 'Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery' -Scope $PrimaryLocationResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $RecoveryLocation -SourceRegion $PrimaryLocation -TargetRegion $RecoveryLocation -targetResourceGroupId $RecoveryLocationResourceGroup.ResourceId -vaultResourceGroupId $RecoveryLocationResourceGroup.ResourceId -vaultId $RecoveryServicesVault.ID -recoveryNetworkId $RecoveryLocationVirtualNetwork.Name -cacheStorageAccountId $PrimaryLocationCacheStorageAccount.StorageAccountName -tagValue @() -targetZone ""

# Grant defined roles to the primary and recovery resource groups with PowerShell
$roleDefinitionIds = $PolicyDefinition | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.Properties.policyRule.then.details.roleDefinitionIds } } | Select-Object -ExpandProperty roleDefinitionIds #-Unique
Start-Sleep -Seconds 30
if ($roleDefinitionIds.Count -gt 0) {
    $roleDefinitionIds | ForEach-Object -Process {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        if (-not(Get-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.Identity.PrincipalId -RoleDefinitionId $roleDefId)) {
            New-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
            New-AzRoleAssignment -Scope $RecoveryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
        }
    }
}

Write-Host -Object "Creating remediation for '$($PolicyDefinition.Properties.DisplayName)' Policy ..."
$PolicyRemediation = Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.PolicyAssignmentId -ResourceGroupName $PrimaryLocationResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
$PolicyRemediation

Write-Host -Object "Starting Compliance Scan for '$PrimaryLocationResourceGroupName' Resource Group ..."
$PolicyComplianceScan = Start-AzPolicyComplianceScan -ResourceGroupName $PrimaryLocationResourceGroup
$PolicyComplianceScan


# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $PrimaryLocationResourceGroup -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $PrimaryLocationResourceGroup | Select-Object -ExpandProperty PolicyAssignments 
#endregion 
#endregion

#endregion

#endregion

#endregion

