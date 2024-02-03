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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.DataProtection, Az.Network, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage

#From https://learn.microsoft.com/en-us/azure/backup/backup-managed-disks-ps
#From https://learn.microsoft.com/en-us/azure/backup/restore-managed-disks-ps


[CmdletBinding()]
param
(
)


#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    #Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}
#endregion

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

$AzureVMNameMaxLength = 15
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$Location = "eastus"
$VMSize = "Standard_D4s_v5"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$BackupVaultPrefix = "bvault"
$ResourceGroupPrefix = "rg"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "vnets"
$Project = "bkp"
$Role = "disk"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
} While (-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location))
           
$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$VirtualNetworkAddressSpace = "10.0.0.0/16" # Format 10.0.0.0/16
$SubnetIPRange = "10.0.0.0/24" # Format 10.0.1.0/24                         

$FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()
#endregion

#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force
}

$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org").Content

#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsServer"
$ImageOffer = "WindowsServer"
$ImageSku = "2022-datacenter-g2"
$PublicIPName = "pip-$VMName" 
$NICName = "nic-$VMName"
$OSDiskName = '{0}_OSDisk' -f $VMName
$DataDisk1Name = '{0}_DataDisk1' -f $VMName
$DataDisk2Name = '{0}_DataDisk2' -f $VMName
$OSDiskSize = "127"
$DiskType = "Premium_LRS"

Write-Verbose "`$VMName: $VMName"
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$PublicIPName: $PublicIPName"
Write-Verbose "`$NICName: $NICName"
Write-Verbose "`$OSDiskName: $OSDiskName"
Write-Verbose "`$FQDN: $FQDN"
#endregion

#region Azure VM Setup
Write-Host -Object "The '$VMName' Azure VM is creating ..."
if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($LocationShortName)) {
    Write-Error "No location short name found for '$Location'" -ErrorAction Stop
}
elseif ($null -eq (Get-AZVMSize -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

#Create Azure Resource Group
# Create Resource Groups
#The resource group for the virtual machine(s)
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#Create Azure Network Security Group
#RDP only for my public IP address
$SecurityRules = @(
    #region Inbound
    #RDP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $RDPPort
    #HTTP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
    #HTTPS only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPSRule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 302 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
    #endregion
)

$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

#Steps 4 + 5: Create Azure Virtual network (and related NSG) using the virtual network subnet configuration
#region Location
$VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $NetworkSecurityGroup.Id
$VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork
#endregion

#Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AlLocationMethod Static -DomainNameLabel $VMName.ToLower()
#Setting up the DNS Name
#$PublicIP.DnsSettings.Fqdn = $FQDN

#Create Network Interface Card 
$NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id

<# Optional : Get Virtual Machine publisher, Image Offer, Sku and Image
$ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
$ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
$ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
$image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
#>

# Create a virtual machine configuration file (As a Spot Intance)
$VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1 -IdentityType SystemAssigned -SecurityType Standard

$null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set VM operating system parameters
$null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent

# Set boot diagnostic storage account
# Set boot diagnostic to managed storage account
$null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

# The uncommented lines below replace Set virtual machine source image
$null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

# Set OsDisk configuration
$null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $DiskType -CreateOption fromImage

#region Adding Data Disk(s)
$VMDataDisk01Config = New-AzDiskConfig -SkuName $DiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDisk1Name -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk1Name -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0

$VMDataDisk02Config = New-AzDiskConfig -SkuName $DiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk02 = New-AzDisk -DiskName $DataDisk2Name -Disk $VMDataDisk02Config -ResourceGroupName $ResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk2Name -CreateOption Attach -ManagedDiskId $VMDataDisk02.Id -Lun 1
#endregion

#Create Azure Virtual Machine
$null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -DisableBginfoExtension

$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName

#region JIT Access Management
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
Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
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
Write-Host "Requesting Temporary Acces via Just in Time for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
$null = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
#endregion

#endregion

#region Enabling auto-shutdown at 11:00 PM in the user time zome
$SubscriptionId = ($VM.Id).Split('/')[2]
$ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
$Properties = @{}
$Properties.Add('status', 'Enabled')
$Properties.Add('taskType', 'ComputeVmShutdownTask')
$Properties.Add('dailyRecurrence', @{'time' = "2300" })
$Properties.Add('timeZoneId', (Get-TimeZone).Id)
$Properties.Add('targetResourceId', $VM.Id)
$null = New-AzResource -Location $Location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
#endregion

#Start Azure Virtual Machine
Write-Host -Object "Starting the '$VMName' VM ..."
$null = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

# Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
$Credential = $null
Write-Warning -Message "Credentials cleared from memory but available in the Windows Credential Manager for automatic logon via a RDP client ..."
Write-Host -Object "The '$VMName' Azure VM is created and started ..."

#Start-Sleep -Seconds 15

#Start RDP Session
#mstsc /v $FQDN
#endregion

#region Azure Managed Disk(s) Backup Setup
$SnapshotResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}-snap" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$BackupVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $BackupVaultPrefix, $Project, $Role, $LocationShortName, $Instance
$SnapshotResourceGroupName = $SnapshotResourceGroupName.ToLower()
$BackupVaultName = $BackupVaultName.ToLower()

$SnapshotResourceGroup = Get-AzResourceGroup -Name $SnapshotResourceGroupName -ErrorAction Ignore 
if ($SnapshotResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $SnapshotResourceGroup | Remove-AzResourceGroup -Force
}

$SnapshotResourceGroup = New-AzResourceGroup -Name $SnapshotResourceGroupName -Location $Location -Force

$OsDisk = $VM.StorageProfile.OsDisk | Get-AzDisk
$DataDisks = $VM.StorageProfile.DataDisks | Get-AzDisk
$Disks = @($OsDisk) + $DataDisks

#region Create a Backup vault
#Create a new Backup vault in the recovery region
Write-Host -Object "The '$BackupVaultName' Backup Vault is creating ..."
$storageSetting = New-AzDataProtectionBackupVaultStorageSettingObject -Type LocallyRedundant -DataStoreType VaultStore
$BackupVault = New-AzDataProtectionBackupVault -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName -Location $Location -StorageSetting $storageSetting -IdentityType SystemAssigned -SoftDeleteState Off
Write-Host -Object "The '$BackupVaultName' Backup Vault is created ..."
#endregion

#region Create a Backup policy
$BackupPolicyName = "DiskBkpPol{0}" -f $Instance
$DataProtectionPolicyTemplate = Get-AzDataProtectionPolicyTemplate -DatasourceType AzureDisk
$DataProtectionBackupPolicy = New-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -Name $BackupPolicyName -Policy $DataProtectionPolicyTemplate
#endregion

#region Assign RBAC permissions
#region Assign the Disk Backup Reader role to Backup vault’s managed identity on the Source disk(s) that needs to be backed up.
#Get the name of the custom role
$DiskBackupReaderRole = Get-AzRoleDefinition "Disk Backup Reader"
foreach ($Disk in $Disks) {
    $Scope = $Disk.Id
    if (-not(Get-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskBackupReaderRole.Name -Scope $Scope)) {
        $null = New-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskBackupReaderRole.Name -Scope $Scope
    }
}
#endregion

#region Assign the Disk Snapshot Contributor role to the Backup vault’s managed identity on the Resource group, where backups are created and managed by the Azure Backup service
#Get the name of the custom role
$DiskSnapshotContributor = Get-AzRoleDefinition "Disk Snapshot Contributor"
$Scopes = $SnapshotResourceGroup.ResourceId, $ResourceGroup.ResourceId
foreach ($CurrentScope in $Scopes) {
    if (-not(Get-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskSnapshotContributor.Name -Scope $CurrentScope)) {
        $null = New-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskSnapshotContributor.Name -Scope $CurrentScope
    }
}
#endregion
#endregion

#region Prepare the request(s)
$BackupInstances = foreach ($Disk in $Disks) {
    $DataProtectionBackupInstance = Initialize-AzDataProtectionBackupInstance -DatasourceType AzureDisk -DatasourceLocation $BackupVault.Location -PolicyId $DataProtectionBackupPolicy.Id -DatasourceId $Disk.Id -SnapshotResourceGroupId $SnapshotResourceGroup.ResourceId #-FriendlyName $Disk.Name
    New-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupInstance $DataProtectionBackupInstance
}
#endregion

#region Run an on-demand backup
Do {
    $AllInstances = Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Where-Object -FilterScript { $_.Name -in $BackupInstances.BackupInstanceName }
    Write-Host -Object "Waiting The Protection(s) Be Configured. Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
} While (($AllInstances).Property.CurrentProtectionState -ne "ProtectionConfigured")

$BackupJobs = foreach ($CurrentInstance in $AllInstances) {
    Backup-AzDataProtectionBackupInstanceAdhoc -BackupInstanceName $CurrentInstance.Name -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupRuleOptionRuleName $DataProtectionBackupPolicy.Property.PolicyRule[0].Name
}

Do {
    Write-Host -Object "Waiting The Backup Job(s) Be Completed. Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
    $DataProtectionJob = Get-AzDataProtectionJob -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName | Where-Object -FilterScript { $_.Id -in $BackupJobs.JobId }
} while ($DataProtectionJob.Status -ne "Completed")
#endregion

#endregion

#region Azure Managed Disk(s) Restore Setup
#region Restoration Resource Group
$RestoreResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}-restore" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

$ResourceGroupName = $ResourceGroupName.ToLower()
$AKSClusterName = $AKSClusterName.ToLower()

$RestoreResourceGroup = Get-AzResourceGroup -Name $RestoreResourceGroupName -ErrorAction Ignore 
if ($RestoreResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $RestoreResourceGroup | Remove-AzResourceGroup -Force
}
$RestoreResourceGroup = New-AzResourceGroup -Name $RestoreResourceGroupName -Location $Location -Force
#endregion

#region Assign RBAC permissions
#region Assign the Disk Restore Operator role to the Backup Vault’s managed identity on the Resource group where the disk will be restored by the Azure Backup service
#Get the name of the custom role
$DiskRestoreOperator = Get-AzRoleDefinition "Disk Restore Operator"
$Scopes = $RestoreResourceGroup.ResourceId
foreach ($CurrentScope in $Scopes) {
    if (-not(Get-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskRestoreOperator.Name -Scope $CurrentScope)) {
        $null = New-AzRoleAssignment -ObjectId $BackupVault.IdentityPrincipalId -RoleDefinitionName $DiskRestoreOperator.Name -Scope $CurrentScope
    }
}
#endregion
#endregion


$AllInstances = Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Where-Object -FilterScript { $_.Name -in $BackupInstances.BackupInstanceName }
$RestoreJobs = foreach ($CurrentInstance in $AllInstances) {
    Write-Host -Object "Processing '$($CurrentInstance.Property.FriendlyName)'"
    #region Fetch the relevant recovery point
    $RecoveryPoints = Get-AzDataProtectionRecoveryPoint -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -BackupInstanceName $CurrentInstance.BackupInstanceName
    $LatestRecoveryPointTime = $RecoveryPoints.Property | Sort-Object -Property RecoveryPointTime -Descending | Select-Object -First 1 
    $LatestRecoveryPoint = $RecoveryPoints | Where-Object -FilterScript { $_.Property.RecoveryPointTime -eq $LatestRecoveryPointTime.RecoveryPointTime }
    Write-Host -Object "Latest Recovery Point for '$($CurrentInstance.Property.FriendlyName)': $($LatestRecoveryPoint.Property.RecoveryPointTime)"
    #endregion

    #region Preparing the restore request
    $targetDiskId = "$($RestoreResourceGroup.ResourceId)/providers/Microsoft.Compute/disks/$($CurrentInstance.Property.FriendlyName)"
    $restorerequest = Initialize-AzDataProtectionRestoreRequest -DatasourceType AzureDisk -SourceDataStore OperationalStore -RestoreLocation $BackupVault.Location  -RestoreType AlternateLocation -TargetResourceId $targetDiskId -RecoveryPoint $LatestRecoveryPoint.Name
    #endregion

    #region Trigger the restore
    Start-AzDataProtectionBackupInstanceRestore -BackupInstanceName $CurrentInstance.BackupInstanceName -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name -Parameter $restorerequest
    #endregion
}

#region Tracking job
Do {
    Write-Host -Object "Waiting The Restore Job(s) Be Completed. Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30
    $Job = Get-AzDataProtectionJob -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $BackupVaultName | Where-Object { $_.Id -in $RestoreJobs.JobID }
} while ($Job.Status -ne "Completed")
$Job | Format-Table -Property DataSourceName, Status

#endregion

#endregion

<#
#region Cleanup
Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupInstance
Get-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $BackupVault.Name | Remove-AzDataProtectionBackupPolicy
Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob
#endregion
#>