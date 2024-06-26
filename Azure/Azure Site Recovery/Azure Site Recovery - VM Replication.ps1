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
#requires -Version 5 -Modules Az.Accounts, Az.Compute,Az.Network, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage

#From https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-powershell

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
$PrimaryLocation = "eastus"
$RecoveryLocation = "eastus2"
$VMSize = "Standard_D4s_v5"
$PrimaryLocationShortName = $shortNameHT[$PrimaryLocation].shortName
$RecoveryLocationShortName = $shortNameHT[$RecoveryLocation].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$RecoveryServicesAsrFabricPrefix = "rsaf"
$RecoveryServicesAsrProtectionContainerPrefix = "rsapc"
$RecoverySiteVaultPrefix = "rsv"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$Project = "asr"
$Role = "vm"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $PrimaryLocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    #Create Cache storage account for replication logs in the primary region
    $PrimaryLocationCacheStorageAccountName = "{0}{1}{2}cache{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
    #Create Cache storage account for replication logs in the recovery region
    $RecoveryLocationCacheStorageAccountName = "{0}{1}{2}cache{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
    $RecoveryLocationStorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $PrimaryLocation)) -or (-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $RecoveryLocation)) -or (-not(Get-AzStorageAccountNameAvailability -Name $PrimaryLocationCacheStorageAccountName).NameAvailable) -or (-not(Get-AzStorageAccountNameAvailability -Name $RecoveryLocationCacheStorageAccountName).NameAvailable) -or (-not(Get-AzStorageAccountNameAvailability -Name $RecoveryLocationStorageAccountName).NameAvailable))

                         
$PrimaryLocationNetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$RecoveryLocationNetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
$PrimaryLocationVirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$RecoveryLocationVirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
$PrimaryLocationSubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$RecoveryLocationSubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
$PrimaryLocationResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$RecoveryLocationResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
$RecoveryServicesVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoverySiteVaultPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance
$PrimaryLocationRecoveryServicesAsrFabricName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrFabricPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance               
$RecoveryLocationRecoveryServicesAsrFabricName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrFabricPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance               
$PrimaryLocationRecoveryServicesAsrProtectionContainerName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrProtectionContainerPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance
$RecoveryLocationRecoveryServicesAsrProtectionContainerName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoveryServicesAsrProtectionContainerPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance

$VMName = $VMName.ToLower()
$PrimaryLocationNetworkSecurityGroupName = $PrimaryLocationNetworkSecurityGroupName.ToLower()
$RecoveryLocationNetworkSecurityGroupName = $RecoveryLocationNetworkSecurityGroupName.ToLower()
$PrimaryLocationVirtualNetworkName = $PrimaryLocationVirtualNetworkName.ToLower()
$RecoveryLocationVirtualNetworkName = $RecoveryLocationVirtualNetworkName.ToLower()
$PrimaryLocationSubnetName = $PrimaryLocationSubnetName.ToLower()
$RecoveryLocationSubnetName = $RecoveryLocationSubnetName.ToLower()
$PrimaryLocationResourceGroupName = $PrimaryLocationResourceGroupName.ToLower()
$RecoveryLocationResourceGroupName = $RecoveryLocationResourceGroupName.ToLower()
$PrimaryLocationVirtualNetworkAddressSpace = "10.0.0.0/16" # Format 10.0.0.0/16
$RecoveryLocationVirtualNetworkAddressSpace = "10.0.0.0/16" # Format 10.0.0.0/16
$SubnetIPRange = "10.0.0.0/24" # Format 10.0.1.0/24                         
$TestFailOverVirtualNetworkAddressSpace = "10.3.0.0/16" # Format 10.0.0.0/16
$TestFailOverSubnetIPRange = "10.3.0.0/20" # Format 10.0.0.0/20                         

$FQDN = "$VMName.$PrimaryLocation.cloudapp.azure.com".ToLower()

#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$Jobs = @()
$PrimaryLocationResourceGroup = Get-AzResourceGroup -Name $PrimaryLocationResourceGroupName -ErrorAction Ignore 
if ($PrimaryLocationResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $Jobs += $PrimaryLocationResourceGroup | Remove-AzResourceGroup -Force -AsJob
}

$RecoveryLocationResourceGroup = Get-AzResourceGroup -Name $RecoveryLocationResourceGroupName -ErrorAction Ignore 
if ($RecoveryLocationResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $Jobs += $RecoveryLocationResourceGroup | Remove-AzResourceGroup -Force -AsJob
}

$Jobs | Wait-Job | Out-Null
$Jobs | Remove-Job -Force

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
$StorageAccountSkuName = "Standard_LRS"
$DiskType = "Premium_LRS"

Write-Verbose "`$VMName: $VMName"
Write-Verbose "`$PrimaryLocationNetworkSecurityGroupName: $PrimaryLocationNetworkSecurityGroupName"         
Write-Verbose "`$RecoveryLocationNetworkSecurityGroupName: $RecoveryLocationNetworkSecurityGroupName"         
Write-Verbose "`$PrimaryLocationVirtualNetworkName: $PrimaryLocationVirtualNetworkName"         
Write-Verbose "`$RecoveryLocationVirtualNetworkName: $RecoveryLocationVirtualNetworkName"         
Write-Verbose "`$PrimaryLocationSubnetName: $PrimaryLocationSubnetName"       
Write-Verbose "`$RecoveryLocationSubnetName: $RecoveryLocationSubnetName"       
Write-Verbose "`$PrimaryLocationResourceGroupName: $PrimaryLocationResourceGroupName"
Write-Verbose "`$RecoveryLocationResourceGroupName: $RecoveryLocationResourceGroupName"
Write-Verbose "`$PublicIPName: $PublicIPName"
Write-Verbose "`$NICName: $NICName"
Write-Verbose "`$OSDiskName: $OSDiskName"
Write-Verbose "`$FQDN: $FQDN"
#endregion
#endregion

#region Azure VM Setup
Write-Host -Object "The '$VMName' Azure VM is creating ..."
if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($RecoveryLocationShortName)) {
    Write-Error "No location short name found for '$RecoveryLocation'" -ErrorAction Stop
}
elseif (-not($PrimaryLocationShortName)) {
    Write-Error "No location short name found for '$PrimaryLocation'" -ErrorAction Stop
}
elseif ($null -eq (Get-AZVMSize -Location $PrimaryLocation | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$PrimaryLocation' location ..." -ErrorAction Stop
}
elseif ($null -eq (Get-AZVMSize -Location $RecoveryLocation | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$RecoveryLocation' location ..." -ErrorAction Stop
}

#Create Azure Resource Group
# Create Resource Groups
#The resource group for the virtual machine(s)
$PrimaryLocationResourceGroup = New-AzResourceGroup -Name $PrimaryLocationResourceGroupName -Location $PrimaryLocation -Force
#The resource group that the virtual machine(s) must be created in when failed over.
$RecoveryLocationResourceGroup = New-AzResourceGroup -Name $RecoveryLocationResourceGroupName -Location $RecoveryLocation -Force

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

$PrimaryLocationNetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -Name $PrimaryLocationNetworkSecurityGroupName -SecurityRules $SecurityRules -Force
$RecoveryLocationNetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -Name $RecoveryLocationNetworkSecurityGroupName -SecurityRules $SecurityRules -Force

#Steps 4 + 5: Create Azure Virtual network (and related NSG) using the virtual network subnet configuration
#region Primary Location
$PrimaryLocationVirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $PrimaryLocationResourceGroupName -Name $PrimaryLocationVirtualNetworkName  -AddressPrefix $PrimaryLocationVirtualNetworkAddressSpace -Location $PrimaryLocation
Add-AzVirtualNetworkSubnetConfig -Name $PrimaryLocationSubnetName -VirtualNetwork $PrimaryLocationVirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $PrimaryLocationNetworkSecurityGroup.Id
$PrimaryLocationVirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $PrimaryLocationVirtualNetwork
$PrimaryLocationSubnet = Get-AzVirtualNetworkSubnetConfig -Name $PrimaryLocationSubnetName -VirtualNetwork $PrimaryLocationVirtualNetwork
#endregion

#region Recovery Location
$RecoveryLocationVirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $RecoveryLocationResourceGroupName -Name $RecoveryLocationVirtualNetworkName  -AddressPrefix $RecoveryLocationVirtualNetworkAddressSpace -Location $RecoveryLocation
$null = Add-AzVirtualNetworkSubnetConfig -Name $RecoveryLocationSubnetName -VirtualNetwork $RecoveryLocationVirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $RecoveryLocationNetworkSecurityGroup.Id
$RecoveryLocationVirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $RecoveryLocationVirtualNetwork
#endregion

#Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -AlLocationMethod Static -DomainNameLabel $VMName.ToLower()
#Setting up the DNS Name
#$PublicIP.DnsSettings.Fqdn = $FQDN

#Create Network Interface Card 
$NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -SubnetId $PrimaryLocationSubnet.Id -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $PrimaryLocationNetworkSecurityGroup.Id

<# Optional : Get Virtual Machine publisher, Image Offer, Sku and Image
$ImagePublisherName = Get-AzVMImagePublisher -Location $PrimaryLocation | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
$ImageOffer = Get-AzVMImageOffer -Location $PrimaryLocation -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
$ImageSku = Get-AzVMImageSku -Location  $PrimaryLocation -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
$image = Get-AzVMImage -Location  $PrimaryLocation -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
#>

# Create a virtual machine configuration file (As a Spot Intance)
$VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1 -IdentityType SystemAssigned -SecurityType Standard

$null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set VM operating system parameters
$null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

# Set boot diagnostic storage account
# Set boot diagnostic to managed storage account
$null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

# The uncommented lines below replace Set virtual machine source image
$null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

# Set OsDisk configuration
$null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $DiskType -CreateOption fromImage

#region Adding Data Disk(s)
$VMDataDisk01Config = New-AzDiskConfig -SkuName $DiskType -Location $PrimaryLocation -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDisk1Name -Disk $VMDataDisk01Config -ResourceGroupName $PrimaryLocationResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk1Name -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0

$VMDataDisk02Config = New-AzDiskConfig -SkuName $DiskType -Location $PrimaryLocation -CreateOption Empty -DiskSizeGB 512
$VMDataDisk02 = New-AzDisk -DiskName $DataDisk2Name -Disk $VMDataDisk02Config -ResourceGroupName $PrimaryLocationResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk2Name -CreateOption Attach -ManagedDiskId $VMDataDisk02.Id -Lun 1
#endregion

#Create Azure Virtual Machine
$null = New-AzVM -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -VM $VMConfig -DisableBginfoExtension

$VM = Get-AzVM -ResourceGroup $PrimaryLocationResourceGroupName -Name $VMName

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
$ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
$UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
$UpdatedJITPolicy.Add($NewJitPolicy)
	
# Enable Access to the VM including management Port, and Time Range in Hours
Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
$null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -Name $JitPolicyName -Kind "Basic"
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
$ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$PrimaryLocationResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
$Properties = @{}
$Properties.Add('status', 'Enabled')
$Properties.Add('taskType', 'ComputeVmShutdownTask')
$Properties.Add('dailyRecurrence', @{'time' = "2300" })
$Properties.Add('timeZoneId', (Get-TimeZone).Id)
$Properties.Add('targetResourceId', $VM.Id)
$null = New-AzResource -Location $PrimaryLocation -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
#endregion

#Start Azure Virtual Machine
Write-Host -Object "Starting the '$VMName' VM ..."
$null = Start-AzVM -Name $VMName -ResourceGroupName $PrimaryLocationResourceGroupName

# Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
$Credential = $null
Write-Warning -Message "Credentials cleared from memory but available in the Windows Credential Manager for automatic logon via a RDP client ..."
Write-Host -Object "The '$VMName' Azure VM is created and started ..."

#Start-Sleep -Seconds 15

#Start RDP Session
#mstsc /v $FQDN
#endregion

#region Create a Recovery Services vault
#Create a new Recovery services vault in the recovery region
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is creating ..."
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $RecoveryLocation -ResourceGroupName $RecoveryLocationResourceGroupName
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is created ..."
#endregion
 
#region Setting the vault context.
Write-Host -Object "Setting the vault context ..."
$null = Set-AzRecoveryServicesAsrVaultContext -Vault $RecoveryServicesVault
#endregion

#region Prepare the vault to start replicating Azure virtual machines
Write-Host -Object "Preparing the '$RecoveryServicesVaultName' Recovery Services Vault to start replicating Azure virtual machines ..."

#region Create a Site Recovery fabric object to represent the primary (source) region
Write-Host -Object "Creating a Site Recovery fabric object to represent the primary (source) region ('$PrimaryLocation') ..."
#Create Primary ASR fabric
$TempASRJob = New-AzRecoveryServicesAsrFabric -Azure -Location $PrimaryLocation  -Name $PrimaryLocationRecoveryServicesAsrFabricName

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
$TempASRJob = New-AzRecoveryServicesAsrFabric -Azure -Location $RecoveryLocation  -Name $RecoveryLocationRecoveryServicesAsrFabricName

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
$TempASRJob = New-AzRecoveryServicesAsrPolicy -AzureToAzure -Name $RecoveryServicesAsrPolicyName -RecoveryPointRetentionInHours 24 -ApplicationConsistentSnapshotFrequencyInHours 4

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
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainerMapping -Name $PrimaryToRecoveryPCMappingName -Policy $ReplicationPolicy -PrimaryProtectionContainer $PrimaryProtectionContainer  -RecoveryProtectionContainer $RecoveryProtectionContainer 

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Protection container mapping creation status: $($TempASRJob.State) ..."

$PrimaryToRecoveryPCMapping = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $PrimaryProtectionContainer  -Name $PrimaryToRecoveryPCMappingName
#endregion

#region Create Protection container mapping (for fail back) between the Recovery and Primary Protection Containers with the Replication policy
Write-Host -Object "Creating Protection container mapping (for fail back) between the Recovery and Primary Protection Containers with the Replication policy..." 
$RecoveryToPrimaryPCMappingName = "{0} - A2ARecoveryToPrimary" -f $RecoveryServicesVaultName
$TempASRJob = New-AzRecoveryServicesAsrProtectionContainerMapping -Name $RecoveryToPrimaryPCMappingName -Policy $ReplicationPolicy -PrimaryProtectionContainer $RecoveryProtectionContainer   -RecoveryProtectionContainer $PrimaryProtectionContainer

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
$PrimaryLocationCacheStorageAccount = New-AzStorageAccount -Name $PrimaryLocationCacheStorageAccountName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -SkuName $StorageAccountSkuName -Kind Storage
#endregion

#region Create Cache storage account for replication logs in the recovery region
Write-Host -Object "Creating cache storage account for replication logs in the recovery region ('$RecoveryLocation') ..."
$RecoveryLocationCacheStorageAccount = New-AzStorageAccount -Name $RecoveryLocationCacheStorageAccountName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -SkuName $StorageAccountSkuName -Kind Storage
#endregion

<#
#region Create Target storage account in the recovery region. In this case a Standard Storage account for virtual machines not using managed disks
Write-Host -Object "Creating Target storage account in the recovery region ('$RecoveryLocation'). In this case a Standard Storage account..."
$RecoveryLocationStorageAccount = New-AzStorageAccount -Name $RecoveryLocationStorageAccountName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -SkuName $StorageAccountSkuName -Kind Storage
#endregion
#>
#endregion

#region Create network mappings
#region Create an ASR network mapping between the primary Azure virtual network and the recovery Azure virtual network
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

#region Replicate Azure virtual machine with managed disks.
Write-Host -Object "Replicating Azure virtual machine with managed disks ..."
#Specify replication properties for each disk of the VM that is to be replicated (create disk replication configuration)

#region OS Disk
$OSdiskId = $VM.StorageProfile.OsDisk.ManagedDisk.Id
$RecoveryOSDiskAccountType = $VM.StorageProfile.OsDisk.ManagedDisk.StorageAccountType
$RecoveryReplicaDiskAccountType = $VM.StorageProfile.OsDisk.ManagedDisk.StorageAccountType
$OSDiskReplicationConfig = New-AzRecoveryServicesAsrAzureToAzureDiskReplicationConfig -ManagedDisk -LogStorageAccountId $PrimaryLocationCacheStorageAccount.Id -DiskId $OSdiskId -RecoveryResourceGroupId  $RecoveryLocationResourceGroup.ResourceId -RecoveryReplicaDiskAccountType  $RecoveryReplicaDiskAccountType -RecoveryTargetDiskAccountType $RecoveryOSDiskAccountType
#endregion

#region Data Disk(s)
$DataDisksReplicationConfig = foreach ($VMDataManagedDisk in $VM.StorageProfile.DataDisks.ManagedDisk) {
    $RecoveryReplicaDiskAccountType = $VMDataManagedDisk.StorageAccountType
    $RecoveryTargetDiskAccountType = $VMDataManagedDisk.StorageAccountType
    New-AzRecoveryServicesAsrAzureToAzureDiskReplicationConfig -ManagedDisk -LogStorageAccountId $PrimaryLocationCacheStorageAccount.Id -DiskId $VMDataManagedDisk.Id -RecoveryResourceGroupId $RecoveryLocationResourceGroup.ResourceId -RecoveryReplicaDiskAccountType $RecoveryReplicaDiskAccountType -RecoveryTargetDiskAccountType $RecoveryTargetDiskAccountType
}
#endregion

#Create a list of disk replication configuration objects for the disks of the virtual machine that are to be replicated.
$DiskConfigs = @($OSDiskReplicationConfig) + $DataDisksReplicationConfig

#Start replication by creating replication protected item. Using a GUID for the name of the replication protected item to ensure uniqueness of name.
Write-Host "Starting replication by creating replication protected item ..."
$TempASRJob = New-AzRecoveryServicesAsrReplicationProtectedItem -AzureToAzure -AzureVmId $VM.Id -Name (New-Guid).Guid -ProtectionContainerMapping $PrimaryToRecoveryPCMapping -AzureToAzureDiskReplicationConfiguration $DiskConfigs -RecoveryResourceGroupId $RecoveryLocationResourceGroup.ResourceId

#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Replication protected item creation status: $($TempASRJob.State) ..."


#Monitor the replication state and replication health
Write-Host -Object "Waiting the replication state of the replicated item be 'protected' ..." 
Write-Host -Object "Replication state of the replicated item: $(Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer | Select-Object -Property FriendlyName, ProtectionState, ReplicationHealth | Out-String)"

Write-Host -Object "Waiting the replication state of the replicated item completes ..."
while ((Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer).ProtectionState -ne "Protected") {
    Start-Sleep -Seconds 60
}

#Monitor the replication state and replication health
Write-Host -Object "Replication state of the replicated item: $(Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $PrimaryProtectionContainer | Select-Object -Property  FriendlyName, ProtectionState, ReplicationHealth | Out-String)"
#endregion

#region Do a test failover, validate, and cleanup test failover
Write-Host -Object "Doing a test failover, validating, and cleaning up test failover ..."
#Create a separate network for test failover (not connected to my DR network)
$TFOVirtualNetworkName = "{0}-a2aTFOvnet" -f $PrimaryLocationVirtualNetwork.Name 
$TFOVirtualNetwork = New-AzVirtualNetwork -Name $TFOVirtualNetworkName -ResourceGroupName $RecoveryLocationResourceGroupName -Location $RecoveryLocation -AddressPrefix $TestFailOverVirtualNetworkAddressSpace
$null = Add-AzVirtualNetworkSubnetConfig -Name "default" -VirtualNetwork $TFOVirtualNetwork -AddressPrefix $TestFailOverSubnetIPRange | Set-AzVirtualNetwork

#region Do a test failover.
Write-Host -Object "Doing a test failover ..."
$ReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -FriendlyName $VMName -ProtectionContainer $PrimaryProtectionContainer
$TFOJob = Start-AzRecoveryServicesAsrTestFailoverJob -ReplicationProtectedItem $ReplicationProtectedItem -AzureVMNetworkId $TFOVirtualNetwork.Id -Direction PrimaryToRecovery

Write-Host -Object "Waiting the test failover completes ..." 
while (($TFOJob.State -eq "InProgress") -or ($TFOJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TFOJob = Get-AzRecoveryServicesAsrJob -Job $TFOJob
}
Write-Host -Object "Test failover status: $($TFOJob.State) ..."
#endregion

#region Starting the cleanup test failover operation
Write-Host -Object "Starting the cleanup test failover operation ..."
$Job_TFOCleanup = Start-AzRecoveryServicesAsrTestFailoverCleanupJob -ReplicationProtectedItem $ReplicationProtectedItem
Write-Host -Object "Waiting cleanup test failover operation completes ..." 
while (($Job_TFOCleanup.State -eq "InProgress") -or ($TFOJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $Job_TFOCleanup = Get-AzRecoveryServicesAsrJob -Job $Job_TFOCleanup 
}
Write-Host -Object "Cleanup test failover operation status: $($Job_TFOCleanup.State) ..."
$null = $TFOVirtualNetwork | Remove-AzVirtualNetwork -AsJob -Force
#endregion
#endregion

#region Fail over to Azure
Write-Host -Object "Starting Failover to Azure to the latest recovery point ..."
$RecoveryPoints = Get-AzRecoveryServicesAsrRecoveryPoint -ReplicationProtectedItem $ReplicationProtectedItem

#The list of recovery points returned may not be sorted chronologically and will need to be sorted first, in order to be able to find the oldest or the latest recovery points for the virtual machine.
$LatestRecoveryPoint = $RecoveryPoints | Sort-Object -Property RecoveryPointTime -Descending | Select-Object -First 1
Write-Host -Object "Latest Recovery Point: $($LatestRecoveryPoint.RecoveryPointTime)"

#Start the fail over job
$Job_Failover = Start-AzRecoveryServicesAsrUnplannedFailoverJob -ReplicationProtectedItem $ReplicationProtectedItem -Direction PrimaryToRecovery -RecoveryPoint $LatestRecoveryPoint

Write-Host -Object "Waiting the Failover to Azure to the latest recovery point completes ..." 
while (($Job_Failover.State -eq "InProgress") -or ($JobFailover.State -eq "NotStarted")) {
    $Job_Failover = Get-AzRecoveryServicesAsrJob -Job $Job_Failover;
    Start-Sleep -Seconds 30
} 
Write-Host -Object "Failover to Azure to the latest recovery point status: $($Job_Failover.State) ..."

#When the failover job is successful, you can commit the failover operation.
Write-Host -Object "Committing the failover operation ..." 
$CommitFailoverJob = Start-AzRecoveryServicesAsrCommitFailoverJob -ReplicationProtectedItem $ReplicationProtectedItem

Write-Host -Object "Waiting the Failover commit completes ..." 
while (($CommitFailoverJob.State -eq "InProgress") -or ($CommitFailoverJob.State -eq "NotStarted")) {
    $CommitFailoverJob = Get-AzRecoveryServicesAsrJob -Job $CommitFailoverJob;
    Start-Sleep -Seconds 30
}

Write-Host -Object "Failover commit status: $($CommitFailoverJob.State) ..."

#endregion

#region Reprotect
Write-Host -Object "Reprotecting ..." 

#Use the recovery protection container, new cache storage account in recovery location and the source region VM resource group
$ReprotectJob = Update-AzRecoveryServicesAsrProtectionDirection -ReplicationProtectedItem $ReplicationProtectedItem -AzureToAzure -ProtectionContainerMapping $RecoveryToPrimaryPCMapping -LogStorageAccountId $RecoveryLocationCacheStorageAccount.Id -RecoveryResourceGroupID $PrimaryLocationResourceGroup.ResourceId

Write-Host -Object "Waiting the reprotection completes ..." 
while (($ReprotectJob.State -eq "InProgress") -or ($ReprotectJob.State -eq "NotStarted")) {
    $ReprotectJob = Get-AzRecoveryServicesAsrJob -Job $ReprotectJob;
    Start-Sleep -Seconds 30
}

Write-Host -Object "Reprotection: $($ReprotectJob.State) ..."
#endregion

#region Disable replication
Write-Host -Object "Disabling replication ..."
$ReplicationProtectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -FriendlyName $VMName -ProtectionContainer $RecoveryProtectionContainer
$TempASRJob = Remove-AzRecoveryServicesAsrReplicationProtectedItem -ReplicationProtectedItem $ReplicationProtectedItem
#$TempASRJob = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $RecoveryProtectionContainer | Remove-AzRecoveryServicesAsrReplicationProtectedItem
#Track Job status to check for completion
while (($TempASRJob.State -eq "InProgress") -or ($TempASRJob.State -eq "NotStarted")) {
    Start-Sleep -Seconds 10
    $TempASRJob = Get-AzRecoveryServicesAsrJob -Job $TempASRJob
}

#Check if the Job completed successfully. The updated job state of a successfully completed job should be "Succeeded"
Write-Host -Object "Disabling replication status: $($TempASRJob.State) ..."
#endregion

<#
#region Cleanup
Remove-AzResourceGroup -Name $PrimaryLocationResourceGroupName -Force -AsJob
Remove-AzResourceGroup -Name $RecoveryLocationResourceGroupName -Force -AsJob
#endregion
#>