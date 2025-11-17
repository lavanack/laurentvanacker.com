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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.PolicyInsights, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage

#From https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-how-to-enable-policy

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
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}

$AzureVMNameMaxLength = 15
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$PrimaryLocation = "EastUS2"
$RecoveryLocation = "CentralUS"
$VMSize = "Standard_D4s_v4"
$PrimaryLocationShortName = $shortNameHT[$PrimaryLocation].shortName
$RecoveryLocationShortName = $shortNameHT[$RecoveryLocation].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$RecoverySiteVaultPrefix = "rsv"
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$Project = "asr"
$Role = "pol"
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
$RecoveryLocationSubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$PrimaryLocationResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $PrimaryLocationShortName, $Instance                       
$RecoveryLocationResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance                       
$RecoveryServicesVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $RecoverySiteVaultPrefix, $Project, $Role, $RecoveryLocationShortName, $Instance

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
$SubnetIPRange = "10.0.0.0/24" # Format 10.0.1.0/24                         

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

$MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"

#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsServer"
$ImageOffer = "WindowsServer"
$ImageSku = "2022-datacenter-g2"
$PublicIPName = "pip-$VMName" 
$NICName = "nic-$VMName"
$OSDiskName = '{0}_OSDisk' -f $VMName
$DataDiskName = '{0}_DataDisk' -f $VMName
$OSDiskSize = "127"
$StorageAccountSkuName = "Standard_LRS"
$OSDiskType = "StandardSSD_LRS"

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
elseif ($null -eq (Get-AzVMSize -Location $PrimaryLocation | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$PrimaryLocation' location ..." -ErrorAction Stop
}
elseif ($null -eq (Get-AzVMSize -Location $RecoveryLocation | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$RecoveryLocation' location ..." -ErrorAction Stop
}

#Create Azure Resource Group
# Create Resource Groups
#The resource group for the virtual machine(s)
$PrimaryLocationResourceGroup = New-AzResourceGroup -Name $PrimaryLocationResourceGroupName -Location $PrimaryLocation -Force
#The resource group that the virtual machine(s) must be created in when failed over.
$RecoveryLocationResourceGroup = New-AzResourceGroup -Name $RecoveryLocationResourceGroupName -Location $RecoveryLocation -Force

#region Create a Recovery Services vault
#Create a new Recovery services vault in the recovery region
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is creating ..."
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $RecoveryLocation -ResourceGroupName $RecoveryLocationResourceGroupName
Write-Host -Object "The '$RecoveryServicesVaultName' Recovery Services Vault is created ..."
#endregion

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

#Steps 4 + 5: Create Azure Virtual network (and related NSG) using the virtual network subnet configuration
#region Primary Location
$PrimaryLocationVirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $PrimaryLocationResourceGroupName -Name $PrimaryLocationVirtualNetworkName  -AddressPrefix $PrimaryLocationVirtualNetworkAddressSpace -Location $PrimaryLocation
Add-AzVirtualNetworkSubnetConfig -Name $PrimaryLocationSubnetName -VirtualNetwork $PrimaryLocationVirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $PrimaryLocationNetworkSecurityGroup.Id
$PrimaryLocationVirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $PrimaryLocationVirtualNetwork
$PrimaryLocationSubnet = Get-AzVirtualNetworkSubnetConfig -Name $PrimaryLocationSubnetName -VirtualNetwork $PrimaryLocationVirtualNetwork
#endregion

#Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -AllocationMethod Static -DomainNameLabel $VMName.ToLower()
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
$null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

#region Adding Data Disk
$VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $PrimaryLocation -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $PrimaryLocationResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
#endregion

#Create Azure Virtual Machine
$null = New-AzVM -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -VM $VMConfig #-DisableBginfoExtension

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

<#
#region Create Cache storage account for replication logs in the primary region
Write-Host -Object "Creating cache storage account for replication logs in the primary region ('$PrimaryLocation') ..."
$PrimaryLocationCacheStorageAccount = New-AzStorageAccount -Name $PrimaryLocationCacheStorageAccountName -ResourceGroupName $PrimaryLocationResourceGroupName -Location $PrimaryLocation -SkuName Standard_LRS -Kind Storage
#endregion
#>

#region Azure Policy Management
$PolicyDefinition = Get-AzPolicyDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery" }
$PolicyParameterObject = @{
    SourceRegion          = $PrimaryLocation 
    TargetRegion          = $RecoveryLocation 
    targetResourceGroupId = $RecoveryLocationResourceGroup.ResourceId 
    vaultResourceGroupId  = $RecoveryLocationResourceGroup.ResourceId 
    vaultId               = $RecoveryServicesVault.ID 
}

$PolicyAssignment = New-AzPolicyAssignment -Name "$($PrimaryLocationResourceGroupName)-enableAzureVMReplicationViaAzureSiteRecovery" -DisplayName 'Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery' -Scope $PrimaryLocationResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $RecoveryLocation -PolicyParameterObject $PolicyParameterObject 

# Grant defined roles to the primary and recovery resource groups with PowerShell
$roleDefinitionIds = $PolicyDefinition | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } | Select-Object -ExpandProperty roleDefinitionIds #-Unique
Start-Sleep -Seconds 30
if ($roleDefinitionIds.Count -gt 0) {
    $roleDefinitionIds | ForEach-Object -Process {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        if (-not(Get-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
            New-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            New-AzRoleAssignment -Scope $RecoveryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
        }
    }
}

Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy ..."
$PolicyRemediation = Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $PrimaryLocationResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
$PolicyRemediation

Write-Host -Object "Starting Compliance Scan for '$PrimaryLocationResourceGroupName' Resource Group ..."
$PolicyComplianceScan = Start-AzPolicyComplianceScan -ResourceGroupName $PrimaryLocationResourceGroup
$PolicyComplianceScan


# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $PrimaryLocationResourceGroup -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $PrimaryLocationResourceGroup | Select-Object -ExpandProperty PolicyAssignments 
#endregion 


