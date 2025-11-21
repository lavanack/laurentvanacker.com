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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.PolicyInsights, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage, PSScheduledJob, PSWorkflow

#From https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-how-to-enable-policy

[CmdletBinding()]
param
(
    [switch]$Wait
)


#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12,122)]
        [int] $minLength = 12, ## characters
        [ValidateRange(13,123)]
        [ValidateScript({$_ -gt $minLength})]
        [int] $maxLength = 15, ## characters
        [switch] $AsSecureString,
        [switch] $ClipBoard,
        [Parameter(ParameterSetName = 'GeneratePassword')]
        [int] $nonAlphaChars = 3,
        [Parameter(ParameterSetName = 'DinoPass')]
        [switch] $Online
    )
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/faq#what-are-the-password-requirements-when-creating-a-vm-
    $ProhibitedPasswords = @('abc@123', 'iloveyou!', 'P@$$w0rd', 'P@ssw0rd', 'P@ssword123', 'Pa$$word', 'pass@word1', 'Password!', 'Password1', 'Password22')
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    Do {
        if ($Online) {
            $URI = "https://www.dinopass.com/password/custom?length={0}&useSymbols=true&useNumbers=true&useCapitals=true" -f $length
            $RandomPassword = Invoke-RestMethod -Uri $URI
        }
        else {
            Add-Type -AssemblyName 'System.Web'
            $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        }
    } Until (($RandomPassword  -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W')))

    #Write-Host -Object "The password is : $RandomPassword"
    if ($ClipBoard) {
        #Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V) ..."
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

#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}

#region JIT/RDP/SSH Settings
$RDPPort = 3389
$JITPolicyPorts = $RDPPort
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
#endregion

#$Location = "swedencentral"
$Location = "EastUS2"
$LocationShortName = $shortNameHT[$Location].shortName
if ([string]::isNullOrEmpty($LocationShortName)) {
	$LocationShortName = "xxx"
}

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
$VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
$VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
$SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].ShortName
$NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
$KeyVaultPrefix = $ResourceTypeShortNameHT["KeyVault/vaults"].ShortName
$PublicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
$NICPrefix = $ResourceTypeShortNameHT["Network/networkInterfaces"].ShortName


$Project = "vm"
$Role = "ade"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    #Create Cache storage account for replication logs in the primary region
    #Create Cache storage account for replication logs in the recovery region
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
    $KeyVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $KeyVaultPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $KeyVaultName = $KeyVaultName.ToLower()
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) -or (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable))


$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$PublicIPName = "{0}-{1}" -f $PublicIPAddressPrefix , $VMName
$NICName = "{0}-{1}" -f $NICPrefix , $VMName

$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$PublicIPName = $PublicIPName.ToLower()
$NICName = $NICName.ToLower()

$ResourceGroupName = $ResourceGroupName.ToLower()
$VirtualNetworkAddressSpace = "10.0.0.0/16" # Format 10.0.0.0/16
$SubnetIPRange = "10.0.0.0/24" # Format 10.0.1.0/24                         

$FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()

#region Defining credential(s)
$Username = $env:USERNAME
$SecurePassword = New-RandomPassword -nonAlphaChars 0 -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$Jobs = @()
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $Jobs += $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
}

$Jobs | Wait-Job | Out-Null
$Jobs | Remove-Job -Force

$MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"

#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsServer"
$ImageOffer = "WindowsServer"
$ImageSku = "2022-datacenter-g2"
$OSDiskName = '{0}_OSDisk' -f $VMName
$DataDisk01Name = '{0}_DataDisk01' -f $VMName
$DataDisk02Name = '{0}_DataDisk02' -f $VMName
$OSDiskSize = "127"
#$OSDiskType = "StandardSSD_LRS"
$OSDiskType = "Standard_LRS"
#$VMSize = "Standard_D4s_v5"
$VMSize = "Standard_B2ms"

if ($null -eq (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error -Message "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

Write-Verbose -Message "`$VMName: $VMName"
Write-Verbose -Message "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
Write-Verbose -Message "`$VirtualNetworkName: $VirtualNetworkName"         
Write-Verbose -Message "`$SubnetName: $SubnetName"       
Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose -Message "`$PublicIPName: $PublicIPName"
Write-Verbose -Message "`$NICName: $NICName"
Write-Verbose -Message "`$OSDiskName: $OSDiskName"
Write-Verbose -Message "`$FQDN: $FQDN"
#endregion
#endregion

#region Azure VM Setup
Write-Host -Object "The '$VMName' Azure VM is creating ..."
if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error -Message "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($LocationShortName)) {
    Write-Error -Message "No location short name found for '$Location'" -ErrorAction Stop
}
elseif ($null -eq (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error -Message "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
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
#region Primary Location
$VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $NetworkSecurityGroup.Id
$VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork
#endregion

#Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -DomainNameLabel $VMName.ToLower()
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
#region Checking if the VM Size can be set as a Spot Instance
$Query = @"
SpotResources 
| where type =~ 'microsoft.compute/skuspotpricehistory/ostype/location' 
| where sku.name in~ ('$VMSize') 
| where properties.osType =~ 'windows' 
| where location in~ ('$Location') 
| project skuName = tostring(sku.name), location
"@
$Result = Search-AzGraph -Query $Query -UseTenantScope
#endregion

#Spot Instance 
if ($Result.skuName -eq $VMSize ){
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1 -IdentityType SystemAssigned -SecurityType TrustedLaunch
}
else {
    Write-Warning -Message "'$VMSize' can not be set as Spot Instance in the '$Location' Azure location"
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -IdentityType SystemAssigned -SecurityType TrustedLaunch
}

$null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set VM operating system parameters
$null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

# Set boot diagnostic storage account
# Set boot diagnostic to managed storage account
$null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

# The uncommented lines below replace Set virtual machine source image
$null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

#region Setting up the Key Vault for Disk Encryption
#Create an Azure Key Vault
$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $Location -EnabledForDiskEncryption -EnablePurgeProtection

#region "Key Vault Administrator" RBAC Assignment
$RoleDefinition = Get-AzRoleDefinition "Key Vault Administrator"
$WhoAmI = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id)
$RoleAssignment = New-AzRoleAssignment -ObjectId $WhoAmI.Id -RoleDefinitionName $RoleDefinition.Name -Scope $KeyVault.ResourceId -ErrorAction Ignore #-Debug
#endregion

Start-Sleep -Seconds 30

#FROM https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell#set-up-an-azure-key-vault-and-diskencryptionset-optionally-with-automatic-key-rotation
$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForDiskEncryption

#As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $WhoAmI.UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru
#endregion

Start-Sleep -Seconds 30
#endregion 

# Set OsDisk configuration
$null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

#region Adding Data Disks
$VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk02Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDisk01Name -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
$VMDataDisk02 = New-AzDisk -DiskName $DataDisk02Name -Disk $VMDataDisk02Config -ResourceGroupName $ResourceGroupName
$null = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk01Name -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
$null = Add-AzVMDataDisk -VM $VMConfig -Name $DataDisk02Name -CreateOption Attach -ManagedDiskId $VMDataDisk02.Id -Lun 1
#endregion

#Create Azure Virtual Machine
$null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig -OSDiskDeleteOption Delete -DataDiskDeleteOption Delete #-DisableBginfoExtension
$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName

#region Formatting Data Disk(s)
$ScriptString = @'
#Creating new partition on uninitialized disk(s)
Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume

#Creating a timestamped file using 10% of the free space on every PSDrive
Get-PSDrive -PSProvider FileSystem | ForEach-Object -Process {
    $FileName= "10Percent_{0:yyyyMMddHHmmss}.txt" -f (Get-Date)
    $FilePath = Join-Path $_.Root -ChildPath $FileName
    $Size = $_.Free/10
    $FS = [System.IO.File]::Create($FilePath)
    $FS.SetLength($size)
}
'@
$RunPowerShellScript = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
#$RunPowerShellScript
#endregion

#region JIT Access Management
#region Enabling JIT Access
$NewJitPolicy = (
    @{
        id    = $VM.Id
        ports = 
        foreach ($CurrentJITPolicyPort in $JITPolicyPorts) {
            @{
                number                     = $CurrentJITPolicyPort;
                protocol                   = "*";
                allowedSourceAddressPrefix = "*";
                maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
            }
        }
    }
)

Write-Host -Object "Get Existing JIT Policy. You can Ignore the error if not found."
$ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
$UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
$UpdatedJITPolicy.Add($NewJitPolicy)
	
# Enable Access to the VM including management Port, and Time Range in Hours
Write-Host -Object "Enabling Just in Time VM Access Policy for ($VMName) on port number(s) $($JitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours..."
$JitNetworkAccessPolicy = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
Start-Sleep -Seconds 5
#endregion

#region Requesting Temporary Access : 3 hours
$JitPolicy = (
    @{
        id    = $VM.Id
        ports = 
        foreach ($CurrentJITPolicyPort in $JITPolicyPorts) {
            @{
                number                     = $CurrentJITPolicyPort;
                endTimeUtc                 = (Get-Date).AddHours($JitPolicyTimeInHours).ToUniversalTime()
                allowedSourceAddressPrefix = @($MyPublicIP) 
            }
        }
    }
)
$ActivationVM = @($JitPolicy)
Write-Host -Object "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number(s) $($JitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
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


#region Azure Disk Encryption
#From https://learn.microsoft.com/en-us/powershell/module/az.compute/set-azvmdiskencryptionextension?view=azps-13.0.0
$params = @{
    ResourceGroupName         = $ResourceGroupName
    VMName                    = $VMName
    DiskEncryptionKeyVaultId  = $KeyVault.ResourceId
    DiskEncryptionKeyVaultUrl = $KeyVault.VaultUri
    VolumeType                = "All"
    Force                     = $true
}
Set-AzVMDiskEncryptionExtension @params

Get-AzVMDiskEncryptionStatus -ResourceGroupName $ResourceGroupName -VMName $VMName
#endregion

#Start Azure Virtual Machine
Write-Host -Object "Starting the '$VMName' VM ..."
$null = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

# Adding Credentials to the Credential Manager (and escaping the password) for the VM
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait #-NoNewWindow
Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" #-ForegroundColor Green
# Adding Credentials to the Credential Manager (and escaping the password) for the potential future target VM
$FQDNTarget = $FQDN -replace "^([^.]*)(.*)$", '$1target$2'
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDNTarget /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait #-NoNewWindow
<#
$Credential = $null
Write-Warning -Message "Credentials cleared from memory but available in the Windows Credential Manager for automatic logon via a RDP client ..."
#>
Write-Host -Object "The '$FQDN' Azure VM is created and started ..."

#Start-Sleep -Seconds 15

#Start RDP Session
#mstsc /v $FQDN
#endregion

#region Disk Encryption In Progress
if ($Wait) {
    Write-Host -Object "Encrypting Disk ..."
    $StartTime = Get-Date
    Do {
        $RunPowerShellScript = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString "Get-BitLockerVolume | ConvertTo-Json"
        Write-Verbose -Message "`$Statuses (As Json):`r`n$($RunPowerShellScript.value[0].Message)"
        $Result = $RunPowerShellScript.value[0].Message | ConvertFrom-Json
        Write-Verbose -Message "`$Statuses:`r`n$($Result | Out-String)"
        $Drives = ($Result | Where-Object -FilterScript { $_.MountPoint -match "^\w:$"})
        Write-Verbose -Message "`$Drives:`r`n$($Drives | Out-String)"
        Start-Sleep -Seconds 30
        #Volumestatus value : 0 = 'FullyDecrypted', 1 = 'FullyEncrypted', 2 = 'EncryptionInProgress', 3 = 'DecryptionInProgress', 4 = 'EncryptionPaused', 5 = 'DecryptionPaused'
    } While (($Drives.VolumeStatus | Select-Object -Unique) -ne "1")
    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Encrypting Disk - Processing Time: $TimeSpan"
}
else {
    Write-Host -Object "-Wait NOT specified: Skipping The Encryption Disk Wait (Encryption will occur in the background)..."
}
#endregion
