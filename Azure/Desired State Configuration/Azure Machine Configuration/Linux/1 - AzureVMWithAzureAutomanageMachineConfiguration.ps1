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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Storage, Az.Resources

[CmdletBinding()]
param
(
    [string] $SSHPublicKeyPath
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
    Write-Host "The password is : $RandomPassword"
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


<#
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Set-Location $HOME
ssh-keygen -t rsa
#>

$SSHPublicKeyProfilePath = Join-Path -Path $HOME -ChildPath '.ssh\id_rsa.pub'
if (([string]::IsNullOrEmpty($SSHPublicKeyPath)) -and (-not(Test-Path -Path $SSHPublicKeyProfilePath -PathType Leaf))) {
    Write-Error -Message "No SSH PublicKey Path specified or not found in '$SSHPublicKeyProfilePath'. STOP !" -ErrorAction Stop
}

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion


$AzureVMNameMaxLength = 15
$RDPPort = 3389
$SSHPort = 22
$JITPolicyPorts = $RDPPort, $SSHPort
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$Location = "eastus2"
$VMSize = "Standard_D4s_v5"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$ResourceGroupPrefix = "rg"
$StorageAccountPrefix = "sa"
$VirtualMachinePrefix = "vm"
$NetworkSecurityGroupPrefix = "nsg"
$VirtualNetworkPrefix = "vnet"
$SubnetPrefix = "snet"
$Project = "dsc"
$Role = "amc"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength-($VirtualMachinePrefix+$Project+$Role+$LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) -or ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)))

$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       

$StorageAccountName = $StorageAccountName.ToLower()
$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$VirtualNetworkAddressSpace = "10.10.0.0/16" # Format 10.10.0.0/16
$SubnetIPRange = "10.10.1.0/24" # Format 10.10.1.0/24                         
$FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()


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
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org").Content


#region Define Variables needed for Virtual Machine
$ImagePublisherName = "canonical"
$ImageOffer = "0001-com-ubuntu-server-jammy"
$ImageSku = "22_04-lts-gen2"
$PublicIPName = "pip-$VMName" 
$NICName = "nic-$VMName"
$OSDiskName = '{0}_OSDisk' -f $VMName
#$DataDiskName = "$VMName-DataDisk01"
$OSDiskSize = "127"
$StorageAccountSkuName = "Standard_LRS"
$OSDiskType = "StandardSSD_LRS"

Write-Verbose "`$VMName: $VMName"
Write-Verbose "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         
Write-Verbose "`$SubnetName: $SubnetName"       
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$PublicIPName: $PublicIPName"
Write-Verbose "`$NICName: $NICName"
Write-Verbose "`$OSDiskName: $OSDiskName"
Write-Verbose "`$FQDN: $FQDN"
#endregion
#endregion


if ($VMName.Length -gt $AzureVMNameMaxLength) {
    Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
}
elseif (-not($LocationShortName)) {
    Write-Error "No location short name found for '$Location'" -ErrorAction Stop
}
elseif ($null -eq (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
    Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
}

#Step 1: Create Azure Resource Group
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#Step 2: Create Azure Storage Account
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -AllowBlobPublicAccess $true

#Step 3: Create Azure Network Security Group
#RDP only for my public IP address
$SecurityRules = @(
    #region Inbound
    #SSH only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name SSHRule -Description "Allow SSH" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $SSHPort
    #RDP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $RDPPort
    #HTTP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 302 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
    #HTTPS only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPSRule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 303 -SourceAddressPrefix $MyPublicIp -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
    #endregion
)

$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

#Steps 4 + 5: Create Azure Virtual network using the virtual network subnet configuration
$VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
$null = Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork -AddressPrefix $SubnetIPRange -NetworkSecurityGroupId $NetworkSecurityGroup.Id

$VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
$Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VirtualNetwork


#Step 6: Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AlLocationMethod Static -DomainNameLabel $VMName.ToLower()
#Setting up the DNS Name
#$PublicIP.DnsSettings.Fqdn = $FQDN

#Step 7: Create Network Interface Card 
$NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id

<# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
$ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "canonical"}
$ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "0001-com-ubuntu-server-jammy"}
$ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "22_04-lts-gen2"}
$image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
#>

# Step 9: Create a virtual machine configuration file (As a Spot Intance)
$VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1 -EvictionPolicy Deallocate

#region Defining SSH Public Key 
if ([string]::IsNullOrEmpty($SSHPublicKeyPath)) {
    #If a SSH Public Key has not been specified, we build a path to test in the current user profile
    $SSHPublicKeyPath = $SSHPublicKeyProfilePath
}
if (Test-Path -Path $SSHPublicKeyPath -PathType Leaf) {
    # Set VM operating system parameters
    Set-AzVMOperatingSystem -VM $VMConfig -Linux -ComputerName $VMName -Credential $Credential -DisablePasswordAuthentication -PatchMode "AutomaticByPlatform"
    $SSHPublicKey = Get-Content -Path $SSHPublicKeyPath
    Add-AzVMSshPublicKey -VM $VMConfig -KeyData $SSHPublicKey -Path "/home/$($Credential.UserName)/.ssh/authorized_keys"
}
else {
    # Set VM operating system parameters
    Set-AzVMOperatingSystem -VM $VMConfig -Linux -ComputerName $VMName -Credential $Credential
}
#endregion

$null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set boot diagnostic storage account
#Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
# Set boot diagnostic to managed storage account
$null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

# The uncommented lines below replace Step #8 : Set virtual machine source image
$null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

# Set OsDisk configuration
$null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

#region Adding Data Disk
<#
$VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
#>
#endregion

#Step 10: Create Azure Virtual Machine
New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig #-DisableBginfoExtension

$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName

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

Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
$ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
$UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
$UpdatedJITPolicy.Add($NewJitPolicy)

# Enable Access to the VM including management Port, and Time Range in Hours
Write-Host "Enabling Just in Time VM Access Policy for ($($VM.Name)) on port number(s) $($NewJitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
$null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
#endregion
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
Write-Host "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number(s) $($JitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
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
New-AzResource -Location $location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
#endregion

#Step 11: Start Azure Virtual Machine
Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

# Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

#region Updating
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'sudo apt update && sudo apt upgrade'
Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
#endregion

#region Installing and configuring xrdp to use Remote Desktop with Ubuntu
#From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/use-remote-desktop?tabs=azure-powershell
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'sudo DEBIAN_FRONTEND=noninteractive apt-get -y install xfce4 && sudo apt install xfce4-session'
#For allowing RDP session with the same user logged in
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString "echo '3' | sudo update-alternatives --config x-session-manager"
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'sudo apt-get -y install xrdp && sudo systemctl enable xrdp && sudo adduser xrdp ssl-cert && echo xfce4-session >~/.xsession && sudo service xrdp restart'
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString 'sudo ufw allow 3389'
$SSHConnection = "{0}@{1}" -f $($Credential.UserName), $FQDN
#Setting the password for the user
#Start-Process -FilePath "$env:comspec" -ArgumentList '/c', "ssh -o StrictHostKeyChecking=no $SSHConnection ""echo -e '$($Credential.GetNetworkCredential().Password)\n$($Credential.GetNetworkCredential().Password)' | sudo passwd $($Credential.UserName)""" -Wait
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptString "echo '$($Credential.GetNetworkCredential().Password)\n$($Credential.GetNetworkCredential().Password)' | sudo passwd $($Credential.UserName)"
Restart-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName

#Step 12: Start RDP Session
mstsc /v $FQDN
#endregion

#region Registering Azure Resource Providers
#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
Register-AzResourceProvider -ProviderNamespace Microsoft.PolicyInsights
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration, Microsoft.PolicyInsights | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}
#endregion

#region Installing/Updating PowerShell 7+ locally (required for creating the Guest Configuration Package)
#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
#endregion

#region Creating the Guest Configuration Package locally
$NewGuestConfigurationPackageScriptFilePath = Join-Path -Path $CurrentDir -ChildPath '2 - NewGuestConfigurationPackage.ps1'
Start-Process -FilePath "$env:comspec" -ArgumentList '/c', "pwsh -File ""$NewGuestConfigurationPackageScriptFilePath""" -Wait
#endregion

Write-Host -Object "Your SSH/RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
#If no SSH Public Key, creating a connection by passing the user name
Start-Process -FilePath "$env:comspec" -ArgumentList '/c', "scp -o StrictHostKeyChecking=no ExampleConfiguration.zip 3*.sh 4*.ps1 $($SSHConnection):~" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList '/c', "ssh -o StrictHostKeyChecking=no $SSHConnection chmod +x *.sh" -Wait
#Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VMName -CommandId 'RunShellScript' -ScriptPath '3 - Prerequisites.sh'
#Start-Process -FilePath "$env:comspec" -ArgumentList '/k', "ssh -o StrictHostKeyChecking=no $SSHConnection sudo './3 - Prerequisites.sh'"
Start-Process -FilePath "$env:comspec" -ArgumentList '/c', "ssh -o StrictHostKeyChecking=no $SSHConnection"

#Browsing to the hosted website
Start-Process -FilePath "http://$FQDN"
