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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Storage

[CmdletBinding()]
Param (
)

#region function definitions
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12, 122)]
        [int] $minLength = 12, ## characters
        [ValidateRange(13, 123)]
        [ValidateScript({ $_ -gt $minLength })]
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
    } Until (($RandomPassword -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W')))

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

#region Main Code
Clear-Host
$Error.Clear()

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

#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion


# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}

$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$Location = "francecentral"
$VMSize = "Standard_D4s_v5"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
$AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$StorageAccountPrefix = $ResourceTypeShortNameHT["Storage/storageAccounts"].ShortName
$VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
$NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
$VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
$SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
$PublicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
$BastionPrefix = $ResourceTypeShortNameHT["Network/bastionHosts"].ShortName

$NatGatewayPrefix = "natgw"
$LocationShortName = $shortNameHT[$Location].shortName

#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$Project = "net"
$Role = $NatGatewayPrefix
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $StorageAccountName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = "{0}{1}{2}{3}{4:D$DigitNumber}" -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
} While ((-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) -or ((-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)))

$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$NatGatewayName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NatGatewayPrefix, $Project, $Role, $LocationShortName, $Instance    
$BastionName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $BastionPrefix, $Project, $Role, $LocationShortName, $Instance    
$BastionPublicIpName = "{0}-{1}" -f $PublicIPAddressPrefix, $BastionName
$NatGatewayPublicIpName = "{0}-{1}" -f $PublicIPAddressPrefix, $NatGatewayName
                     
$StorageAccountName = $StorageAccountName.ToLower()
$VMName = $VMName.ToLower()
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$VirtualNetworkName = $VirtualNetworkName.ToLower()
$SubnetName = $SubnetName.ToLower()
$ResourceGroupName = $ResourceGroupName.ToLower()
$NatGatewayName = $NatGatewayName.ToLower()
$BastionName = $BastionName.ToLower()
$BastionPublicIpName = $BastionPublicIpName.ToLower()
$NatGatewayPublicIpName = $NatGatewayPublicIpName.ToLower()
$VirtualNetworkSubnetAddressPrefix = "10.0.0.0/16" # Format 10.0.0.0/16
$BastionSubnetAddressPrefix = '10.0.1.0/26'
$NatGatewaySubnetAddressPrefix = "10.0.0.0/24" # Format 10.0.1.0/24                         
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
$MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"


#region Define Variables needed for Virtual Machine
$ImagePublisherName = "MicrosoftWindowsServer"
$ImageOffer = "WindowsServer"
$ImageSku = "2022-datacenter-g2"
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
Write-Verbose "`$NatGatewayName: $NatGatewayName"       
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$BastionPublicIpName: $BastionPublicIpName"
Write-Verbose "`$NatGatewayPublicIpName: $NatGatewayPublicIpName"
Write-Verbose "`$NICName: $NICName"
Write-Verbose "`$OSDiskName: $OSDiskName"
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

#region Create Azure Resource Group
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion 

#region Create the NAT gateway
#From https://learn.microsoft.com/en-us/azure/nat-gateway/quickstart-create-nat-gateway?tabs=powershell
#region Create public IP address for NAT gateway 
$IP = @{
    Name              = $NatGatewayPublicIpName
    ResourceGroupName = $ResourceGroupName
    Location          = $Location
    Sku               = 'Standard'
    AllocationMethod  = 'Static'
    #Zone = 1,2,3
}
$PublicIp = New-AzPublicIpAddress @IP
#endregion 

#region Create NAT gateway resource 
$Nat = @{
    ResourceGroupName    = $ResourceGroupName
    Name                 = $NatGatewayName
    IdleTimeoutInMinutes = '10'
    Sku                  = 'Standard'
    Location             = $Location
    PublicIpAddress      = $PublicIp
}
$NatGateway = New-AzNatGateway @Nat
#endregion 

#region Create subnet config and associate NAT gateway to subnet
$Subnet = @{
    Name          = $SubnetName
    AddressPrefix = $NatGatewaySubnetAddressPrefix
    NatGateway    = $NatGateway
}
$SubnetConfig = New-AzVirtualNetworkSubnetConfig @subnet 
#endregion 

#region Create Azure Bastion subnet 
$BastionSubnet = @{
    Name          = 'AzureBastionSubnet' 
    AddressPrefix = $BastionSubnetAddressPrefix
}
$BastionSubnetConfig = New-AzVirtualNetworkSubnetConfig @BastionSubnet
#endregion 

#region Create the virtual network
$Net = @{
    Name              = $VirtualNetworkName
    ResourceGroupName = $ResourceGroupName
    Location          = $Location
    AddressPrefix     = $VirtualNetworkSubnetAddressPrefix
    Subnet            = $SubnetConfig, $BastionSubnetConfig
}
$VirtualNetwork = New-AzVirtualNetwork @Net
$BastionSubnetConfig = New-AzVirtualNetworkSubnetConfig @BastionSubnet
#endregion

#region Create public IP address for bastion host ##
$IP = @{
    Name              = $BastionPublicIpName
    ResourceGroupName = $ResourceGroupName
    Location          = $Location
    Sku               = 'Standard'
    AllocationMethod  = 'Static'
    #Zone = 1,2,3
}
$PublicIp = New-AzPublicIpAddress @ip
#endregion

#region Create bastion host
$bastion = @{
    Name                  = $BastionName
    ResourceGroupName     = $ResourceGroupName
    PublicIpAddressRgName = $ResourceGroupName
    PublicIpAddressName   = $BastionPublicIpName
    VirtualNetworkRgName  = $ResourceGroupName
    VirtualNetworkName    = $VirtualNetworkName
    Sku                   = 'Basic'
}
New-AzBastion @bastion
#endregion
#endregion

#region Create Azure Storage Account
$StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -AllowBlobPublicAccess $true
#endregion

#region Create Network Interface Card 
$NIC = @{
    Name              = $NICName
    ResourceGroupName = $ResourceGroupName
    Location          = $Location
    Subnet            = $VirtualNetwork.Subnets[0]
}
$NICVM = New-AzNetworkInterface @NIC
#endregion

#region Create a virtual machine configuration
$VMSize = @{
    VMName       = $VMName
    VMSize       = $VMSize
    IdentityType = "SystemAssigned"
    Priority     = "Spot"
    MaxPrice     = -1
}
$VMOS = @{
    ComputerName     = $VMName
    Credential       = $Credential
    ProvisionVMAgent = $true
    EnableAutoUpdate = $true
    PatchMode        = "AutomaticByPlatform"
}
$VMImage = @{
    PublisherName = $ImagePublisherName
    Offer         = $ImageOffer
    Skus          = $ImageSku
    Version       = 'latest'     
}
$VMConfig = New-AzVMConfig @VMSize `
| Set-AzVMOperatingSystem @VMOS -Windows `
| Set-AzVMOSDisk -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage `
| Set-AzVMBootDiagnostic -ResourceGroupName $ResourceGroupName -Enable `
| Set-AzVMSourceImage @VMImage `
| Add-AzVMNetworkInterface -Id $NICVM.Id
#endregion

#region Create the virtual machine
$vm = @{
    ResourceGroupName = $ResourceGroupName
    Location          = $Location
    VM                = $VMConfig
}
$VM = New-AzVM @vm
$VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
#endregion

<#
#region Adding Data Disk
$VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
$VMDataDisk01 = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
$VM = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
#endregion
#>

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

#region Start Azure Virtual Machine
$VM | Start-AzVM
#endregion

#region Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait
Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
#endregion
#endregion