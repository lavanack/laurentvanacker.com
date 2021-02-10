Clear-Host

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword
{
    [CmdletBinding(PositionalBinding=$false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 5,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard)
    {
        Write-Verbose "The password has beeen copied into the clipboard ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString)
    {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else
    {
        $RandomPassword
    }
}
#endregion

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Defining variables for networking part
$ResourceGroupName          = "automatedlab-rg"
$Location                   = "FranceCentral"
$VirtualNetworkName         = "automatedlab-vnet"
$VirtualNetworkAddressSpace = "10.10.0.0/16" # Format 10.10.0.0/16
$SubnetIPRange              = "10.10.1.0/24" # Format 10.10.1.0/24
$SubnetName                 = "Subnet"
$NetworkSecurityGroupName   = "automatedlab-nsg"
$StorageAccountName         = "automatelabsa" # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$StorageAccountSkuName      = "Standard_LRS"
$SubscriptionName           = "Microsoft Azure Internal Consumption"
#endregion

#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
#$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$SecurePassword = Read-Host -Prompt "Enter your Password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

#region Define Variables needed for Virtual Machine
$VMName 	        = "WIN10"
$ImagePublisherName	= "MicrosoftWindowsDesktop"
$ImageOffer	        = "Windows-10"
$ImageSku	        = "20h2-ent"
$VMSize 	        = "Standard_D4s_v3"
$PublicIPName       = "$VMName-PIP" 
$NICName            = "$VMName-NIC"
$OSDiskName         = "$VMName-OSDisk"
$DataDiskName       = "$VMName-DataDisk"
$OSDiskSize         = "128"
$DataDiskSize       = "256"
$OSDiskType         = "Premium_LRS"
$DataDiskType       = "Premium_LRS"
#endregion

# Login to your Azure subscription.
Connect-AzAccount
#$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup)
{
    #Step 0: Remove previously existing Azure Resource Group with the "automatedlab-rg" name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

#Step 1: Create Azure Resource Group
# Create Resource Groups and Storage Account for diagnostic
New-AzResourceGroup -Name $ResourceGroupName -Location $Location

#Step 2: Create Azure Storage Account
New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName

#Step 3: Create Azure Network Security Group
$RDPRule              = New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389
$HTTPRule             = New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $RDPRule,$HTTPRule

#Steps 4 + 5: Create Azure Virtual network using the virtual network subnet configuration
$vNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -AddressPrefix $VirtualNetworkAddressSpace -Location $Location
Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNetwork -AddressPrefix $SubnetIPRange
$vNetwork = Set-AzVirtualNetwork -VirtualNetwork $vNetwork
$Subnet   = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNetwork

#Step 6: Create Azure Public Address
$PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AlLocationMethod Static 

#Step 7: Create Network Interface Card 
$NIC      = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id -NetworkSecurityGroupId $NetworkSecurityGroup.Id

<# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
$ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
$ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "windows-10-20h2-vhd-client-prod-stage"}
$ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "2019-Datacenter"}
$image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $VMImageOffer.Offer -sku $VMImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
#>

# Step 9: Create a virtual machine configuration file
$VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

# Set VM operating system parameters
Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $Credential

# Set boot diagnostic storage account
Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    

# The line below replaces Step #8 : Set virtual machine source image
Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

# Set OsDisk configuration
Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

# Set DataDisk configuration
$DataDiskConfig = New-AzDiskConfig -SkuName $DataDiskType -Location $Location -CreateOption Empty -DiskSizeGB $DataDiskSize
$DataDisk = New-AzDisk -DiskName $DataDiskName -Disk $DataDiskConfig -ResourceGroupName $ResourceGroupName
$VMConfig = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -CreateOption Attach -ManagedDiskId $DataDisk.Id -Lun 1

#Step 10: Create Azure Virtual Machine
$VM = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig

#Step 11: Start Azure Virtual Machine
Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

#Copying the Pulic IP into the clipboard 
#$PublicIP.IpAddress | Set-Clipboard

#Step 11: Start RDP Session
mstsc /v $PublicIP.IpAddress