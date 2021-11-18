Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureADAdminUserUpn = $Settings.AzureAD.AdminUserUpn.value
$AzureADDSResourceGroupName = $Settings.AzureADDS.ResourceGroupName.value
$AzureADDSVirtualNetworkName = $Settings.AzureADDS.VirtualNetworkName.value
$AzureLocation = $Settings.Azure.Location.value
$AzureSubscriptionName = $Settings.Azure.SubscriptionName.value
$VMNames = $Settings.VM.Names.value
$VMSize = $Settings.VM.Size.value
$VMStorageAccountSKUName = $Settings.VM.StorageAccount.SKUName.value
$VMStorageAccountName = $Settings.VM.StorageAccount.Name.value
$VMImagePublisherName = $Settings.VM.Image.PublisherName.value
$VMImageOffer = $Settings.VM.Image.Offer.value
$VMImageSKU	= $Settings.VM.Image.SKU.value
$VMOSDiskSize = $Settings.VM.OS.DiskSize.value
$VMOSDiskType = $Settings.VM.OS.DiskType.value

#region Defining credential(s)
$DomainCredential = Get-Credential -Message "Enter the credential for the Domain Admin to join the domain" -UserName $AzureADAdminUserUpn 
$VMCredential = Get-Credential -Message "Enter the credential for the VM Admin"
#endregion
$OUPath = "OU=AADDC Computers"+$($AzureADDomainName -replace '\.|^', ',DC=')

Disconnect-AzAccount
Disconnect-AzureAD

# Login to your Azure subscription.
Connect-AzAccount
$AzureSubscription = Get-AzSubscription -SubscriptionName $AzureSubscriptionName
#Get Tenant matching the specified tenant name
$AzTenant = Get-AzTenant | Where-Object -FilterScript { $AzureADDomainName -in $_.Domains}
Set-AzContext -Subscription $AzureSubscription -Tenant $AzTenant

#Step 1: Create Azure Storage Account
# Remove any previously existing storage accoun.
Remove-AzStorageAccount -Name $VMStorageAccountName -ResourceGroupName $AzureADDSResourceGroupName -Force -ErrorAction Ignore
New-AzStorageAccount -Name $VMStorageAccountName -ResourceGroupName $AzureADDSResourceGroupName -Location $AzureLocation -SKUName $VMStorageAccountSKUName

#Steps 2: Get Azure Virtual network configuration
$vNetwork = Get-AzVirtualNetwork -ResourceGroupName $AzureADDSResourceGroupName -Name $AzureADDSVirtualNetworkName
$Subnet   = Get-AzVirtualNetworkSubnetConfig -Name "ManagementSubnet" -VirtualNetwork $vNetwork


$VMNames | ForEach-Object -Process {
    #region Define Variables needed for Virtual Machine
    $CurrentVMName = $_
    $CurrentNICName = "$CurrentVMName-NIC"
    $CurrentOSDiskName = "$CurrentVMName-OSDisk"
    #endregion

    #Step 3: Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $CurrentNICName -ResourceGroupName $AzureADDSResourceGroupName -Location $AzureLocation -SubnetId $Subnet.Id

    <# Optional : Step 4: Get Virtual Machine publisher, Image Offer, SKU and Image
    $VMImagePublisher = Get-AzVMImagePublisher -Location $AzureLocation| Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsServer"}
    $VMImageOffer = Get-AzVMImageOffer -Location $AzureLocation -publisher $VMImagePublisher.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "WindowsServer"}
    $ImageSKU = Get-AzVMImageSKU -Location  $AzureLocation -publisher $VMImagePublisher.PublisherName -offer $VMImageOffer.Offer | Where-Object -FilterScript { $_.SKUs  -eq "2019-Datacenter"}
    $image = Get-AzVMImage -Location  $AzureLocation -publisher $VMImagePublisher.PublisherName -offer $VMImageOffer.Offer -SKU $VMImageSKU.SKUs | Sort-Object -Property Version -Descending | Select-Object -First 1
    #>

    # Step 5: Create a virtual machine configuration file
    $VMConfig = New-AzVMConfig -VMName $CurrentVMName -VMSize $VMSize
    Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    # Set VM operating system parameters
    Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $CurrentVMName -Credential $VMCredential

    # Set boot diagnostic storage account
    Set-AzVMBootDiagnostic -Enable -ResourceGroupName $AzureADDSResourceGroupName -VM $VMConfig -StorageAccountName $VMStorageAccountName    

    # The line below replaces Step #8 : Set virtual machine source image
    Set-AzVMSourceImage -VM $VMConfig -PublisherName $VMImagePublisherName -Offer $VMImageOffer -SKUs $VMImageSKU -Version 'latest'

    # Set OsDisk configuration
    Set-AzVMOSDisk -VM $VMConfig -Name $CurrentOSDiskName -DiskSizeInGB $VMOSDiskSize -StorageAccountType $VMOSDiskType -CreateOption fromImage

    #Step 6: Create Azure Virtual Machine
    New-AzVM -ResourceGroupName $AzureADDSResourceGroupName -Location $AzureLocation -VM $VMConfig

    #Step 7: Start Azure Virtual Machine
    Start-AzVM -Name $CurrentVMName -ResourceGroupName $AzureADDSResourceGroupName
    #Restart-AzVM -Name $CurrentVMName -ResourceGroupName $AzureADDSResourceGroupName

    #Step 8: Add the VM to the Domain
    #"Add-Computer -DomainName $AzureADDomainName -Credential $($DomainCredential.UserName) -Restart" | Set-ClipBoard
    #Set-AzVMADDomainExtension -DomainName $AzureADDomainName -VMName $CurrentVMName -Credential $DomainCredential -ResourceGroupName $AzureADDSResourceGroupName -JoinOption 0x00000003 -Restart -Verbose
    Set-AzVMADDomainExtension -DomainName $AzureADDomainName -VMName $CurrentVMName -Credential $DomainCredential -ResourceGroupName $AzureADDSResourceGroupName -JoinOption 0x00000003 -OUPath $OUPath -Restart -Verbose 
}