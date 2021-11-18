#From (with minor changes) https://docs.microsoft.com/en-us/azure/bastion/bastion-create-host-powershell
Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureBastionResourceGroupName = $Settings.Bastion.ResourceGroupName.value
$AzureBastionPublicIpAddressName = $Settings.Bastion.PublicIpAddressName.value
$AzureBastionName = $Settings.Bastion.Name.value
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureADDSVirtualNetworkName = $Settings.AzureADDS.VirtualNetworkName.value
$AzureLocation = $Settings.Azure.Location.value
$AzureSubscriptionName = $Settings.Azure.SubscriptionName.value

Disconnect-AzAccount
Disconnect-AzureAD

# Login to your Azure subscription.
Connect-AzAccount
$AzureSubscription = Get-AzSubscription -SubscriptionName $AzureSubscriptionName
#Get Tenant matching the specified tenant name
$AzTenant = Get-AzTenant | Where-Object -FilterScript { $AzureADDomainName -in $_.Domains}
Set-AzContext -Subscription $AzureSubscription -Tenant $AzTenant

# Connect to your Azure AD directory.
#Connect-AzureAD -TenantId  $AzTenant.Id

# Remove any previously existing resource group.
Remove-AzResourceGroup -Name $AzureBastionResourceGroupName -Force -ErrorAction Ignore

# Create the resource group.
New-AzResourceGroup `
  -Name $AzureBastionResourceGroupName `
  -Location $AzureLocation


$vnet = Get-AzVirtualNetwork -Name $AzureADDSVirtualNetworkName 
$subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $Vnet -Name "AzureBastionSubnet"

$publicip = New-AzPublicIpAddress -ResourceGroupName $AzureBastionResourceGroupName -name $AzureBastionPublicIpAddressName -location $AzureLocation -AllocationMethod Static -Sku Standard
$AzureBastion = New-AzBastion -ResourceGroupName $AzureBastionResourceGroupName -Name $AzureBastionName -PublicIpAddress $publicip -VirtualNetwork $vnet
