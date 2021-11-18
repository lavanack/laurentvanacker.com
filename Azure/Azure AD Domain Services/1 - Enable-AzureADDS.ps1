# Based (with minor changes) from https://docs.microsoft.com/en-us/azure/active-directory-domain-services/powershell-create-instance#complete-powershell-script
Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$AADDCAdministratorsGroupName = "AAD DC Administrators"

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureADAdminUserUpn = $Settings.AzureAD.AdminUserUpn.value
$AzureADDSResourceGroupName = $Settings.AzureADDS.ResourceGroupName.value
$AzureADDSVirtualNetworkName = $Settings.AzureADDS.VirtualNetworkName.value
$AzureADDSNetworkSecurityGroupName = $Settings.AzureADDS.NetworkSecurityGroupName.value
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

$AzureSubscriptionId = $AzureSubscription.Id

# Login to your Azure AD
Connect-AzureAD -TenantId $AzTenant.Id

# Create the service principal for Azure AD Domain Services.
$AzureADServicePrincipal = Get-AzureADServicePrincipal | Where-Object -FilterScript { $_.AppId -eq "2565bd9d-da50-47d4-8b85-4c97f669dc36"}
if (-not($AzureADServicePrincipal)) {
    New-AzureADServicePrincipal -AppId "2565bd9d-da50-47d4-8b85-4c97f669dc36"
}
else 
{
    Write-Output "Another object with the same value for property servicePrincipalNames already exists."
}

# First, retrieve the object ID of the 'AAD DC Administrators' group.
$GroupObjectId = Get-AzureADGroup -Filter "DisplayName eq 'AAD DC Administrators'" | Select-Object ObjectId

# Create the delegated administration group for Azure AD Domain Services if it doesn't already exist.
if (!$GroupObjectId) 
{
    $GroupObjectId = New-AzureADGroup -DisplayName $AADDCAdministratorsGroupName -Description "Delegated group to administer Azure AD Domain Services" -SecurityEnabled $true -MailEnabled $false -MailNickName "AADDCAdministrators"
}
else 
{
    Write-Output "$AADDCAdministratorsGroupName group already exists."
}

# Now, retrieve the object ID of the user you'd like to add to the group.
$UserObjectId = Get-AzureADUser -Filter "UserPrincipalName eq '$AzureADAdminUserUpn'" | Select-Object ObjectId

# Add the user to the 'AAD DC Administrators' group.
# Create the service principal for Azure AD Domain Services.
$AzureADUserMembership = (Get-AzureADUserMembership -ObjectId $UserObjectId.ObjectId).DisplayName
if ($AADDCAdministratorsGroupName -notin $AzureADUserMembership) 
{
    Add-AzureADGroupMember -ObjectId $GroupObjectId.ObjectId -RefObjectId $UserObjectId.ObjectId -ErrorAction Ignore
}
else 
{
    Write-Output "$AzureADAdminUserUpn is already a member of this Azure AD Group"
}

# Register the resource provider for Azure AD Domain Services with Resource Manager.
Register-AzResourceProvider -ProviderNamespace Microsoft.AAD

# Remove any previously existing resource group.
Remove-AzResourceGroup -Name $AzureADDSResourceGroupName -Force -ErrorAction Ignore

# Create the resource group.
New-AzResourceGroup -Name $AzureADDSResourceGroupName -Location $AzureLocation

# Create the dedicated subnet for AAD Domain Services.
$SubnetName = "DomainServicesSubnet"
$AaddsSubnet = New-AzVirtualNetworkSubnetConfig `
  -Name $SubnetName `
  -AddressPrefix 10.0.0.0/24

$WorkloadSubnet = New-AzVirtualNetworkSubnetConfig `
  -Name "WorkloadSubnet" `
  -AddressPrefix 10.0.1.0/24

$BastionSubnet = New-AzVirtualNetworkSubnetConfig `
  -Name "AzureBastionSubnet" `
  -AddressPrefix 10.0.2.0/24

$ManagementSubnet = New-AzVirtualNetworkSubnetConfig `
  -Name "ManagementSubnet" `
  -AddressPrefix 10.0.3.0/24

# Create the virtual network in which you will enable Azure AD Domain Services.
$Vnet=New-AzVirtualNetwork `
  -ResourceGroupName $AzureADDSResourceGroupName `
  -Location $AzureLocation `
  -Name $AzureADDSVirtualNetworkName `
  -AddressPrefix 10.0.0.0/16 `
  -Subnet $AaddsSubnet,$BastionSubnet,$WorkloadSubnet,$ManagementSubnet
  
# Create a rule to allow inbound TCP port 443 traffic for synchronization with Azure AD
$nsg101 = New-AzNetworkSecurityRuleConfig `
    -Name AllowSyncWithAzureAD `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 101 `
    -SourceAddressPrefix AzureActiveDirectoryDomainServices `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 443

# Create a rule to allow inbound TCP port 3389 traffic from Microsoft secure access workstations for troubleshooting
$nsg201 = New-AzNetworkSecurityRuleConfig -Name AllowRD `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 201 `
    -SourceAddressPrefix CorpNetSaw `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 3389

# Create a rule to allow TCP port 5986 traffic for PowerShell remote management
$nsg301 = New-AzNetworkSecurityRuleConfig -Name AllowPSRemoting `
    -Access Allow `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 301 `
    -SourceAddressPrefix AzureActiveDirectoryDomainServices `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 5986

# Create the network security group and rules
$nsg = New-AzNetworkSecurityGroup -Name $AzureADDSNetworkSecurityGroupName `
    -ResourceGroupName $AzureADDSResourceGroupName `
    -Location $AzureLocation `
    -SecurityRules $nsg101,$nsg201,$nsg301

# Get the existing virtual network resource objects and information
$vnet = Get-AzVirtualNetwork -Name $AzureADDSVirtualNetworkName -ResourceGroupName $AzureADDSResourceGroupName
$subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $SubnetName
$addressPrefix = $subnet.AddressPrefix

# Associate the network security group with the virtual network subnet
Set-AzVirtualNetworkSubnetConfig -Name $SubnetName `
    -VirtualNetwork $vnet `
    -AddressPrefix $addressPrefix `
    -NetworkSecurityGroup $nsg
$vnet | Set-AzVirtualNetwork

# Enable Azure AD Domain Services for the directory.
New-AzResource -ResourceId "/subscriptions/$AzureSubscriptionId/resourceGroups/$AzureADDSResourceGroupName/providers/Microsoft.AAD/DomainServices/$AzureADDomainName" `
  -ApiVersion "2017-06-01" `
  -Location $AzureLocation `
  -Properties @{"DomainName"=$AzureADDomainName; `
    "SubnetId"="/subscriptions/$AzureSubscriptionId/resourceGroups/$AzureADDSResourceGroupName/providers/Microsoft.Network/virtualNetworks/$AzureADDSVirtualNetworkName/subnets/$SubnetName"} `
  -Force -Verbose

#Final manual steps : Update DNS Server Settings for the Azure virtual network as explained on https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#update-dns-settings-for-the-azure-virtual-network
Write-Host "First final manual step: Update DNS Server Settings for the Azure virtual network as explained on https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#update-dns-settings-for-the-azure-virtual-network" -ForegroundColor Red
Write-Host "Second final manual step: Reset the password for $AzureADAdminUserUpn and connect to https://myapps.microsoft.com as $AzureADAdminUserUpn to change the password to force the password synchronization with ADDS. cf. https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#enable-user-accounts-for-azure-ad-ds" -ForegroundColor Red
Start-Process "https://myapps.microsoft.com"
Write-Host "Third optional final manual step: Grant access to the Azure AD Domain Services to the user(s)/group(s) you want"  