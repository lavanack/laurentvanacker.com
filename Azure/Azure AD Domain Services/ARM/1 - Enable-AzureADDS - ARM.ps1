# Based for v1 template (with minor changes) from https://github.com/Azure/azure-quickstart-templates/tree/master/101-AAD-DomainServices#predeployment
# Based for v2 template (with minor changes) from https://docs.microsoft.com/fr-fr/azure/active-directory-domain-services/template-create-instance

Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$AADDCAdministratorsGroupName = "AAD DC Administrators"
#$TemplateFile = $CurrentScript -replace "\.ps1$",  ".template.json"
#$TemplateParameterFile = $CurrentScript -replace "\.ps1$", ".parameters.json"
$TemplateFile = $CurrentScript -replace "\.ps1$",  "v2.template.json"
$TemplateParameterFile = $CurrentScript -replace "\.ps1$", "v2.parameters.json"


$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureADAdminUserUpn = $Settings.AzureAD.AdminUserUpn.value
$AzureADDSResourceGroupName = $Settings.AzureADDS.ResourceGroupName.value
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

New-AzResourceGroupDeployment -ResourceGroupName $AzureADDSResourceGroupName -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile -Name "Azure_AD_DS_Deployment" -Force -Verbose 

#Final manual steps : Update DNS Server Settings for the Azure virtual network as explained on https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#update-dns-settings-for-the-azure-virtual-network
Write-Host "First final manual step: Update DNS Server Settings for the Azure virtual network as explained on https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#update-dns-settings-for-the-azure-virtual-network" -ForegroundColor Red
Write-Host "Second final manual step: Reset the password for $AzureADAdminUserUpn and connect to https://myapps.microsoft.com as $AzureADAdminUserUpn to change the password to force the password synchronization with ADDS. cf. https://docs.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-create-instance#enable-user-accounts-for-azure-ad-ds" -ForegroundColor Red
Start-Process "https://myapps.microsoft.com"
Write-Host "Third optional final manual step: Grant access to the Azure AD Domain Services to the user(s)/group(s) you want"