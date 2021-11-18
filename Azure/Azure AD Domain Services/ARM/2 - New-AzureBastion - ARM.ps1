#From (with minor changes) https://github.com/Azure/azure-quickstart-templates/tree/master/101-azure-bastion

Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#$TemplateFile = $CurrentScript -replace "\.ps1$",  ".template.json"
$TemplateParameterFile = $CurrentScript -replace "\.ps1$", ".parameters.json"

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDSResourceGroupName = $Settings.AzureADDS.ResourceGroupName.value
$AzureADDomainName = $Settings.AzureAD.DomainName.value
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

# Get the resource group.
Get-AzResourceGroup -Name $AzureADDSResourceGroupName -Location $AzureLocation

#New-AzResourceGroupDeployment -ResourceGroupName $AzureADDSResourceGroupName -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile -Name "Azure_AD_DS_Deployment" -Force -Verbose 
New-AzResourceGroupDeployment -ResourceGroupName $AzureADDSResourceGroupName -TemplateUri https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-azure-bastion/azuredeploy.json -TemplateParameterFile $TemplateParameterFile -Name "Bastion_Deployment" -Force -Verbose 
