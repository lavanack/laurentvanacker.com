# From (with minor changes) https://portal.azure.com/#blade/Microsoft_Azure_WVD/WvdManagerMenuBlade/overview
Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureSubscriptionName = $Settings.Azure.SubscriptionName.value
$AzureLocation = $Settings.Azure.Location.value
$WVDTokenExpirationTime = $Settings.WVD.TokenExpirationTime.value
$WVDResourceGroupName = $Settings.WVD.ResourceGroupName.value


#$TemplateFile = Join-Path -Path $CurrentDir -ChildPath "template.json"
#$TemplateParameterFile = Join-Path -Path $CurrentDir -ChildPath "parameters.json"
$TemplateFile = $CurrentScript -replace "\.ps1$",  ".template.json"
$TemplateParameterFile = $CurrentScript -replace "\.ps1$", ".parameters.json"

$TemplateParameterObject = Get-Content $TemplateParameterFile | ConvertFrom-Json

($TemplateParameterObject.parameters).PSObject.Properties | Select Name, @{Name="Value";Expression={$_.value.value}}  | ForEach-Object -Begin {$TemplateParameterObject =@{}} -Process {$TemplateParameterObject["$($_.Name)"]=$_.Value} -end {$TemplateParameterObject}

#region Defining credential(s)
$administratorAccountCredential = Get-Credential -Message "Enter the credential for the Domain Admin to join the domain" -UserName $TemplateParameterObject["administratorAccountUsername"]
$TemplateParameterObject["administratorAccountPassword"] = $administratorAccountCredential.Password
$TemplateParameterObject["TokenExpirationTime"] = $((Get-Date).ToUniversalTime().AddHours($WVDTokenExpirationTime).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
#Using the same resource group for the workspace
$TemplateParameterObject["workspaceResourceGroup"] = $WVDResourceGroupName

#endregion

# Login to your Azure subscription.
Connect-AzAccount
$AzureSubscription = Get-AzSubscription -SubscriptionName $AzureSubscriptionName
#Get Tenant matching the specified tenant name
$AzTenant = Get-AzTenant | Where-Object -FilterScript { $AzureADDomainName -in $_.Domains}
Set-AzContext -Subscription $AzureSubscription -Tenant $AzTenant

# Connect to your Azure AD directory.
#Connect-AzureAD -TenantId  $AzTenant.Id


$ResourceGroup = Get-AzResourceGroup -Name $WVDResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup)
{
    #Step 0: Remove previously existing Azure Resource Group with the "WVD-RG" name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

# Create Resource Groups and Storage Account for diagnostic
New-AzResourceGroup -Name $WVDResourceGroupName -Location $AzureLocation

#New-AzResourceGroup -Name $AzureADDSResourceGroupName -Location $AzureLocation #use this command when you need to create a new resource group for your deployment
New-AzResourceGroupDeployment -ResourceGroupName $WVDResourceGroupName -TemplateFile $TemplateFile -TemplateParameterObject $TemplateParameterObject -Name "WVD_Deployment" -Force -Verbose 