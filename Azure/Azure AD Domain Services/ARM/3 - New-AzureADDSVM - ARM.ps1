#From https://docs.microsoft.com/en-us/azure/active-directory-domain-services/join-windows-vm-template#join-an-existing-windows-server-vm-to-a-managed-domain
#From https://azure.microsoft.com/en-us/resources/templates/201-vm-domain-join/

Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
$AzureADDomainName = $Settings.AzureAD.DomainName.value
$AzureADAdminUserUpn = $Settings.AzureAD.AdminUserUpn.value
$AzureADDSResourceGroupName = $Settings.AzureADDS.ResourceGroupName.value
$AzureADDSVirtualNetworkName = $Settings.AzureADDS.VirtualNetworkName.value
$AzureADDSManagementSubnetName = $Settings.AzureADDS.ManagementSubnetName.value
$AzureLocation = $Settings.Azure.Location.value
$AzureSubscriptionName = $Settings.Azure.SubscriptionName.value
$VMNames = $Settings.VM.Names.value
$VMSize = $Settings.VM.Size.value

#region Defining credential(s)
$DomainCredential = Get-Credential -Message "Enter the credential for the Domain Admin to join the domain" -UserName $AzureADAdminUserUpn 
$VMCredential = Get-Credential -Message "Enter the credential for the VM Admin"
#endregion
$OUPath = "OU=AADDC Computers"+$($AzureADDomainName -replace '\.|^', ',DC=')

# Login to your Azure subscription.
Connect-AzAccount
$AzureSubscription = Get-AzSubscription -SubscriptionName $AzureSubscriptionName
#Get Tenant matching the specified tenant name
$AzTenant = Get-AzTenant | Where-Object -FilterScript { $AzureADDomainName -in $_.Domains}
Set-AzContext -Subscription $AzureSubscription -Tenant $AzTenant

# Connect to your Azure AD directory.
#Connect-AzureAD -TenantId  $AzTenant.Id

$VMNames | ForEach-Object -Process {
    $CurrentVMName = $_
    $TemplateParameterObject = @{
        existingVNETName = $AzureADDSVirtualNetworkName
        existingSubnetName = $AzureADDSManagementSubnetName
        dnsLabelPrefix = $CurrentVMName
        vmSize = $VMSize
        domainToJoin = $AzureADDomainName
        domainUsername = $DomainCredential.UserName
        domainPassword = $DomainCredential.Password
        ouPath = $OUPath
        domainJoinOptions = 3
        vmAdminUsername = $VMCredential.UserName
        vmAdminPassword = $VMCredential.Password
        location = $AzureLocation
    }

    #New-AzResourceGroup -Name $AzureADDSResourceGroupName -Location $AzureLocation #use this command when you need to create a new resource group for your deployment
    New-AzResourceGroupDeployment -ResourceGroupName $AzureADDSResourceGroupName -TemplateUri https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/201-vm-domain-join/azuredeploy.json -TemplateParameterObject $TemplateParameterObject -Name "ADDS_VM_Deployment" -Force -Verbose 
}