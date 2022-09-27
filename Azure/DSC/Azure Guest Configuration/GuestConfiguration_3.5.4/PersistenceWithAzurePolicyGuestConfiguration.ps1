<#More info on 
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


#region From Windows PowerShell
#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

#Installing VSCode with Powershell extension
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }" -Verbose

#region Disabling IE Enhanced Security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force
#endregion

Start-Process -FilePath pwsh
#endregion


#region From PowerShell
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module -Name Az.Accounts, Az.Resources, Az.Compute, Az.PolicyInsights -Force

Connect-AzAccount
Get-AzSubscription | Out-GridView -PassThru | Select-AzSubscription

Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
$vm = Get-AzVM -ResourceGroupName AzurePolicy -Name winguest
Update-AzVM -ResourceGroupName AzurePolicy -VM $vm -IdentityType SystemAssigned

$PolicyIni = Get-AzPolicySetDefinition | ?  { $_.Properties.DisplayName -match "Deploy prerequisites to enable guest configuration policies on virtual machines"}
$PolicyIni.Properties.PolicyDefinitions

$ResourceGroup = Get-AzResourceGroup -Name "AzurePolicy"
$Definition = Get-AzPolicySetDefinition -Name 12794019-7a00-42cf-95c2-882eed337cc8 # Deploy prerequisites to enable guest configuration policies on virtual machines
$Assignment = New-AzPolicyAssignment -Name 'deployPrerequisitesForGuestConfigurationPolicies' -DisplayName 'Deploy prerequisites to enable guest configuration policies on virtual machines' -Scope $ResourceGroup.ResourceId -PolicySetDefinition $Definition -EnforcementMode Default -IdentityType SystemAssigned -Location 'West Europe'

# Grant defined roles with PowerShell
$roleDefinitionIds = $Definition.Properties.PolicyDefinitions | % {  Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select @{n="roleDefinitionIds";e={$_.Properties.policyRule.then.details.roleDefinitionIds}} } | Select-Object -ExpandProperty roleDefinitionIds -Unique
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $Assignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}

# Start remediation for every policy definition
$Definition.Properties.PolicyDefinitions | % {
  Start-AzPolicyRemediation -Name $_.policyDefinitionReferenceId -PolicyAssignmentId $Assignment.PolicyAssignmentId -PolicyDefinitionReferenceId $_.policyDefinitionId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
}

Start-AzPolicyComplianceScan -ResourceGroupName 'AzurePolicy'

Install-Module -Name GuestConfiguration -RequiredVersion 3.5.4 -Force
Install-Module -Name 'PSDesiredStateConfiguration','PSDscResources' -Force

& "$PSScriptRoot\CreateAdminUserDSCConfiguration.ps1"

# Create a guest configuration package for Azure Policy GCS
New-GuestConfigurationPackage `
  -Name 'ISO1773' `
  -Configuration './CreateAdminUser/localhost.mof' `
  -Type AuditAndSet  `
  -Force

  
# Create a storage account with a random name and a storage container
$StorageAccountName = "azurepolicycfg$(Get-Random)"
New-AzStorageAccount -ResourceGroupName AzurePolicy -Name $StorageAccountName -SkuName 'Standard_LRS' -Location 'West Europe' | New-AzStorageContainer -Name guestconfiguration -Permission Blob

# Publish the guest configuration package (zip) to the storage account
$ContentURI = Publish-GuestConfigurationPackage -Path './ISO1773/ISO1773.zip' -ResourceGroupName AzurePolicy -StorageAccountName $StorageAccountName -Force | Select-Object -Expand ContentUri
# Create a Policy Id
$PolicyId = $(New-GUID)
# Define the parameters to create and publish the guest configuration policy
$Params = @{
  "PolicyId" =  $PolicyId
  "ContentUri" =  $ContentURI
  "DisplayName" =  'ISO 1337'
  "Description" =  'Make sure all servers comply with ISO 1337'
  "Path" =  './policies'
  "Platform" =  'Windows'
  "Version" =  '1.0.1'
  "Mode" =  'ApplyAndAutoCorrect'
  "Verbose" = $true
}
# Create the guest configuration policy
New-GuestConfigurationPolicy @Params
# Publish the guest configuration policy
Publish-GuestConfigurationPolicy -Path './policies'

$ResourceGroup = Get-AzResourceGroup -Name "AzurePolicy"
# $PolicyId = "0ad52941-d75c-4eaa-b092-10f93c354d04"
$Definition = Get-AzPolicyDefinition -Name $PolicyId
$Assignment = New-AzPolicyAssignment -Name 'ISO1337' -DisplayName 'Make sure all Windows servers comply with ISO 1337' -Scope $ResourceGroup.ResourceId -PolicyDefinition $Definition -EnforcementMode Default -IdentityType SystemAssigned -Location 'West Europe'
# Grant defined roles with PowerShell
# https://docs.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources#grant-defined-roles-with-PowerShell
$roleDefinitionIds = $Definition.Properties.policyRule.then.details.roleDefinitionIds
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $Assignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}
Start-AzPolicyRemediation -Name 'deployWinGuestExtension' -PolicyAssignmentId $Assignment.PolicyAssignmentId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
#endregion
