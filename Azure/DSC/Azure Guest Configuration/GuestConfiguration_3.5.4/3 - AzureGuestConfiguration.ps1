#To run from the Azure VM
#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>
<#
Get-AzPolicyRemediation | Where-Object -FilterScript { $_.Id -like '*dscagc*' } | Remove-AzPolicyRemediation -AllowStop -Verbose
Get-AzPolicyAssignment  | Where-Object -FilterScript { $_.Id -like '*dscagc*' } | Remove-AzPolicyAssignment -Verbose
Get-AzPolicyDefinition  | Where-Object -FilterScript { $_.Id -like '*dscagc*' } | Remove-AzPolicyDefinition -Force -Verbose
#>

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


$Location                           = "EastUs"
#$ResourcePrefix                    = "dscazgcfg"
$ResourcePrefix                     = "dscagc102"
#$resourceGroupName                = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$ResourceGroupName                  = "$ResourcePrefix-rg-$Location"
$StorageAccountName                 = "{0}sa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$StorageContainerName               = "guestconfiguration"
$VMName 	                        = "{0}ws2019" -f $ResourcePrefix
#$ConfigurationName                  = "FileServerBaseline_{0:yyyyMMddHHmmss}" -f (Get-Date)
#$ConfigurationName                  = "CreateAdminUserDSCConfiguration"
$ConfigurationName                  = "{0}_{1:yyyyMMddHHmmss}" -f $VMName, (Get-Date)
$GuestConfigurationPackageName      = "$ConfigurationName.zip"
#$GuestConfigurationPackageFullName  = "$CurrentDir\$ConfigurationName\$GuestConfigurationPackageName"

#region From PowerShell
#region Deploy prerequisites to enable Guest Configuration policies on virtual machines
$PolicyIni = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.Properties.DisplayName -eq "Deploy prerequisites to enable Guest Configuration policies on virtual machines"}
$PolicyIni.Properties.PolicyDefinitions

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$PolicyDefinition = Get-AzPolicySetDefinition -Name $PolicyIni.ResourceName #12794019-7a00-42cf-95c2-882eed337cc8 
$PolicyAssignment = New-AzPolicyAssignment -Name 'deployPrerequisitesForGuestConfigurationPolicies' -DisplayName 'Deploy prerequisites to enable Guest Configuration policies on virtual machines' -Scope $ResourceGroup.ResourceId -PolicySetDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location

# Grant defined roles with PowerShell
$roleDefinitionIds = $PolicyDefinition.Properties.PolicyDefinitions | ForEach-Object -Process {  Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select-Object @{n="roleDefinitionIds";e={$_.Properties.policyRule.then.details.roleDefinitionIds}} } | Select-Object -ExpandProperty roleDefinitionIds -Unique
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}

# Start remediation for every policy definition
$PolicyDefinition.Properties.PolicyDefinitions | ForEach-Object -Process {
  Start-AzPolicyRemediation -Name $_.policyDefinitionReferenceId -PolicyAssignmentId $PolicyAssignment.PolicyAssignmentId -PolicyDefinitionReferenceId $_.policyDefinitionId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
}

Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName
#endregion

#region Our Guest Policy
& "$PSScriptRoot\CreateAdminUserDSCConfiguration.ps1"

# Create a guest configuration package for Azure Policy GCS
$GuestConfigurationPackage = New-GuestConfigurationPackage -Name $ConfigurationName -Configuration './CreateAdminUser/localhost.mof' -Type AuditAndSet -Force

$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
# Creates a new container
$storageAccount | New-AzStorageContainer -Name $StorageContainerName -Permission Blob

# Publish the guest configuration package (zip) to the storage account
$ContentURI = Publish-GuestConfigurationPackage -Path $GuestConfigurationPackage.Path -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force | Select-Object -Expand ContentUri

# Create a Policy Id
$PolicyId = (New-Guid).Guid 
# Define the parameters to create and publish the guest configuration policy
$Params = @{
  "PolicyId" =  $PolicyId
  "ContentUri" =  $ContentURI
  "DisplayName" =  $ConfigurationName
  "Description" =  "Make sure all Windows servers comply with $ConfigurationName"
  "Path" =  './policies'
  "Platform" =  'Windows'
  "Version" =  '1.0.0'
  "Mode" =  'ApplyAndAutoCorrect'
  "Verbose" = $true
}
# Create the guest configuration policy
$Policy = New-GuestConfigurationPolicy @Params
# Publish the guest configuration policy
Publish-GuestConfigurationPolicy -Path './policies'

$PolicyDefinition = Get-AzPolicyDefinition -Name $PolicyId
$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='True'}

$PolicyAssignment = New-AzPolicyAssignment -Name $ConfigurationName -DisplayName "Make sure all servers comply with $ConfigurationName" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  

# Grant defined roles with PowerShell
# https://docs.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources#grant-defined-roles-with-PowerShell
$roleDefinitionIds = $PolicyDefinition.Properties.policyRule.then.details.roleDefinitionIds
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}

$PolicyAssignmentName = ($PolicyAssignment.PolicyAssignmentId -split '/')[-1]
$job = Start-AzPolicyRemediation -AsJob -Name $PolicyAssignmentName -PolicyAssignmentId $PolicyAssignment.PolicyAssignmentId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
$job | Wait-Job | Receive-Job -Keep

#If you want to force an update on the compliance result you can use the following cmdlet instead of waiting for the next trigger : https://docs.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers.
Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -Verbose

# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $PolicyAssignmentName #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $ResourceGroupName | Select-Object -ExpandProperty PolicyAssignments 
#endregion
#endregion
