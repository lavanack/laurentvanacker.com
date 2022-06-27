#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


$Location                           = "EastUs"
#$ResourcePrefix                    = "dscazgcfg"
$ResourcePrefix                     = "dscagc033"
#$resourceGroupName                = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$ResourceGroupName                  = "$ResourcePrefix-rg-$Location"
$StorageAccountName                 = "{0}sa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$StorageContainerName               = "guestconfiguration"
$VMName 	                        = "{0}ws2019" -f $ResourcePrefix
$ConfigurationName                  = "{0}_FileServerBaseline" -f $VMName
$GuestConfigurationPackageName      = "$ConfigurationName.zip"
$GuestConfigurationPackageFullName  = "$CurrentDir\$GuestConfigurationPackageName"
$GuestConfigurationPolicyFullName   = ".\policies"

#region From PowerShell
#region Deploy prerequisites to enable Guest Configuration policies on virtual machines
$PolicyIni = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.Properties.DisplayName -match "Deploy prerequisites to enable Guest Configuration policies on virtual machines"}
$PolicyIni.Properties.PolicyDefinitions

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$Definition = Get-AzPolicySetDefinition -Name $PolicyIni.ResourceName #12794019-7a00-42cf-95c2-882eed337cc8 
$Assignment = New-AzPolicyAssignment -Name 'deployPrerequisitesForGuestConfigurationPolicies' -DisplayName 'Deploy prerequisites to enable Guest Configuration policies on virtual machines' -Scope $ResourceGroup.ResourceId -PolicySetDefinition $Definition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location

# Grant defined roles with PowerShell
$roleDefinitionIds = $Definition.Properties.PolicyDefinitions | ForEach-Object -Process {  Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select-Object @{n="roleDefinitionIds";e={$_.Properties.policyRule.then.details.roleDefinitionIds}} } | Select-Object -ExpandProperty roleDefinitionIds -Unique
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        #$roleDefId = (Get-AzRoleDefinition -Name "Guest Configuration Resource Contributor").Id
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $Assignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}

# Start remediation for every policy definition
$Definition.Properties.PolicyDefinitions | ForEach-Object -Process {
  Start-AzPolicyRemediation -Name $_.policyDefinitionReferenceId -PolicyAssignmentId $Assignment.PolicyAssignmentId -PolicyDefinitionReferenceId $_.policyDefinitionId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
}

Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName
#endregion

#region Our Guest Policy
#region Example 1
<#
& "$PSScriptRoot\CreateAdminUserDSCConfiguration.ps1"

New-GuestConfigurationPackage `
 -Name $ConfigurationName `
# -Path $CurrentDir `
 -Configuration $CurrentDir\CreateAdminUser\localhost.mof `
 -Type AuditAndSet `
 -Force
#endregion
#>
#region Example 2
& "$PSScriptRoot\LocalRegistryDSCConfiguration.ps1"

New-GuestConfigurationPackage `
 -Name $ConfigurationName `
 -Configuration $CurrentDir\LocalRegistry\localhost.mof `
 -Type AuditAndSet `
 -Force `
 -Verbose
#endregion


$ComplianceStatus = Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackageFullName
$ComplianceStatus.resources.reasons
#Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackageFullName -Verbose
#Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackageFullName


$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
# Creates a new resource group, storage account, and container
$storageAccount | New-AzStorageContainer -Name $StorageContainerName -Permission Blob
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript {$_.KeyName -eq "key1"}).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

#$ContentURI = (Publish-GuestConfigurationPackage -Path $GuestConfigurationPackageFullName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force).ContentUri
Set-AzStorageBlobContent -Container $StorageContainerName -File $GuestConfigurationPackageFullName -Blob $GuestConfigurationPackageName -Context $Context -Force
#Adding a 3-year expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddYears(3)
$ContentURI = New-AzStorageBlobSASToken -Context $Context -FullUri -Container $StorageContainerName -Blob $GuestConfigurationPackageName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      

$PolicyId = (New-Guid).Guid  


$Policy = New-GuestConfigurationPolicy `
  -PolicyId $PolicyId `
  -ContentUri $ContentURI `
  -DisplayName $ConfigurationName `
  -Description 'Compliance check for File Server Baseline' `
  -Path $GuestConfigurationPolicyFullName `
  -Platform 'Windows' `
  -PolicyVersion "1.0.0" `
  -Mode 'ApplyAndAutoCorrect' -Verbose

$PolicyDefinition = New-AzPolicyDefinition -Name "Ensure [$ConfigurationName] is appplied" -Policy $Policy.Path

# Create the policy assignment with the built-in definition against your resource group
$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$PolicyParameterObject = @{'IncludeArcMachines'='true'}# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

#$PolicyAssignment = New-AzPolicyAssignment -Name 'auditandset-fileserverbaseline' -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -Location $Location -PolicyParameterObject $PolicyParameterObject -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  
$PolicyAssignment = New-AzPolicyAssignment -Name "[Windows]$($ConfigurationName)" -DisplayName "[Windows]$($ConfigurationName)" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -Location $Location -PolicyParameterObject $PolicyParameterObject -EnforcementMode Default -IdentityType SystemAssigned -NonComplianceMessage $NonComplianceMessage  
# Grant defined roles with PowerShell
# https://docs.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources#grant-defined-roles-with-PowerShell
# https://github.com/Azure/azure-powershell/issues/10196#issuecomment-575393990 for the following lines
## Extract the RoleID and ObjectID
$roleDefinitionIds = $PolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
$objectID = [GUID]($PolicyAssignment.Identity.principalId)
Start-Sleep 15
## Create a role assignment from the previous information
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = [GUID]($_.Split("/") | Select-Object -Last 1)
        #$roleDefId = (Get-AzRoleDefinition -Name "Guest Configuration Resource Contributor").Id
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $objectID -RoleDefinitionId $roleDefId
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
