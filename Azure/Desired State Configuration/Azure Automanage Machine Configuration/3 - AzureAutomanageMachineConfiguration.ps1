﻿#To run from the Azure VM
#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>
<#
#Cleaning up previous tests 
Get-AzResourceGroup -Name dscagc* | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyRemediation | Remove-AzPolicyRemediation -AllowStop -AsJob -Verbose | Wait-Job
Get-AzResourceGroup -Name dscagc* | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyAssignment  | Where-Object -FilterScript { $_.ResourceGroupName -like '*dscagc*' } | Remove-AzPolicyAssignment -Verbose #-Whatif
Get-AzPolicyDefinition | Where-Object -filterScript {$_.Properties.metadata.category -eq "Guest Configuration" -and $_.Properties.DisplayName -like "*CreateAdminUserDSCConfiguration*"} | Remove-AzPolicyDefinition -Verbose -Force #-WhatIf
#>


Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$VMName 	                        = $env:COMPUTERNAME
$AzVM                               = Get-AzVM -Name $VMName 
$Location                           = $AzVM.Location
$ResourceGroupName                  = $AzVM.ResourceGroupName
$StorageAccount                     = Get-AzStorageAccount -ResourceGroupName $resourceGroupName
$StorageAccountName                 = $StorageAccount.StorageAccountName
$StorageContainerName               = "guestconfiguration"
$ConfigurationName                  = "CreateAdminUserDSCConfiguration"
$GuestConfigurationPackageName      = "$ConfigurationName.zip"
#$GuestConfigurationPackageFullName  = "$CurrentDir\$ConfigurationName\$GuestConfigurationPackageName"

#region From PowerShell
#region Deploy prerequisites to enable Guest Configuration policies on virtual machines

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$PolicyDefinition = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.Properties.DisplayName -eq "Deploy prerequisites to enable Guest Configuration policies on virtual machines"}
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
	Write-Host -Object "Creating remediation for Policy $($_.policyDefinitionReferenceId)"
    Start-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignment.PolicyAssignmentId -PolicyDefinitionReferenceId $_.policyDefinitionReferenceId -Name $_.policyDefinitionReferenceId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
}

Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName
#endregion


#region Our Guest Policy
& "$PSScriptRoot\$ConfigurationName.ps1"

# Create a guest configuration package for Azure Policy GCS
$GuestConfigurationPackage = New-GuestConfigurationPackage -Name $ConfigurationName -Configuration './CreateAdminUser/localhost.mof' -Type AuditAndSet -Force

# Creates a new container
$storageAccount | New-AzStorageContainer -Name $StorageContainerName -Permission Blob
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript {$_.KeyName -eq "key1"}).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

Set-AzStorageBlobContent -Container $StorageContainerName -File $GuestConfigurationPackage.Path -Blob $GuestConfigurationPackageName -Context $Context -Force
#Adding a 3-year expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddYears(3)
$ContentURI = New-AzStorageBlobSASToken -Context $Context -FullUri -Container $StorageContainerName -Blob $GuestConfigurationPackageName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      

# Create a Policy Id
$PolicyId = (New-Guid).Guid  
# Define the parameters to create and publish the guest configuration policy
$Params = @{
  "PolicyId" =  $PolicyId
  "ContentUri" =  $ContentURI
  "DisplayName" = "[Windows] Make sure all Windows servers comply with $ConfigurationName DSC Configuration"
  "Description" = "[Windows] Make sure all Windows servers comply with $ConfigurationName DSC Configuration"
  "Path" =  './policies'
  "Platform" =  'Windows'
  "PolicyVersion" =  '1.0.0'
  "Mode" =  'ApplyAndAutoCorrect'
  "Verbose" = $true
}
# Create the guest configuration policy
$Policy = New-GuestConfigurationPolicy @Params

$PolicyDefinition = New-AzPolicyDefinition -Name "[Windows] $ConfigurationName" -Policy $Policy.Path

$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='true'}# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

$PolicyAssignment = New-AzPolicyAssignment -Name $ConfigurationName -DisplayName "[Windows] Make sure all Windows servers comply with $ConfigurationName DSC Configuration" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  

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
Write-Host -Object "Creating remediation for Policy '$($PolicyDefinition.Properties.DisplayName)'"
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