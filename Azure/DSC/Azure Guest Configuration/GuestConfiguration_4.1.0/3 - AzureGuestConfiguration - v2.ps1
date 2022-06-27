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
$ResourcePrefix                     = "dscagc040"
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
$PolicyIni = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.Properties.DisplayName -match "Deploy prerequisites to enable Guest Configuration policies on virtual machines"}
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
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript {$_.KeyName -eq "key1"}).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

#$ContentURI = (Publish-GuestConfigurationPackage -Path $GuestConfigurationPackage.Path -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force).ContentUri
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
  "DisplayName" =  $ConfigurationName
  "Description" =  "Make sure all Windows servers comply with $ConfigurationName"
  "Path" =  './policies'
  "Platform" =  'Windows'
  "PolicyVersion" =  '1.0.0'
  "Mode" =  'ApplyAndAutoCorrect'
  "Verbose" = $true
}
# Create the guest configuration policy
$Policy = New-GuestConfigurationPolicy @Params

$PolicyDefinition = New-AzPolicyDefinition -Name "Ensure [$ConfigurationName] is appplied" -Policy $Policy.Path

$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='true'}# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

$PolicyAssignment = New-AzPolicyAssignment -Name $ConfigurationName -DisplayName "Make sure all servers comply with $ConfigurationName" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  
#$PolicyAssignment = New-AzPolicyAssignment -Name "[Windows]$($ConfigurationName)" -DisplayName "[Windows]$($ConfigurationName)" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -Location $Location -PolicyParameterObject $PolicyParameterObject -EnforcementMode Default -IdentityType SystemAssigned -NonComplianceMessage $NonComplianceMessage  

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
