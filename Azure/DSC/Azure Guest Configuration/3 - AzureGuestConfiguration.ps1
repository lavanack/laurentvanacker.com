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
$ResourcePrefix                     = "dscagc006"
#$resourceGroupName                = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$ResourceGroupName                  = "$ResourcePrefix-rg-$Location"
$StorageAccountName                 = "{0}sa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$VMName 	                        = "{0}ws2019" -f $ResourcePrefix
$ConfigurationName                  = "FileServerBaseline_$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
#$ConfigurationName                  = "CreateAdminUserDSCConfiguration"
$GuestConfigurationPackageName      = "$ConfigurationName.zip"
$GuestConfigurationPackageFullName  = "$CurrentDir\$GuestConfigurationPackageName"


#region Adding the GuestConfiguration extension
$VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
#Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -Type 'ConfigurationforWindows' -Name 'AzurePolicyforWindows' -TypeHandlerVersion 1.0 -ResourceGroupName $ResourceGroupName -Location $Location -VMName $VMName -EnableAutomaticUpgrade $true
$VM | Update-AzVM -IdentityType SystemAssigned -Verbose
#endregion


$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 

#$PolicyIni = Get-AzPolicySetDefinition | ?  { $_.Properties.DisplayName -match "Deploy prerequisites to enable guest configuration policies on virtual machines"}
#$PolicyIni.Properties.PolicyDefinitions

# Deploy prerequisites to enable guest configuration policies on virtual machines
$Definition = Get-AzPolicySetDefinition -Name 12794019-7a00-42cf-95c2-882eed337cc8 
$Assignment = New-AzPolicyAssignment -Name 'deployPrerequisitesForGuestConfigurationPolicies' -DisplayName 'Deploy prerequisites to enable guest configuration policies on virtual machines' -Scope $ResourceGroup.ResourceId -PolicySetDefinition $Definition -EnforcementMode Default -IdentityType SystemAssigned -Location 'West Europe'

# Grant defined roles with PowerShell
$roleDefinitionIds = $Definition.Properties.PolicyDefinitions | ForEach-Object {  Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select @{Name="roleDefinitionIds";Expression={$_.Properties.policyRule.then.details.roleDefinitionIds}} } | Select-Object -ExpandProperty roleDefinitionIds -Unique
Start-Sleep 15
if ($roleDefinitionIds.Count -gt 0)
{
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $Assignment.Identity.PrincipalId -RoleDefinitionId $roleDefId
    }
}

# Start remediation for every policy definition
$Definition.Properties.PolicyDefinitions | ForEach-Object {
  Start-AzPolicyRemediation -Name $_.policyDefinitionReferenceId -PolicyAssignmentId $Assignment.PolicyAssignmentId -PolicyDefinitionReferenceId $_.policyDefinitionId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
}



$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
# Creates a new resource group, storage account, and container
$storageAccount | New-AzStorageContainer -Name guestconfiguration -Permission Blob
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript {$_.KeyName -eq "key1"}).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

#Install-Module -Name PSDesiredStateConfiguration -AllowClobber -Force
<#
& "$CurrentDir\AzureGuestDSCConfiguration.ps1"
New-GuestConfigurationPackage -Name $ConfigurationName  -Path $CurrentDir -Configuration $CurrentDir\LocalRegistry\localhost.mof -Type AuditAndSet -Force
#>
& "$CurrentDir\CreateAdminUserDSCConfiguration.ps1"
New-GuestConfigurationPackage -Name $ConfigurationName  -Path $CurrentDir -Configuration $CurrentDir\CreateAdminUser\localhost.mof -Type AuditAndSet -Force
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackageFullName
#Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackageFullName -Verbose
#Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackageFullName

#$ContentURI = (Publish-GuestConfigurationPackage -Path $GuestConfigurationPackageFullName -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force).ContentUri
Set-AzStorageBlobContent -Container "guestconfiguration" -File $GuestConfigurationPackageFullName -Blob $GuestConfigurationPackageName -Context $Context -Force
#Adding a 3-year expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddYears(3)
$ContentURI = New-AzStorageBlobSASToken -Context $Context -FullUri -Container guestconfiguration -Blob $GuestConfigurationPackageName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      

#Removing any existing policy definition and assignment
Remove-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -Scope $ResourceGroup.ResourceId -Verbose
Remove-AzPolicyDefinition -Name $ConfigurationName -Force
#Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq $ConfigurationName } | Remove-AzPolicyDefinition -Force

$Guid = (New-Guid).Guid

Remove-Item -Path '.\policies' -Recurse -Force -ErrorAction Ignore
New-GuestConfigurationPolicy -PolicyId $Guid -ContentUri $ContentURI -DisplayName $ConfigurationName -Description 'Compliance check for File Server Baseline' -Path './policies' -Platform 'Windows' -PolicyVersion $([System.Version]::Parse("1.0.0")) -Mode 'ApplyAndAutoCorrect' -Verbose
$Policy = Get-ChildItem -Path '.\policies' -Filter "$($ConfigurationName)*.json" -File
New-AzPolicyDefinition -Name $ConfigurationName -Policy $Policy
#Publish-GuestConfigurationPolicy -Path '.\policies' -Verbose

#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
# Register the resource provider if it's not already registered
Register-AzResourceProvider -ProviderNamespace 'Microsoft.PolicyInsights'

# Get a referenace to the built-in policy definition to assign
$PolicyDefinition = Get-AzPolicyDefinition | Where-Object { $_.Name -eq $ConfigurationName }

# Create the policy assignment with the built-in definition against your resource group
$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines'='true'}
#$PolicyAssignment = New-AzPolicyAssignment -Name 'auditandset-fileserverbaseline' -DisplayName $ConfigurationName -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  
$PolicyAssignment = New-AzPolicyAssignment -Name "$($ConfigurationName)Assignment" -DisplayName "$($ConfigurationName)Assignment" -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -EnforcementMode Default -IdentityType "SystemAssigned" -NonComplianceMessage $NonComplianceMessage  
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
        New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $objectID -RoleDefinitionId $roleDefId
    }
}

#Listing returned policy assignments to include all assignments related to the given scope, including those from ancestor scopes and those from descendent scopes.
Get-AzPolicyAssignment -Scope $ResourceGroup.ResourceId  -IncludeDescendent

#Starting a policy remediation for a policy assignment
Start-AzPolicyRemediation -Name "$($ConfigurationName)Remediation" -PolicyAssignmentId $PolicyAssignment.PolicyAssignmentId -ResourceGroupName $ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance

#If you want to force an update on the compliance result you can use the following cmdlet instead of waiting for the next trigger : https://docs.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers.
Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -Verbose

# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName "$($ConfigurationName)Assignment" #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $ResourceGroupName | Select-Object -ExpandProperty PolicyAssignments 