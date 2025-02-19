#To run from the Azure VM
#requires -Version 7 -RunAsAdministrator 

<#More info on 
- https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026
- https://cloudbrothers.info/en/azure-persistence-azure-policy-guest-configuration/
#>
<#
#Cleaning up previous tests 
Get-AzResourceGroup -Name rg-dsc-amc* | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyRemediation | Remove-AzPolicyRemediation -AllowStop -AsJob -Verbose | Wait-Job
Get-AzResourceGroup -Name rg-dsc-amc* | Select-Object -Property @{Name="Scope"; Expression={$_.ResourceID}} | Get-AzPolicyAssignment  | Where-Object -FilterScript { $_.ResourceGroupName -like 'rg-dsc-amc*' } | Remove-AzPolicyAssignment -Verbose #-Whatif
Get-AzPolicyDefinition | Where-Object -filterScript {$_.metadata.category -eq "Guest Configuration" -and $_.DisplayName -like "*ExampleConfiguration*"} | Remove-AzPolicyDefinition -Force -Verbose #-WhatIf
Get-AzResourceGroup -Name rg-dsc-amc* | Remove-AzResourceGroup -AsJob -Force -Verbose 
#>
*#region Function defintions
#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}
#endregion

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent


#region Connection to Azure and Subscription selection
if (-not(Get-AzContext)) {
    Connect-AzAccount -UseDeviceAuthentication
    #Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}

$AzVM = Get-AzVMCompute
$Location = $AzVM.Location
$ResourceGroupName = $AzVM.ResourceGroupName
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName
$StorageAccountName = $StorageAccount.StorageAccountName
$StorageContainerName = "guestconfiguration"
$ConfigurationName = "ExampleConfiguration"
$GuestConfigurationPackageFileName = "$ConfigurationName.zip"
$GuestConfigurationPackageFilePath = Join-Path -Path $CurrentDir -ChildPath $GuestConfigurationPackageFileName -Resolve
#endregion

#region Deploy prerequisites to enable Guest Configuration policies on virtual machines

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
$PolicySetDefinition = Get-AzPolicySetDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Deploy prerequisites to enable Guest Configuration policies on virtual machines" }
$PolicyAssignment = New-AzPolicyAssignment -Name "$($resourceGroupName)-deployPrereqForGuestConfigurationPolicies" -DisplayName 'Deploy prerequisites to enable Guest Configuration policies on virtual machines' -Scope $ResourceGroup.ResourceId -PolicySetDefinition $PolicySetDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location

# Grant defined roles with PowerShell
$roleDefinitionIds = $PolicySetDefinition.PolicyDefinition | ForEach-Object -Process { Get-AzPolicyDefinition -Id $_.policyDefinitionId | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } } | Select-Object -ExpandProperty roleDefinitionIds -Unique
Start-Sleep -Seconds 30
if ($roleDefinitionIds.Count -gt 0) {
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        if (-not(Get-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
            New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
        }
    }
}

$Jobs = @() 
# Start remediation for every policy definition
$PolicySetDefinition.PolicyDefinition | ForEach-Object -Process {
    Write-Host -Object "Creating remediation for '$($_.policyDefinitionReferenceId)' Policy ..."
    $Jobs += Start-AzPolicyRemediation -PolicyAssignmentId $PolicyAssignment.Id -PolicyDefinitionReferenceId $_.policyDefinitionReferenceId -Name $_.policyDefinitionReferenceId -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob
}
$remediation = $Jobs | Receive-Job -Wait -AutoRemoveJob
$remediation

Write-Host -Object "Starting Compliance Scan for '$ResourceGroupName' Resource Group ..."
$Job = Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -AsJob
#endregion


#region Our Guest Policy
# Testing the configuration
Get-GuestConfigurationPackageComplianceStatus -Path $GuestConfigurationPackageFilePath
#Set-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -AllowBlobPublicAccess $true
# Applying the Machine Configuration Package locally
#Start-GuestConfigurationPackageRemediation -Path $GuestConfigurationPackageFilePath -Verbose

# Creates a new container
if (-not($storageAccount | Get-AzStorageContainer -Name $StorageContainerName -ErrorAction Ignore)) {
    $storageAccount | New-AzStorageContainer -Name $StorageContainerName -Permission Blob
}
$StorageAccountKey = (($storageAccount | Get-AzStorageAccountKey) | Where-Object -FilterScript { $_.KeyName -eq "key1" }).Value
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"

Set-AzStorageBlobContent -Container $StorageContainerName -File $GuestConfigurationPackageFilePath -Blob $GuestConfigurationPackageFileName -Context $Context -Force
#Adding a 3-year expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddYears(3)
$ContentURI = New-AzStorageBlobSASToken -Context $Context -FullUri -Container $StorageContainerName -Blob $GuestConfigurationPackageFileName -Permission rwd -StartTime $StartTime -ExpiryTime $ExpiryTime      

# Create a Policy Id
$PolicyId = (New-Guid).Guid  
# Define the parameters to create and publish the guest configuration policy
$Params = @{
    "PolicyId"      = $PolicyId
    "ContentUri"    = $ContentURI
    "DisplayName"   = "[Linux] $ResourceGroupName - Make sure all Linux servers comply with $ConfigurationName DSC Config."
    "Description"   = "[Linux] $ResourceGroupName - Make sure all Linux servers comply with $ConfigurationName DSC Config."
    "Path"          = './policies'
    "Platform"      = 'Linux'
    "PolicyVersion" = '1.0.0'
    "Mode"          = 'ApplyAndAutoCorrect'
    "Verbose"       = $true
}
# Create the guest configuration policy
$Policy = New-GuestConfigurationPolicy @Params

$PolicyDefinition = New-AzPolicyDefinition -Name "[Lin]$ResourceGroupName-$ConfigurationName" -Policy $Policy.Path

$NonComplianceMessage = [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.Policy.NonComplianceMessage]::new()
$NonComplianceMessage.message = "Non Compliance Message"
$IncludeArcConnectedServers = @{'IncludeArcMachines' = 'true' }# <- IncludeArcMachines is important - given you want to target Arc as well as Azure VMs

$PolicyAssignment = New-AzPolicyAssignment -Name "$($ResourceGroupName)-$($ConfigurationName)" -DisplayName "[Linux] $ResourceGroupName - Make sure all Linux servers comply with $ConfigurationName DSC Config." -Scope $ResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $Location -PolicyParameterObject $IncludeArcConnectedServers -NonComplianceMessage $NonComplianceMessage  

# Grant defined roles with PowerShell
# https://docs.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources#grant-defined-roles-with-PowerShell
$roleDefinitionIds = $PolicyDefinition.policyRule.then.details.roleDefinitionIds
Start-Sleep -Seconds 30
if ($roleDefinitionIds.Count -gt 0) {
    $roleDefinitionIds | ForEach-Object {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        if (-not(Get-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
            New-AzRoleAssignment -Scope $resourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
        }
    }
}

Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy ..."
$Jobs = Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $ResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance -AsJob
$PolicyRemediation = $Jobs | Wait-Job | Receive-Job #-Keep
$PolicyRemediation

#If you want to force an update on the compliance result you can use the following cmdlet instead of waiting for the next trigger : https://docs.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data#evaluation-triggers.
Write-Host -Object "Starting Compliance Scan for '$ResourceGroupName' Resource Group ..."
Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName -Verbose

# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $ResourceGroupName -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $ResourceGroupName | Select-Object -ExpandProperty PolicyAssignments 
#endregion
#endregion

$Job | Receive-Job -Wait -AutoRemoveJob