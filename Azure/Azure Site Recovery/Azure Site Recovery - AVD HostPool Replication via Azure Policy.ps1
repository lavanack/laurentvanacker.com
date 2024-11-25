<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.PolicyInsights, Az.RecoveryServices, Az.Resources, Az.Security, Az.Storage

#From https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-how-to-enable-policy

[CmdletBinding()]
param
(
)

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Login to your Azure subscription.
While (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
$null = Update-AzConfig -DisplayBreakingChangeWarning $false

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString


$PrimaryLocation = "EastUS2"
$PrimaryLocationResourceGroupName = "rg-avd-hp-pd-ad-poc-mp-use2-770"
$PrimaryLocationResourceGroup = Get-AzResourceGroup -Name $PrimaryLocationResourceGroupName -Location $PrimaryLocation

$RecoveryLocation = "CentralUS"
$RecoveryLocationResourceGroupName = $PrimaryLocationResourceGroupName -replace $shortNameHT[$PrimaryLocation].shortName, $shortNameHT[$RecoveryLocation].shortName
$RecoveryLocationResourceGroup = New-AzResourceGroup -Name $RecoveryLocationResourceGroupName -Location $RecoveryLocation

$RecoveryServicesVaultName = $RecoveryLocationResourceGroupName -replace "^rg", "rsv" 
$RecoveryServicesVault = New-AzRecoveryServicesVault -Name $RecoveryServicesVaultName -Location $RecoveryLocation -ResourceGroupName $RecoveryLocationResourceGroupName
#endregion

#region Azure Policy Management
$PolicyDefinition = Get-AzPolicyDefinition | Where-Object -FilterScript { $_.DisplayName -eq "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery" }
$PolicyParameterObject = @{
    SourceRegion          = $PrimaryLocation 
    TargetRegion          = $RecoveryLocation 
    targetResourceGroupId = $RecoveryLocationResourceGroup.ResourceId 
    vaultResourceGroupId  = $RecoveryLocationResourceGroup.ResourceId 
    vaultId               = $RecoveryServicesVault.ID 
    <#
    tagName               = "ASRIncluded"
    tagValue              = "True"
    tagType               = "Inclusion"
    #>
}

$PolicyAssignment = New-AzPolicyAssignment -Name "pa-$($PrimaryLocationResourceGroupName)" -DisplayName "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery (AVD)" -Scope $PrimaryLocationResourceGroup.ResourceId -PolicyDefinition $PolicyDefinition -EnforcementMode Default -IdentityType SystemAssigned -Location $RecoveryLocation -PolicyParameterObject $PolicyParameterObject 

# Grant defined roles to the primary and recovery resource groups with PowerShell
$roleDefinitionIds = $PolicyDefinition | Select-Object @{Name = "roleDefinitionIds"; Expression = { $_.policyRule.then.details.roleDefinitionIds } } | Select-Object -ExpandProperty roleDefinitionIds #-Unique
Start-Sleep -Seconds 30
if ($roleDefinitionIds.Count -gt 0) {
    $roleDefinitionIds | ForEach-Object -Process {
        $roleDefId = $_.Split("/") | Select-Object -Last 1
        if (-not(Get-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId)) {
            New-AzRoleAssignment -Scope $PrimaryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
            New-AzRoleAssignment -Scope $RecoveryLocationResourceGroup.ResourceId -ObjectId $PolicyAssignment.IdentityPrincipalId -RoleDefinitionId $roleDefId
        }
    }
}

Write-Host -Object "Creating remediation for '$($PolicyDefinition.DisplayName)' Policy ..."
$PolicyRemediation = Start-AzPolicyRemediation -Name $PolicyAssignment.Name -PolicyAssignmentId $PolicyAssignment.Id -ResourceGroupName $PrimaryLocationResourceGroup.ResourceGroupName -ResourceDiscoveryMode ReEvaluateCompliance
$PolicyRemediation

Write-Host -Object "Starting Compliance Scan for '$PrimaryLocationResourceGroupName' Resource Group ..."
$PolicyComplianceScan = Start-AzPolicyComplianceScan -ResourceGroupName $PrimaryLocationResourceGroup
$PolicyComplianceScan


# Get the resources in your resource group that are non-compliant to the policy assignment
Get-AzPolicyState -ResourceGroupName $PrimaryLocationResourceGroup -PolicyAssignmentName $PolicyAssignment.Name #-Filter 'IsCompliant eq false'

#Get latest non-compliant policy states summary in resource group scope
Get-AzPolicyStateSummary -ResourceGroupName $PrimaryLocationResourceGroup | Select-Object -ExpandProperty PolicyAssignments 
#endregion