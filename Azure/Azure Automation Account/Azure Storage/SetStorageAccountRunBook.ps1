#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
)

#region Azure Connection
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject $AzureContext
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject $AzureContext
#endregion

#region Set Storage Account Configuration
$ResourceGroupName = Get-AutomationVariable -Name ResourceGroupName
$Name = Get-AutomationVariable -Name Name
$IPAddressOrRange = Get-AutomationVariable -Name IPAddressOrRange

Set-AzStorageAccount -ResourceGroupName $ResourceGroupName1 -Name $Name -PublicNetworkAccess Enabled -AllowSharedKeyAccess $true -NetworkRuleSet (@{ipRules = (@{IPAddressOrRange = $IPAddressOrRange; Action = "allow" }); defaultAction = "deny" })
#endregion