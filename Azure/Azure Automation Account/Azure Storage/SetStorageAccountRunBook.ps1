#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
)

$ResourceGroupName = Get-AutomationVariable -Name ResourceGroupName
$Name = Get-AutomationVariable -Name Name
$IPAddressOrRange = Get-AutomationVariable -Name IPAddressOrRange

Write-Output -InputObject "`$ResourceGroupName : $ResourceGroupName"
Write-Output -InputObject "`$Name : $Name"
Write-Output -InputObject "`$IPAddressOrRange : $IPAddressOrRange"

#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject $AzureContext
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject $AzureContext
#endregion


#region Set Storage Account Configuration
Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $Name -PublicNetworkAccess Enabled -AllowSharedKeyAccess $true -NetworkRuleSet (@{ipRules = (@{IPAddressOrRange = $IPAddressOrRange; Action = "allow" }); defaultAction = "deny" })
#endregion