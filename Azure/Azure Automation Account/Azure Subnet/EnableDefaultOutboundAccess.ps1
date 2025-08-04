#requires -Version 3.0 -Modules Az.Accounts, Az.Network

Param(
)

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

#region Set Subnet Configuration
foreach ($vNet in Get-AzVirtualNetwork) {
    foreach ($subnet in $vNet.Subnets) {
        if (-not($subnet.DefaultOutboundAccess)) {
            Write-Verbose -Message "Enabling DefaultOutboundAccess for '$($subnet.Name)'"
            $subnet.DefaultOutboundAccess = $true
        }
        else {
            Write-Verbose -Message "DefaultOutboundAccess already enabled for '$($subnet.Name)'"
        }
    }
    $null = Set-AzVirtualNetwork -VirtualNetwork $vNet
}
#endregion