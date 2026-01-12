<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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
#requires -Version 3.0 -Modules Az.Accounts, Az.Resources, Az.OperationalInsights
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
)

$ResourceGroupId = Get-AutomationVariable -Name ResourceGroupId

if ([string]::IsNullOrEmpty($ResourceGroupId)) {
    Write-Output -InputObject "The provider ResourceGroupId is null or empty"
}
else {
    #region Azure connection
    # Ensures you do not inherit an AzContext in your dirbook
    Disable-AzContextAutosave -Scope Process
    # Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
    $AzureContext = (Connect-AzAccount -Identity).context
    Write-Output -InputObject $AzureContext
    # set and store context
    $AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
    Write-Output -InputObject $AzureContext
    #endregion
}
