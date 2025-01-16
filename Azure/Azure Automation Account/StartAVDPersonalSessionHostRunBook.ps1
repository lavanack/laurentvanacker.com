#requires -Version 3.0 -Modules Az.Accounts, Az.Resources
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
)

$LogAnalyticsWorkspaceId  = Get-AutomationVariable -Name LogAnalyticsWorkspaceId

if ([string]::IsNullOrEmpty($LogAnalyticsWorkspaceId)) {
    Write-Output -InputObject "The provider LogAnalyticsWorkspaceId is null or empty"
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

    #In case we enter multiple LogAnalyticsWorkspace Ids by using the comma as delimiter
    $LogAnalyticsWorkspaceIds = $LogAnalyticsWorkspaceId -split ','

    foreach ($CurrentLogAnalyticsWorkspaceId in $LogAnalyticsWorkspaceIds) {
        $Query = 'let daysAgo = 3d; WVDConnections | where TimeGenerated > ago(daysAgo) and State == "Connected" | distinct SessionHostName'
        Write-Output -InputObject "`$Query: $Query"
        # Run the query
        $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspaceId -Query $Query
        $VMNames = $Result.Results.SessionHostName

        Foreach ($VMName in $VMNames) {
            Write-Output -InputObject "Starting $($vm.Name)"                
            Get-AzVM -Name $VMName | Start-AzVM -AsJob
        }
    }
}
