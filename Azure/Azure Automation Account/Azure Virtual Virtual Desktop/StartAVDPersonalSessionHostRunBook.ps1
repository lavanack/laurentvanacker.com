#requires -Version 3.0 -Modules Az.Accounts, Az.Resources
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
)

$LogAnalyticsWorkspaceId = Get-AutomationVariable -Name LogAnalyticsWorkspaceId

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
        Write-Output -InputObject "`$CurrentLogAnalyticsWorkspaceId: $CurrentLogAnalyticsWorkspaceId"
        #Connection in the last 3 days
        $Query = 'let daysAgo = 3d; WVDConnections | where TimeGenerated > ago(daysAgo) and State == "Connected" | distinct SessionHostName'
        #Connection in the last 28 days summarize by week day. Return the VM only if the connected at least twice for this weekday on the previous 4 weeks.
        #$Query = 'let daysAgo = 28d; WVDConnections | where TimeGenerated > ago(daysAgo) and State == "Connected" | distinct DayOfWeek=dayofweek(TimeGenerated), SessionHostName | summarize count() by DayOfWeek, SessionHostName | where count_>=2'

        Write-Output -InputObject "`$Query: $Query"
        # Run the query
        $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspaceId -Query $Query
        $VMNames = $Result.Results.SessionHostName

        Foreach ($VMName in $VMNames) {
            Write-Output -InputObject "Starting $VMName"                
            Get-AzVM -Name $VMName | Start-AzVM -AsJob
        }
    }
}
