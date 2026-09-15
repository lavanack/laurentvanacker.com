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

#Alternative to the "Monitoring Azure Local" instructions from https://jumpstart.azure.com/azure_jumpstart_localbox/using_localbox
#requires -Version 5 #-Modules Az.Accounts, Az.Resources, Az.OperationalInsights, Az.Monitor

[CmdletBinding(PositionalBinding = $false)]
param
(
)

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Login to your Azure subscription.
# Keep prompting until the Az context can issue an access token.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

#region ResourceGroup Selection
$ResourceGroup = Get-AzResourceGroup -ResourceGroupName rg-az-local-*

#Selecting only one ResourceGroup
if ($ResourceGroup.Count -gt 1) {
    $ResourceGroup = $ResourceGroup | Out-GridView -OutputMode Single -PassThru
}
#endregion

#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
$Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
$ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
#endregion

#region Variables
$SubscriptionId = (Get-AzContext).Subscription.Id
$ClusterName = "localboxcluster"
$LogAnalyticsWorkSpaceName = "LocalBox-Workspace"
$LADestinationDestinationName = "LogAnalyticsWorkspace"
$Location = $ResourceGroup.Location
$ResourceGroupNamePrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName

$DataCollectionRuleName = $ResourceGroup.ResourceGroupName -replace $ResourceGroupNamePrefix, "azurestackhci-dcr"
$DataCollectionEndpointName = $ResourceGroup.ResourceGroupName -replace $ResourceGroupNamePrefix, "dce"
#endregion

#region Azure Local resource
$ClusterResourceId = @(
    $ResourceGroup.ResourceId
    "providers/Microsoft.AzureStackHCI/clusters/$ClusterName"
) -join "/"

Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ClusterResourceId: $ClusterResourceId)"
$Cluster = Get-AzResource -ResourceId $ClusterResourceId
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Cluster: $($Cluster | Out-String))"
#endregion

#region Log Analytics Workspace
$Parameters = @{
    ResourceGroupName = $ResourceGroup.ResourceGroupName 
    Name = $LogAnalyticsWorkSpaceName
}
$LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace @Parameters
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$LogAnalyticsWorkSpace: $($LogAnalyticsWorkSpace | Out-String))"
#endregion

#region Data Collection Endpoint
$Parameters = @{
    ResourceGroupName = $ResourceGroup.ResourceGroupName 
    Name = $DataCollectionEndpointName
}
$DataCollectionEndpoint = Get-AzDataCollectionEndpoint @Parameters -ErrorAction Ignore
    
if (-not($DataCollectionEndpoint)) {
    $Parameters['Location'] = $Location
    $DataCollectionEndpoint = New-AzDataCollectionEndpoint -Name $DataCollectionEndpointName
}

Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionEndpoint: $($DataCollectionEndpoint | Out-String))"
#endregion

#region Data Collection Rule
$Parameters = @{
    Stream = "Microsoft-InsightsMetrics"
    Destination = $LogAnalyticsWorkSpace.Name

}
$DataFlow = New-AzDataFlowObject @Parameters
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataFlow: $($DataFlow | Out-String))"

$Parameters = @{
    Name = $LogAnalyticsWorkSpace.Name
    WorkspaceResourceId = $LogAnalyticsWorkSpace.ResourceId
}
$DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject @Parameters
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Destination: $($DestinationLogAnalytic | Out-String))"


$Parameters = @{
    ResourceGroupName = $ResourceGroup.ResourceGroupName
    Name = $DataCollectionRuleName
}
$DataCollectionRule = Get-AzDataCollectionRule @Parameters -ErrorAction Ignore
    
if (-not($DataCollectionRule)) {
    $Parameters['Location'] = $Location
    $Parameters['DataCollectionEndpointId'] = $DataCollectionEndpoint.Id
    $Parameters['DataFlow'] = $DataFlow
    $Parameters['DestinationLogAnalytic'] = $DestinationLogAnalytic
    $Parameters['Kind'] = "Windows"
    $DataCollectionRule = New-AzDataCollectionRule @Parameters
}
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRule: $($DataCollectionRule | Out-String))"

#region Associate DCR with Azure Local
$Parameters = @{
    ResourceGroupName = $DataCollectionRule.ResourceGroupName
    DataCollectionRuleName = $DataCollectionRule.Name
}
$Association = Get-AzDataCollectionRuleAssociation @Parameters -ErrorAction Ignore

if (-not($Association)) {
    #Current Target Resources of the DCR Association 
    $TargetResources = $Association.Id -replace ".*/machines/" -replace "/providers/.*"
    #AzureArcMachines in the ResourceGroup
    $AzureArcMachines = $(Get-AzConnectedMachine -ResourceGroupName $ResourceGroup.ResourceGroupName)
    #If not the same one(s)
    $Compare = Compare-Object -ReferenceObject $AzureArcMachines.Name -DifferenceObject $TargetResources
    if ($null -ne $Compare) {
        $NonAssociatedMachines = ($Compare | Where-Object -FilterScript { $_.SideIndicator -eq "<="}).InputObject
        $ToAssociate = $AzureArcMachines | Where-Object -FilterScript {$_.Name -in $NonAssociatedMachines}
        foreach ($TargetResourceId in $ToAssociate) {
            $AssociationName = "dra_{0}" -f $((New-Guid).Guid)
            $Parameters = @{
                TargetResourceId = $TargetResource.Id
                AssociationName = $AssociationName
                RuleId = $DataCollectionRule.Id
            }
            $DataCollectionRuleAssociation = New-AzDataCollectionRuleAssociation @Parameters
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DataCollectionRuleAssociation: $($DataCollectionRuleAssociation | Out-String))"
        }
    }
}

#endregion
#endregion
#endregion
