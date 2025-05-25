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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.OperationalInsights, Az.ResourceGraph

[CmdletBinding()]
param
(
    [parameter(Mandatory = $true)]
    [string] $LogAnalyticsWorkSpaceId,
    [switch]$Force,
    [switch]$Wait
)

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion


<#
#region Graph
$Query = @'
// This will by default return only hosts without a user assigned to it. If you want to return both unassigned and assigned
// hosts then comment out line '|where isempty(assignedUser)'

//remove comment on '| summarize totalsessionhostsinpool' if you want to have the second view in screenshot 
// which provides a summary count

Resources
| where type == "microsoft.desktopvirtualization/hostpools"
| where properties.hostPoolType == 'Personal'
| extend hostpoolId = toupper(id), hostpoolType = properties.hostPoolType, name, type, location, hostpoolProperties = properties
| join kind=inner (
        desktopvirtualizationresources
        | where type == "microsoft.desktopvirtualization/hostpools/sessionhosts"
        | extend sessionhostId = toupper(id), type, properties.allowNewSession, properties.assignedUser, properties.sessions, sessionhostProperties = properties
        | project sessionhostId = toupper(trim_end(@'\/sessionhosts\/.*$', id)), hostpoolName = trim_end(@'\/.*$',name), sessionhostName = trim_start(@'^.*\/', name), allowNewSession = properties.allowNewSession, assignedUser = properties.assignedUser, currentSessions = properties.sessions, sessionhostProperties, vmresourceId = properties.resourceId)
    on $left.hostpoolId == $right.sessionhostId
//| summarize totalSessionhostsinPool = count(assignedUser), unassignedSessionhostCount = count(isempty(assignedUser)), assignedSessionhostCount = count(isnotempty(assignedUser)) by hostpoolName
| where currentSessions == 0
| project hostpoolId, hostpoolName = name, sessionhostName, hostpoolType, resourceGroup, assignedUser, currentSessions, allowNewSession, sessionhostProperties, hostpoolProperties, vmresourceId
'@
$Result = Search-AzGraph -Query $Query
$SessionHosts = $Result | Select-Object -Property @{Name = "ResourceGroupName"; Expression = { $_.resourceGroup } }, @{Name = "Name"; Expression = { $_.sessionhostName -replace "\..*" } }
#endregion
#>

#region Log Analytics Workspace
#Query for listing the Azure VM with an inactive session in the last 5 minutes
$Query = @"
WVDAgentHealthStatus
| where TimeGenerated > ago(5m) and InactiveSessions == 1
| distinct tostring(split(SessionHostName, '.', 0)[0]), tostring(split(SessionHostResourceId, '/', 4)[0])
| project-rename Name=SessionHostName_0, ResourceGroupName=SessionHostResourceId_0
"@

$Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspaceId -Query $Query
$SessionHosts = $Result.Results
#endregion 

$AzRunningVMs = (($SessionHosts | Get-AzVM -Status) | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") } )
if (-not([string]::IsNullOrEmpty($AzRunningVMs))) {
    Write-Host -Object "The following VMs will be hibernated :`r`n$($AzRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
    $Jobs = $AzRunningVMs | Stop-AzVM -Hibernate -Force -AsJob -Verbose
    if ($Wait) {
        Write-Host -Object "Waiting the hibernation jobs complete ..."
        $null = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue
    }
    else {
        $Jobs
    }

    if ($Force) {
        Write-Host -Object "Waiting the hibernation jobs complete ..."
        $null = $Jobs | Receive-Job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue
        $AzRunningVMs = (($SessionHosts | Get-AzVM -Status) | Where-Object -FilterScript { ($_.Statuses.code -eq "PowerState/running") -and ($_.Statuses.DisplayStatus -eq "VM running") })

        if (-not([string]::IsNullOrEmpty($AzRunningVMs))) {
            Write-Warning -Message "The following VMs will be shutdown :`r`n$($AzRunningVMs | Select-Object -Property ResourceGroupName, Name | Out-String)"
            $Jobs = $AzRunningVMs | Stop-AzVM -Force -AsJob -Verbose
            if ($Wait) {
                Write-Host -Object "Waiting the shutdown jobs complete ..."
                $null = $Jobs | Receive-Job -Wait -AutoRemoveJob #-ErrorAction SilentlyContinue
            }
            else {
                $Jobs
            }
        }
    }
}
#endregion