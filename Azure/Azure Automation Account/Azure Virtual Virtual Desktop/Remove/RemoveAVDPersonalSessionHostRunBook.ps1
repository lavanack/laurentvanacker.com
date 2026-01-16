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

#requires -Version 3.0 -Modules Az.Accounts, Az.Resources
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
	[Parameter(Mandatory = $true)]
	[string[]]$LogAnalyticsWorkspaceId, 
	[Parameter(Mandatory = $true)]
	[string[]]$HostPoolResourceId,
	[Parameter(Mandatory = $false)]
	[int]$DayAgo = 90,
	[Parameter(Mandatory = $false)]
	[boolean]$WhatIf = $true
)


#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given the right permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject "`$AzureContext: $($AzureContext | Select-Object -Property * | Out-string)"
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject "`$AzureContext: $($AzureContext | Select-Object -Property * | Out-string)"
#endregion


#region Parameters
Write-Output -InputObject "`$LogAnalyticsWorkspaceId: $($LogAnalyticsWorkspaceId -join ', ')" 
Write-Output -InputObject "`$DayAgo: $DayAgo" 
Write-Output -InputObject "`$HostPoolResourceId: $($HostPoolResourceId -join ', ')" 
Write-Output -InputObject "`$WhatIf: $WhatIf" 
#endregion

#region WhatIf Mode
if ($WhatIf) {
    Write-Warning -Message "WHATIF MODE ENABLED"                
}
#endregion


#region Getting all Session Hosts but not the excluded one(s)
$SessionHostNames = @()
$HostPoolToProcess = Get-AzWvdHostPool | Where-Object -FilterScript { ($_.Id -in $HostPoolResourceId) } 
Write-Output -InputObject "`$HostPoolToProcess: $($HostPoolToProcess | Select-Object -Property * | Out-string)"
$HostPoolToProcess | ForEach-Object -Process { 
    $HostPool = $_
    Write-Output -InputObject "`$HostPool: $($HostPool | Select-Object -Property * | Out-string)"
    Write-Output -InputObject "`$HostPool Name: $($HostPool.Name)"
    Write-Output -InputObject "`$HostPool Id: $($HostPool.Id)"
    Write-Output -InputObject "`$HostPool ResourceGroupName: $($HostPool.ResourceGroupName)"
    if ([string]::IsNullOrEmpty($HostPool.ResourceGroupName)) {
        Write-Warning -Message "HostPool ResourceGroupName set to an empty value. Getting ResourceGroupName from the ResourceId"
        $ResourceGroupName = $HostPool.Id -replace ".+/resourcegroups/" -replace "/providers/.+"
    }
    else {
        $ResourceGroupName = $HostPool.ResourceGroupName
    }
    Write-Output -InputObject "`$HostPool ResourceGroupName: $ResourceGroupName"
    $HostPoolObject = [PSCustomObject] @{Name=$HostPool.Name; ResourceGroupName = $ResourceGroupName}
    Write-Output -InputObject "`$HostPoolObject: $($HostPoolObject | Select-Object -Property * | Out-string)"
    $SessionHostNames += (Get-AzWvdSessionHost -HostPoolName $HostPool.Name -ResourceGroupName $ResourceGroupName) | Select-Object -Property @{Name="Name"; Expression={$_.ResourceId -replace ".*/"}}, @{Name="ResourceId"; Expression={$_.ResourceId}}, @{Name="HostPool"; Expression={$HostPoolObject}}
} 
Write-Output -InputObject "`$SessionHostNames: $($SessionHostNames | Out-String)"
$SessionHostNameHT = $SessionHostNames | Group-Object -Property Name -AsHashTable -AsString
#endregion
    

#In case we enter multiple LogAnalyticsWorkspace
$NotConnectedVMs = @()
foreach ($CurrentLogAnalyticsWorkspaceId in $LogAnalyticsWorkspaceId) {
    Write-Output -InputObject "`$CurrentLogAnalyticsWorkspaceId: $CurrentLogAnalyticsWorkspaceId"
    #region Session Hosts not connected in the last 90 days
    $Query = "let daysAgo = {0}d; WVDConnections | sort by TimeGenerated asc | limit 1 | where TimeGenerated <= ago(daysAgo) | distinct SessionHostName" -f $DayAgo

    Write-Output -InputObject "`$Query: $Query"
    # Run the query
    $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspaceId -Query $Query
    Write-Output -InputObject "`$Result: $($Result | Out-String)"                
    Write-Output -InputObject "`$Result.Results.SessionHostName: $($Result.Results.SessionHostName -join ', ')"                
    $Result.Results.SessionHostName -replace "\..+$" | ForEach-Object -Process { 
        Write-Output -InputObject "`$_: $_"                
        if ($SessionHostNameHT)  { 
            if ($SessionHostNameHT[$_]) {
                Write-Output -InputObject "No connection in the last $DayAgo days for '$_' ..."                
                $NotConnectedVMs += Get-AzVM -ResourceId $SessionHostNameHT[$_].ResourceId 
            }
            else {
                Write-Output -InputObject "'$_' is not a member of the HostPool(s) to process ..."                
            }
        }
        else {
            Write-Output -InputObject "Nothing to process as not connected session hosts ..."                
        }
    } 
    #endregion 
}
Write-Output -InputObject "`$NotConnectedVMs: $($NotConnectedVMs.Name -join ', ')"                

#region Session Hosts not started in the last 90 days
Write-Output -InputObject "SessionHost Names: $($SessionHostNameHT.Keys -join ', ')"                
$NotStartedVMs = @()
foreach ($SessionHostName in $SessionHostNameHT.Keys) {
    Write-Output -InputObject "`$SessionHostName: $SessionHostName"
    $ResourceId = $SessionHostNameHT[$SessionHostName].ResourceId
    Write-Output -InputObject "`$ResourceId: $ResourceId"
    #Checking if the VM has been started in the last 90 days
    if (Get-AzLog -StartTime ((Get-Date).AddDays(-$DayAgo)) -ResourceId $ResourceId -Status Succeeded | Where-Object { $_.OperationName -eq "Start Virtual Machine" }) {
        Write-Output -InputObject "The '$SessionHostName' has been started in the last $DayAgo days"
    }
    else {
        Write-Output -InputObject "The '$SessionHostName' has NOT been started in the last $DayAgo days"
        $NotStartedVM =  Get-AzVM -ResourceId $ResourceId
        $NotStartedVMs += $NotStartedVM
    }
}
Write-Output -InputObject "`$NotStartedVMs: $($NotStartedVMs.Name -join ', ')"                
#endregion 

[array] $VMs = $NotStartedVMs
foreach ($NotConnectedVM in $NotConnectedVMs) {
    #If a VM has been started in the last 90 days but with no connection we keep it.
    if ($NotConnectedVM -notin $NotStartedVMs) {
        Write-Output -InputObject "'$($NotConnectedVM.Name)' is not in the `$NotStartedVMs list. We exclude it !"                
    }
    else {
        Write-Output -InputObject "Adding '$($NotConnectedVM.Name)' as VM to process !"                
        $VMs += $NotConnectedVM
    }
}


Write-Output -InputObject "`$VMs: $($VMs.Name -join ', ')"                
Foreach ($VM in $VMs) {
    Write-Output -InputObject "Processing '$($VM.Name)' Session Host"                
    $HostPool = $SessionHostNameHT[$VM.Name].HostPool
    if ($WhatIf) {
        Write-Warning -Message "WHATIF: Removing '$($VM.Name)' Session Host from '$($HostPool.Name)' HostPool (ResourceGroup: '$($HostPool.ResourceGroupName)')"                
    }
    else {
        #Normally this command line should be useless (if not connected or started in the last 90 days)
        $VM | Stop-AzVM -Force
        Write-Output -InputObject "`$HostPool: $($HostPool | Select-Object -Property * | Out-string)"
        Write-Output -InputObject "Removing '$($VM.Name)' Session Host from '$($HostPool.Name)' HostPool (ResourceGroup: '$($HostPool.ResourceGroupName)')"                
        Remove-AzWvdSessionHost -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name -Name $VM.Name -Force

        #region NICs
        $VM.NetworkProfile.NetworkInterfaces.Id | ForEach-Object { 
            Write-Output -InputObject "[$($VM.Name)] Removing NIC: '$_'"                
            Remove-AzResource -ResourceId $_ -Force -AsJob 
        }
        #endregion

        #region Disks
        $TimeStamp = '{0:yyyyMMddHHmmss}' -f (Get-Date)
        #region OS Disk
        $VMOSDisk = $VM.StorageProfile.OSDisk.ManagedDisk
        $SnapshotName = "{0}_{1}" -f $VMOSAzDisk.Name, $TimeStamp
        $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $VMOSAzDisk.Id -Location $VM.Location -CreateOption Copy
        Write-Output -InputObject "[$($VM.Name)] Taking a snapshot of the OS Disk"                
        $AzSnapshot = New-AzSnapshot -ResourceGroupName $VM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
        Write-Output -InputObject "[$($VM.Name)] Removing the OS Disk"                
        $VMOSDisk | Get-AzResource | Remove-AzDisk -AsJob -Force
        #endregion

        #region Data Disk
        foreach ($VMDataDisk in $VM.StorageProfile.DataDisks.ManagedDisk.Id) {
            $SnapshotName = "{0}_{1}" -f $VMDataDisk.Name, $TimeStamp
            $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $VMDataDisk.Id -Location $VM.Location -CreateOption Copy
            Write-Output -InputObject "[$($VM.Name)] Taking a snapshot of the '$($VMDataDisk.Name)' Data Disk"                
            $AzSnapshot = New-AzSnapshot -ResourceGroupName $VM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
            Write-Output -InputObject "[$($VM.Name)] Removing the '$($VMDataDisk.Name)' Data Disk"                
            $VMDataDisk | Get-AzResource | Remove-AzDisk -AsJob -Force
        }
        #endregion
        #endregion
    }
}
Write-Output -InputObject "Runbook completed !"