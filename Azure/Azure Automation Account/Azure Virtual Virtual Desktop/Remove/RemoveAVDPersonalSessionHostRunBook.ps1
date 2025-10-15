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
)

$LogAnalyticsWorkspaceId = Get-AutomationVariable -Name LogAnalyticsWorkspaceId
$DayAgo = 90

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


    #region Getting all Session Hosts
    $SessionHostNameHT = Get-AzWvdHostPool | ForEach-Object -Process { 
        $HostPool = $_
        (Get-AzWvdSessionHost -HostPoolName $HostPool.Name -ResourceGroupName $HostPool.ResourceGroupName) | Select-Object -Property @{Name="Name"; Expression={$_.ResourceId -replace ".*/"}}, @{Name="ResourceId"; Expression={$_.ResourceId}}, @{Name="HostPool"; Expression={$HostPool}}
    } | Group-Object -Property Name -AsHashTable -AsString
    #endregion
    

    #In case we enter multiple LogAnalyticsWorkspace Ids by using the comma as delimiter
    $LogAnalyticsWorkspaceIds = $LogAnalyticsWorkspaceId -split ','
    foreach ($CurrentLogAnalyticsWorkspaceId in $LogAnalyticsWorkspaceIds) {
        Write-Output -InputObject "`$CurrentLogAnalyticsWorkspaceId: $CurrentLogAnalyticsWorkspaceId"
        #region Session Hosts not connected in the last 90 days
        $Query = "let daysAgo = {0}d; WVDConnections | sort by TimeGenerated asc | limit 1 | where TimeGenerated <= ago(daysAgo) | distinct SessionHostName" -f $DayAgo

        Write-Output -InputObject "`$Query: $Query"
        # Run the query
        $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $CurrentLogAnalyticsWorkspaceId -Query $Query
        $NotConnectedVMs = $Result.Results.SessionHostName -replace "\..*$" | ForEach-Object -Process { if ($SessionHostNameHT[$_].ResourceId) { Get-AzResource -ResourceId $SessionHostNameHT[$_].ResourceId | Get-AzVM } } 
        Write-Output -InputObject "`$NotConnectedVMs: $($NotConnectedVMs.Name -join ', ')"                
        #endregion 

        #region Session Hosts not started in the last 90 days
        $NotStartedVMs = foreach ($SessionHostName in $SessionHostNameHT.Keys) {
            $ResourceId = $SessionHostNameHT[$SessionHostName].ResourceId
            #Checkinf if the VM has been started in the last 90 days
            if ((Get-AzLog -StartTime ((Get-Date).AddDays(-$DayAgo)) -ResourceId $ResourceId | Where-Object { $_.status -eq "Started" }).ResourceId) {
                Write-Verbose -Message "The '$SessionHostName' has been started in the last $DayAgo days"
            }
            else {
                Write-Verbose -Message "The '$SessionHostName' has NOT been started in the last $DayAgo days"
                $NotStartedVM =  Get-AzResource -ResourceId $ResourceId | Get-AzVM
                $NotStartedVM
            }
        }
        #endregion 

        [array] $VMs = $NotStartedVMs+$NotStartedVMs
        if (-not([string]::IsNullOrEmpty($VMNames))) {
            Foreach ($CurrentVM in $VMs) {
                Write-Output -InputObject "Processing '$($CurrentVM.Name)' Session Host"                
                #Normally this command line should be useless (if not connected or started in the last 90 days)
                $CurrentVM | Stop-AzVM -Force
                $HostPool = $SessionHostNameHT[$VM.Name].HostPool
                Write-Output -InputObject "Removing '$VMName' Session Host from '$($HostPool.Name)' HostPool (ResourceGroup: '$($HostPool.ResourceGroupName)')"                
                Remove-AzWvdSessionHost -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name -Name $CurrentVM.Name -Force

                #region NICs
                $CurrentVM.NetworkProfile.NetworkInterfaces.Id | ForEach-Object { 
                    Write-Output -InputObject "[$VMName] Removing NIC: '$_'"                
                    Remove-AzResource -ResourceId $_ -Force -AsJob 
                }
                #endregion

                #region Disks
                $TimeStamp = '{0:yyyyMMddHHmmss}' -f (Get-Date)
                #region OS Disk
                $VMOSDisk = $CurrentVM.StorageProfile.OSDisk.ManagedDisk
                $SnapshotName = "{0}_{1}" -f $VMOSAzDisk.Name, $TimeStamp
                $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $VMOSAzDisk.Id -Location $CurrentVM.Location -CreateOption Copy
                Write-Output -InputObject "[$VMName] Taking a snapshot of the OS Disk"                
                $AzSnapshot = New-AzSnapshot -ResourceGroupName $CurrentVM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
                Write-Output -InputObject "[$VMName] Removing the OS Disk"                
                $VMOSDisk | Get-AzResource | Remove-AzDisk -AsJob -Force
                #endregion

                #region Data Disk
                foreach ($VMDataDisk in $CurrentVM.StorageProfile.DataDisks.ManagedDisk.Id) {
                    $SnapshotName = "{0}_{1}" -f $VMDataDisk.Name, $TimeStamp
                    $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $VMDataDisk.Id -Location $CurrentVM.Location -CreateOption Copy
                    Write-Output -InputObject "[$VMName] Taking a snapshot of the '$($VMDataDisk.Name)' Data Disk"                
                    $AzSnapshot = New-AzSnapshot -ResourceGroupName $CurrentVM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
                    Write-Output -InputObject "[$VMName] Removing the '$($VMDataDisk.Name)' Data Disk"                
                    $VMDataDisk | Get-AzResource | Remove-AzDisk -AsJob -Force
                }
                #endregion
                #endregion
            }
        }
    }
}
