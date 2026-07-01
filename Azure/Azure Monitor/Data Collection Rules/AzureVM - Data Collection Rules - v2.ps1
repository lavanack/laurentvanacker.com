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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Storage, Az.Resources

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12,122)]
        [int] $minLength = 12, ## characters
        [ValidateRange(13,123)]
        [ValidateScript({$_ -gt $minLength})]
        [int] $maxLength = 15, ## characters
        [switch] $AsSecureString,
        [switch] $ClipBoard,
        [Parameter(ParameterSetName = 'GeneratePassword')]
        [int] $nonAlphaChars = 3,
        [Parameter(ParameterSetName = 'DinoPass')]
        [switch] $Online
    )
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/faq#what-are-the-password-requirements-when-creating-a-vm-
    $ProhibitedPasswords = @('abc@123', 'iloveyou!', 'P@$$w0rd', 'P@ssw0rd', 'P@ssword123', 'Pa$$word', 'pass@word1', 'Password!', 'Password1', 'Password22')
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    Do {
        if ($Online) {
            $URI = "https://www.dinopass.com/password/custom?length={0}&useSymbols=true&useNumbers=true&useCapitals=true" -f $length
            $RandomPassword = Invoke-RestMethod -Uri $URI
        }
        else {
            Add-Type -AssemblyName 'System.Web'
            $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        }
    } Until (($RandomPassword  -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W')))

    #Write-Host -Object "The password is : $RandomPassword"
    if ($ClipBoard) {
        #Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Azure Resource Creation
$Location = "CentralUS"
$ResourceGroupName = "rg-dcr-test-usc-001"
$LogAnalyticsWorkSpaceName = "log{0}" -f $($ResourceGroupName -replace "\W")
$null = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore | Remove-AzResourceGroup -Force
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
$LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroupName -Force
$VMNb = 2

#region Defining credential(s)
$Username = $env:USERNAME
$SecurePassword = New-RandomPassword -Online -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$PSAzureOperationResponses = 1.. $VMNb | ForEach-Object -Process {
    $VMName = "vmdcrtestusc{0:D3}" -f $_
    $Parameters = @{
        Name              = $VMName
        Size              = "Standard_D2s_v5"
        Credential        = $Credential 
        ResourceGroupName = $ResourceGroupName 
        Image             = 'Win2022AzureEdition'
        Priority          = 'Spot'
    }
    New-AzVM @Parameters | Set-AzVMBootDiagnostic -Enable | Update-AzVM 
}
$VMs = Get-AzVM -ResourceGroupName $ResourceGroupName
#endregion

#region Data Collection Rules
#region Event Logs
#Levels : 1 = Critical, 2 = Error or Failure, 3 = Warning
$EventLogs = @(
    [PSCustomObject] @{EventLogName = 'Application'; Levels = 1, 2, 3 }
    [PSCustomObject] @{EventLogName = 'System'; Levels = 1, 2, 3 }
    [PSCustomObject] @{EventLogName = 'Security'; Keywords = "4503599627370496" }
    [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Levels = 1, 2, 3 }
    [PSCustomObject] @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'; Levels = 1, 2, 3 }
    [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; Levels = 1, 2, 3 }
    [PSCustomObject] @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; Levels = 1, 2, 3 }
)
#Building the XPath for each event log
$XPathQuery = foreach ($CurrentEventLog in $EventLogs) {
    #Building the required level for each event log
    $Levels = foreach ($CurrentLevel in $CurrentEventLog.Levels) {
        "Level={0}" -f $CurrentLevel
    }
    "{0}!*[System[($($Levels -join ' or '))]]" -f $CurrentEventLog.EventLogName
}
$WindowsEventLogs = New-AzWindowsEventLogDataSourceObject -Name WindowsEventLogsDataSource -Stream Microsoft-Event -XPathQuery $XPathQuery
#endregion

#region Performance Counters
#From https://github.com/AzaryaShaulov/AVD/blob/main/AVD-SessionHost-Insights/AVD-Insights-Enable-PerfMetricsDCR.ps1
$PerformanceCounters = @(
    # CPU
    [PSCustomObject] @{ObjectName = 'Processor Information'; CounterName = '% Processor Time'; InstanceName = '_Total'; IntervalSeconds = 30 }
    #Memory
    [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Available Mbytes'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Page Faults/sec'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Memory'; CounterName = 'Pages/sec'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Memory'; CounterName = '% Committed Bytes In Use'; InstanceName = '*'; IntervalSeconds = 30 }
	# Disk - Capacity (per-volume for C: and other drives)
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = '% Free Space'; InstanceName = '*'; IntervalSeconds = 30 }
    # Disk - Latency (per-volume and per-physical-disk)
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = 'C:'; IntervalSeconds = 60 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
    # Disk - Queue
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 60 }
    [PSCustomObject] @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 60 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
    # AVD Session Quality - User Input Delay
    [PSCustomObject] @{ObjectName = 'User Input Delay per Process'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'User Input Delay per Session'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
    # AVD Session Quality - RemoteFX Network
    [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current TCP RTT'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Current UDP Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
    # AVD Session Quality - RemoteFX Graphics (GPU hosts)
    [PSCustomObject] @{ObjectName = 'RemoteFX Network'; CounterName = 'Average Encoding Time'; InstanceName = '*'; IntervalSeconds = 30 }
    # AVD Session Lifecycle - Terminal Services
    [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Active Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
    [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Inactive Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
    [PSCustomObject] @{ObjectName = 'Terminal Services'; CounterName = 'Total Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
    # Network - Bandwidth (bytes per second)
    [PSCustomObject] @{ObjectName = 'Network Adapter'; CounterName = 'Bytes Total/sec'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Network Adapter'; CounterName = 'Bytes Received/sec'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Network Adapter'; CounterName = 'Bytes Sent/sec'; InstanceName = '*'; IntervalSeconds = 30 }
    [PSCustomObject] @{ObjectName = 'Network Adapter'; CounterName = 'Current Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
    # Network - Queue
    [PSCustomObject] @{ObjectName = 'Network Adapter'; CounterName = 'Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
)

#Building and Hashtable for each Performance Counters where the key is the sample interval
$PerformanceCountersHT = $PerformanceCounters | Group-Object -Property IntervalSeconds -AsHashTable -AsString

$PerformanceCounters = foreach ($CurrentKey in $PerformanceCountersHT.Keys) {
    $Name = "PerformanceCounters{0}" -f $CurrentKey
    #Building the Performance Counter paths for each Performance Counter
    $CounterSpecifier = foreach ($CurrentCounter in $PerformanceCountersHT[$CurrentKey]) {
        "\{0}({1})\{2}" -f $CurrentCounter.ObjectName, $CurrentCounter.InstanceName, $CurrentCounter.CounterName
    }
    New-AzPerfCounterDataSourceObject -Name $Name -Stream Microsoft-Perf -CounterSpecifier $CounterSpecifier -SamplingFrequencyInSecond $CurrentKey
}
#endregion

#region Data Collection Rule
<#
$DataCollectionEndpointName = "dce-{0}" -f $LogAnalyticsWorkSpace.Name
$DataCollectionEndpoint = New-AzDataCollectionEndpoint -Name $DataCollectionEndpointName -ResourceGroupName $ResourceGroupName -Location $Location -NetworkAclsPublicNetworkAccess Enabled
#>
#From https://www.reddit.com/r/AZURE/comments/1ddac0z/avd_insights_dcr_does_not_appear/?tl=fr
$DataCollectionRuleName = "microsoft-avdi-{0}" -f $LogAnalyticsWorkSpace.Location
$DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics, Microsoft-Perf, Microsoft-Event -Destination $LogAnalyticsWorkSpace.Name
$DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
$DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $ResourceGroupName -Location $Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounters -DataSourceWindowsEventLog $WindowsEventLogs -DestinationLogAnalytic $DestinationLogAnalytic #-DataCollectionEndpointId $DataCollectionEndpoint.Id
#endregion
#endregion
#endregion

#region Adding Data Collection Rule Association for every VM
#$DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $ResourceGroupName -RuleName $DataCollectionRuleName
$DataCollectionRuleAssociations = foreach ($VM in $VMs) {
    <#
    $AssociationName = 'configurationAccessEndpoint'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionEndpoint.Name)' Data Collection Endpoint with the '$($VM.Name)' Session Host "
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
    New-AzDataCollectionRuleAssociation -ResourceUri $VM.ResourceId -AssociationName $AssociationName #-DataCollectionEndpointId $DataCollectionEndpoint.Id
    #>
    #$AssociationName = "dcr-{0}" -f $($VM.ResourceId -replace ".*/").ToLower()
    $AssociationName = "{0}-VMInsights-Dcr-Association" -f $($VM.Id -replace ".+/").ToLower()
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the '$($DataCollectionRule.Name)' Data Collection Rule with the '$($VM.Name)' Session Host "
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AssociationName: $AssociationName"
    New-AzDataCollectionRuleAssociation -ResourceUri $VM.Id -AssociationName $AssociationName -DataCollectionRuleId $DataCollectionRule.Id
}
#endregion

#region Enable VM insights on Virtual Machine(s)
#From http://aka.ms/OnBoardVMInsights
#From https://learn.microsoft.com/en-us/azure/azure-monitor/vm/vminsights-enable?tabs=powershell#enable-vm-insights-1
if (-not(Get-InstalledScript -Name Install-VMInsights)) {
    Install-Script -Name Install-VMInsights -Force
}
else {
    Update-Script -Name Install-VMInsights -Force
}
$UserAssignedManagedIdentityName = "uami-{0}" -f $ResourceGroupName
$UserAssignedManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedManagedIdentityName -ErrorAction Ignore
if (-not($UserAssignedManagedIdentity)) {
    $UserAssignedManagedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $UserAssignedManagedIdentityName -Location $Location
}

#region Data Collection Rule for VM Insights
$DataCollectionRuleName = "MSVMI-{0}" -f $LogAnalyticsWorkspaceName
$DataFlow = New-AzDataFlowObject -Stream Microsoft-InsightsMetrics -Destination $LogAnalyticsWorkspaceName
$PerformanceCounter = New-AzPerfCounterDataSourceObject -CounterSpecifier "\VmInsights\DetailedMetrics" -Name VMInsightsPerfCounters -SamplingFrequencyInSecond 60 -Stream Microsoft-InsightsMetrics
#$DestinationLogAnalytic = New-AzLogAnalyticsDestinationObject -Name $LogAnalyticsWorkSpace.Name -WorkspaceResourceId $LogAnalyticsWorkSpace.ResourceId
$DataCollectionRule = New-AzDataCollectionRule -Name $DataCollectionRuleName -ResourceGroupName $ResourceGroupName -Location $Location -DataFlow $DataFlow -DataSourcePerformanceCounter $PerformanceCounter -DestinationLogAnalytic $DestinationLogAnalytic
#endregion


if (-not([string]::IsNullOrEmpty($VMs.Id))) {
    #$VMs = $VMs.Id | Get-AzVM
    foreach ($CurrentVM in $VMs) {
        $Parameters = @{
            SubscriptionId                           = (Get-AzContext).Subscription.Id
            ResourceGroup                            = $ResourceGroupName
            Name                                     = $CurrentVM.Name
            DcrResourceId                            = $DataCollectionRule.Id
            UserAssignedManagedIdentityName          = $UserAssignedManagedIdentity.Name
            UserAssignedManagedIdentityResourceGroup = $UserAssignedManagedIdentity.ResourceGroupName
            Approve                                  = $true
        }
        Install-VMInsights.ps1 @Parameters
    }
}
#endregion 

#region Querying the latest HeartBeat, Performance Counter and Event Log entry sent
[string[]] $Queries = @("Heartbeat | order by TimeGenerated desc | limit 1", "Perf | order by TimeGenerated desc | limit 1", "Event | order by TimeGenerated desc | limit 1")
$Results = foreach ($CurrentQuery in $Queries) {
    Write-Verbose -Message "`$CurrentQuery: $CurrentQuery"

    # Run the query
    $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkSpace.CustomerId -Query $CurrentQuery
    [PSCustomObject]@{LogAnalyticsWorkspaceName = $LogAnalyticsWorkSpace.Name ; Query = $CurrentQuery; Results = $($Result.Results | Select-Object -Property *, @{Name = "LocalTimeGenerated"; Expression = { Get-Date $_.TimeGenerated } }) }
}
$Results.Results | Out-GridView
#endregion
#endregion