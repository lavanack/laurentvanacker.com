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
#requires -Version 5 -Modules ActiveDirectoryDsc, FailOverClusterDsc, PSDesiredStateConfiguration, ComputerManagementDsc, SqlServerDsc -RunAsAdministrator 


Configuration CreateClusterWithTwoNodes {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SqlInstallCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SqlServiceCredential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SqlAgentServiceCredential = $SqlServiceCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SqlSACredential,

        [Parameter(Mandatory = $true)]
        [PSCredential]
        $ActiveDirectoryAdministratorCredential
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc, PSDesiredStateConfiguration, FailOverClusterDsc, ComputerManagementDsc, SqlServerDsc

    Node $AllNodes.NodeName
    {
        #$ClusterOUDistinguishedName = "OU=Clusters,DC=contoso,DC=com"
        $ClusterOUDistinguishedName = $Node.ClusterOUDistinguishedNam
        $ClusterOUName, $ClusterOUPath =  $ClusterOUDistinguishedName -split ",", 2
        if ($ClusterOUDistinguishedName -match "OU=(?<ClusterOUName>[^,]*),(?<ClusterOUPath>DC=.*)")
        {
            $ClusterOUName =  $Matches['ClusterOUName']
            $ClusterOUPath =  $Matches['ClusterOUPath']
            $DomainNetBIOSName = (Get-ADDomain -Identity $ClusterOUPath).NetBIOSName
        }
        else
        {
            $ClusterOUName = "Clusters"
            $ClusterOUPath = (Get-ADDomain).DistinguishedName
            $DomainNetBIOSName = (Get-ADDomain).NetBIOSName
        }
        #region AD Management : OU & Computer Object Creation and Settings
        #From https://docs.microsoft.com/en-us/windows-server/failover-clustering/prestage-cluster-adds
	    ADOrganizationalUnit 'ClustersOU'
        {
            Name                            = $ClusterOUName
            Path                            = $ClusterOUPath
            ProtectedFromAccidentalDeletion = $true
            Description                     = "$ClusterOUName OU"
            Ensure                          = 'Present'
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential 
        }

        ADComputer ClusterNameObject
        {
            ComputerName         = $Node.ClusterName
            Ensure               = 'Present'
            Path                 = "OU=$ClusterOUName,$ClusterOUPath"
            DependsOn            = "[ADOrganizationalUnit]ClustersOU"
            EnabledOnCreation    = $false
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential 
        }

        Script SetCNOProtectedFromAccidentalDeletion {
            GetScript  = {
                #$Result = [string](Get-ADComputer -Filter "Name -eq '$($using:Node.ClusterName)'" -SearchBase "OU=$($using:ClusterOUName),$ClusterOUPath" -Properties ProtectedFromAccidentalDeletion).ProtectedFromAccidentalDeletion
                $Result = [string](Get-ADComputer -Filter "Name -eq '$($using:Node.ClusterName)'" -SearchBase "OU=$($using:ClusterOUName),$($using:ClusterOUPath)" -Properties ProtectedFromAccidentalDeletion).ProtectedFromAccidentalDeletion
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $Result
                }
            }
     
            SetScript  = {
                #Get-ADComputer -Filter "Name -eq '$($using:Node.ClusterName)'" -SearchBase "OU=$($using:ClusterOUName),$ClusterOUPath" | Set-ADObject -ProtectedFromAccidentalDeletion $true
                Get-ADComputer -Filter "Name -eq '$($using:Node.ClusterName)'" -SearchBase "OU=$($using:ClusterOUName),$($using:ClusterOUPath)" | Set-ADObject -ProtectedFromAccidentalDeletion $true
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return [system.boolean]::Parse($state.Result)
            }
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential
            DependsOn            = '[ADComputer]ClusterNameObject'
        }

        ADObjectPermissionEntry 'SetCNOCreateChildRightOnsOU'
        {
            Ensure                             = 'Present'
            Path                               = "OU=$ClusterOUName,$ClusterOUPath"
            IdentityReference                  = "{0}\{1}$" -f $DomainNetBIOSName, $Node.ClusterName
            ActiveDirectoryRights              = 'CreateChild'
            AccessControlType                  = 'Allow'
            ObjectType                         = 'bf967a86-0de6-11d0-a285-00aa003049e2' # Computer objects
            ActiveDirectorySecurityInheritance = 'All'
            InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
            DependsOn                          = '[ADComputer]ClusterNameObject'
            PsDscRunAsCredential               = $ActiveDirectoryAdministratorCredential 
        }
        
        ADObjectPermissionEntry 'SetCNOReadPropertyandGenericExecuteRightsOnsOU'
        {
            Ensure                             = 'Present'
            Path                               = "OU=$ClusterOUName,$ClusterOUPath"
            IdentityReference                  = "{0}\{1}$" -f $DomainNetBIOSName, $Node.ClusterName
            ActiveDirectoryRights              = 'ReadProperty', 'GenericExecute'
            AccessControlType                  = 'Allow'
            ObjectType                         = '00000000-0000-0000-0000-000000000000'
            ActiveDirectorySecurityInheritance = 'All'
            InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
            DependsOn                          = '[ADComputer]ClusterNameObject'
            PsDscRunAsCredential               = $ActiveDirectoryAdministratorCredential 
        }
        #endregion

        #region Required Windows Features
        WindowsFeature AddFailoverFeature
        {
            Ensure = 'Present'
            Name = 'Failover-clustering'
            IncludeAllSubFeature = $true
            DependsOn = '[WindowsFeature]AddRSATClustering'
        }

        WindowsFeature AddRSATClustering
        {
            Ensure = 'Present'
            Name = 'RSAT-Clustering'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Core'
            Ensure = 'Present'
        }

        WindowsFeature 'SNMPWMIProvider'
        {
            Name   = 'SNMP-WMI-Provider'
            Ensure = 'Present'
        }

        WindowsFeature 'MultipathIO'
        {
            Name   = 'Multipath-IO'
            Ensure = 'Present'
        }
        #endregion

        #Setting Up The Server For High Performance
        PowerPlan SetPlanHighPerformance
        {
            IsSingleInstance = 'Yes'
            Name             = 'High performance'
        }

        <#
        Script HighPerformance {
            GetScript  = {
                $ActiveScheme = [string]($(powercfg -getactivescheme).split()[3])
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $ActiveScheme
                }
            }
     
            SetScript  = {
                $HighPerformanceScheme = (powercfg -l | Where-Object -FilterScript {$_ -match "High Performance"} | Select-Object -First 1).split()[3]
                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "powercfg -setactive $HighPerformanceScheme" -Wait
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                $HighPerformanceScheme = (powercfg -l | Where-Object -FilterScript {$_ -match "High Performance"} | Select-Object -First 1).split()[3]
                return ($state.Result -eq $HighPerformanceScheme)
            }
        }
        #>

        #region LCM Setup
        LocalConfigurationManager     
	    {
            #ConfigurationMode  = "ApplyAndAutoCorrect"
            ConfigurationMode  = 'ApplyOnly'
		    ActionAfterReboot  = 'ContinueConfiguration'
		    # Allowing to reboot if needed even in the middle of a configuration.
            RebootNodeIfNeeded = $True
		    RefreshMode        = 'Push'
        }
        #endregion
    }

    Node $AllNodes.Where{$_.Role -eq 'FirstServerNode' }.NodeName
    {
        #Cluster Creation : First Node
        Cluster CreateCluster
        {
            Name = $Node.ClusterName
            StaticIPAddress = $Node.ClusterIPAddress
            # This user must have the permission to create the CNO (Cluster Name Object) in Active Directory, unless it is prestaged.
            DomainAdministratorCredential = $ActiveDirectoryAdministratorCredential
            # IgnoreNetwork = '10.0.0.0/8'
            #DependsOn = '[WindowsFeature]AddRSATClusteringCmdInterfaceFeature'
            DependsOn = '[WindowsFeature]AddRSATClustering', '[ADObjectPermissionEntry]SetCNOCreateChildRightOnsOU', '[ADObjectPermissionEntry]SetCNOReadPropertyandGenericExecuteRightsOnsOU'
        }

        <#
        #Bug : https://github.com/dsccommunity/FailOverClusterDsc/issues/200
        #You have to add the disk manually via the FailOver Cluster Manager
        Workaround : Get-ClusterAvailableDisk | Add-ClusterDisk
        ClusterDisk 'AddClusterDisk-SQL2022-DATA'
        {
            Number = 1
            Ensure = 'Present'
            Label  = $Node.FailoverClusterGroupName
            DependsOn = '[Cluster]CreateCluster'
        }
        #>

        #Adding Disk to the Cluster
        Script AddClusterDisk {
            GetScript  = {
                $ClusterDisk= Get-ClusterResource -Cluster ($using:Node).ClusterName | Where-Object -FilterScript {$_.ResourceType -eq 'Physical Disk'}
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $ClusterDisk
                }
            }
     
            SetScript  = {
                Get-Volume | Where-Object -FilterScript { $_.DriveLetter -eq ($using:Node).Drive.Substring(0,1) } | Get-Partition | Get-Disk | Get-ClusterAvailableDisk -Cluster ($using:Node).ClusterName | Add-ClusterDisk
                #Renaming the disk in the cluster configuration
                #(Get-ClusterResource -Cluster ($using:Node).ClusterName | Where-Object -FilterScript {$_.ResourceType -eq 'Physical Disk'}).Name = $Node.FailoverClusterGroupName
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return $state.Result -ne $null
            }
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential
            DependsOn = '[WaitForAll]JoinAdditionalServerNodeToCluster'
        }

        #Waiting all nodes be up and running before validating the cluster.
        WaitForAll JoinAdditionalServerNodeToCluster
        {
            ResourceName      = '[Cluster]JoinNodeToCluster'
            NodeName          = $AllNodes.Where{$_.Role -eq 'AdditionalServerNode' }.NodeName
            RetryIntervalSec  = 30
            RetryCount        = 60
        }        

        Script TestCluster {
            GetScript  = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
     
            SetScript  = {
                Test-Cluster -ReportName C:\DSC-Test-Cluster
            }
     
            TestScript = {
                if (-not(Test-Path -Path C:\DSC-Test-Cluster.htm -PathType Leaf))
                {
                    [scriptblock]::Create($SetScript).Invoke()
                }
                <#
                    Other way to validate the cluster is by reading the XML report
                    $LatestClusterValidationReport = Get-ChildItem -Path C:\Windows\Cluster\Reports\ -Filter 'Validation Data For Node*.xml' -File | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                    $LatestClusterValidationReportContent = [xml] (Get-Content -Path $LatestClusterValidationReport.FullName)
                    $NodeData = $LatestClusterValidationReportContent.SelectNodes("//Report/Channel/Node") | Select-Object -Property @{Name="Node"; Expression = {$_.Value.innerText}}, @{Name="Status"; Expression = {$_.Status.innerText}}
                    $return ($NodeData | Where-Object -FilterScript {($_.Status -eq 'Validated')}).Count -eq ($using:AllNodes.NodeName | Where-Object -FilterScript {$_ -ne '*'}).Count
                #>
                [string]$reportContent = Get-Content -Path C:\DSC-Test-Cluster.htm
                $MyMatches= [regex]::Matches(($reportContent),"(?m)Node:.*Validated</div>")
                $Output = $MyMatches.Value -replace "<[^>]*>" -replace "Node:\s+([^\s]+)\s+", '$1=' -replace "\s+", " "  -split " "
                return (($Output -replace ".*=") | Where-Object -FilterScript {($_ -eq 'Validated')}).Count -eq ($using:AllNodes.NodeName | Where-Object -FilterScript {$_ -ne '*'}).Count
            }
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential
            DependsOn = '[Script]AddClusterDisk'
        }
        
        #Installing SQL server in Failover Cluster Mode : First Node
        SqlSetup 'InstallFailoverCluster'
        {
            Action                     = 'InstallFailoverCluster'
            InstanceName               = $Node.FailoverClusterInstanceName
            InstanceID                 = $Node.FailoverClusterInstanceName
            Features                   = $Node.Features
            SourcePath                 = "$($Node.SourceShareRoot)\SQLServer2022"
            FailoverClusterGroupName   = $Node.FailoverClusterGroupName
            FailoverClusterNetworkName = $Node.FailoverClusterNetworkName
            FailoverClusterIPAddress   = $Node.FailoverClusterIPAddress
            InstallSQLDataDir          = "$($Node.Drive)\System"
            # Windows account(s) to provision as SQL Server system administrators.
            SQLSysAdminAccounts        = $Node.SqlSysAdminAccounts
            #UpdateEnabled              = 'False'
            UpdateEnabled              = 'True'
            UpdateSource               = "$($Node.SourceShareRoot)\SQLServer2022\Updates"
            AgtSvcAccount              = $SqlAgentServiceCredential
            AgtSvcStartupType          = 'Automatic'
            SQLSvcAccount              = $SqlServiceCredential
            SqlSvcStartupType          = 'Automatic'
            SAPwd                      = $SqlSACredential
            # Specifies a Windows collation or an SQL collation to use for the Database Engine.
            SQLCollation               = "Latin1_General_CI_AS"
            # The default is Windows Authentication. Use "SQL" for Mixed Mode Authentication.
            SecurityMode               = 'SQL'
            # The number of Database Engine TempDB files.
            SqlTempdbFileCount         = 8
            # Specifies the initial size of a Database Engine TempDB data file in MB.
            #SqlTempdbFileSize          = 1024
            SqlTempdbFileSize          = 128
            # Specifies the automatic growth increment of each Database Engine TempDB data file in MB.
            #SqlTempdbFileGrowth        = 1024
            SqlTempdbFileGrowth        = 128
            # Specifies the initial size of the Database Engine TempDB log file in MB.
            #SqlTempdbLogFileSize       = 1024
            SqlTempdbLogFileSize       = 128
            # Specifies the automatic growth increment of the Database Engine TempDB log file in MB.
            SqlTempdbLogFileGrowth       = 512
            # Default directory for the Database Engine user databases.
            SQLUserDBDir                 = "$($Node.Drive)\DATA"
            # Default directory for the Database Engine user database logs.
            SQLUserDBLogDir              = "$($Node.Drive)\LOG"
            # Directories for Database Engine TempDB files.
            SQLTempDBDir                 = "$($Node.Drive)\TEMPDB"
            # Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed.
            InstallSharedDir             = "C:\Program Files\Microsoft SQL Server"
            # Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed.
            InstallSharedWOWDir          = "C:\Program Files (x86)\Microsoft SQL Server"
            # Specify 0 to disable or 1 to enable the TCP/IP protocol.
            #TcpEnabled                   = 1 
            # Specify 0 to disable or 1 to enable the Named Pipes protocol.
            #NpEnabled                    = 0
            # Startup type for Browser Service         
            #BrowserSvcStartupType  = "Automatic"
            ForceReboot                  = $true
            PsDscRunAsCredential         = $SqlInstallCredential
            DependsOn                    = '[Script]TestCluster', '[Script]AddClusterDisk','[WindowsFeature]NetFramework45'
        }

        WaitForAll SqlSetupAddNode
        {
            ResourceName      = '[SqlSetup]AddNode'
            NodeName          = $AllNodes.Where{$_.Role -eq 'AdditionalServerNode' }.NodeName
            RetryIntervalSec  = 30
            RetryCount        = 60
        }        

        Script SetClusterOwnerNode {
            GetScript  = {
                $Result = Get-ClusterResource | Get-ClusterOwnerNode | Out-String
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $Result
                }
            }
     
            SetScript  = {
                Get-ClusterResource | Set-ClusterOwnerNode -Owners ($using:AllNodes).NodeName
            }
     
            TestScript = {
                return ((Get-ClusterResource | Get-ClusterOwnerNode | Where-Object -FilterScript {$_.OwnerNodes.Count -lt ($using:AllNodes).Count}) -eq $null)
            }
            PsDscRunAsCredential = $ActiveDirectoryAdministratorCredential
            DependsOn            = '[WaitForAll]SqlSetupAddNode'
        }
                
        #region Cluster Preferred Owner
        ClusterPreferredOwner 'AddOwnersForCluster'
        {
            Ensure               = 'Present'
            ClusterName          = $Node.ClusterName
            ClusterGroup         = $Node.FailoverClusterGroupName
            Nodes                = $AllNodes.NodeName
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[Script]SetClusterOwnerNode'
        }
        #endregion

        #region SQL Server Service Management
        if ($Node.InstanceName -eq "MSSQLServer")
        {
            $ServiceName = 'SQLSERVERAGENT'
        }
        else
        {
            $ServiceName = 'SQLAGENT${0}' -f $Node.FailoverClusterInstanceName
        }

        Service SQLServerAgent
        {
            Name        = $ServiceName
            Ensure      = 'Present'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[SqlSetup]InstallFailoverCluster'
        }
        #endregion

        #region SQL Server Registry Management
        Registry DisableNp
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.FailoverClusterInstanceName)\$($Node.FailoverClusterInstanceName)\SuperSocketNetLib\Np"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]InstallFailoverCluster'
        }

        Registry DisableSm
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.FailoverClusterInstanceName)\$($Node.FailoverClusterInstanceName)\SuperSocketNetLib\sm"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]InstallFailoverCluster'
        }

        Registry TcpPort
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.FailoverClusterInstanceName)\$($Node.FailoverClusterInstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpPort"
            ValueData   = $Node.SQLTCPPort
            ValueType   = "String"
        }

        Registry TcpDynamicPorts
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.FailoverClusterInstanceName)\$($Node.FailoverClusterInstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpDynamicPorts"
            ValueData   = ""
            ValueType   = "String"
            DependsOn   = '[SqlSetup]InstallFailoverCluster'
        }
        #endregion

        #region SQL Server Configuration Management
        SqlConfiguration ShowAdvancedOptions
        {
 
            ServerName     = $Node.FailoverClusterNetworkName
            InstanceName   = $Node.FailoverClusterInstanceName
            OptionName     = 'show advanced options'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallFailoverCluster'
        }

        SqlConfiguration MaxDegreeOfParallelism
        {
 
            ServerName           = $Node.FailoverClusterNetworkName
            InstanceName         = $Node.FailoverClusterInstanceName
            OptionName           = 'max degree of parallelism'
            OptionValue          = 1
            RestartService       = $false
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallFailoverCluster', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration AgentXPs
        {
 			ServerName           = $Node.FailoverClusterNetworkName
            InstanceName         = $Node.FailoverClusterInstanceName
            OptionName     = 'Agent XPs'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallFailoverCluster', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration CostThresholdForParallelism
        {
 
            ServerName     = $Node.FailoverClusterNetworkName
            InstanceName   = $Node.FailoverClusterInstanceName
            OptionName     = 'cost threshold for parallelism'
            OptionValue    = 32767
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallFailoverCluster', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration MaxServerMemoryMB
        {
 
            ServerName     = $Node.FailoverClusterNetworkName
            InstanceName   = $Node.FailoverClusterInstanceName
            OptionName     = 'max server memory (MB)'
            OptionValue    = 480000
            RestartService = $false
            DependsOn      = '[SqlSetup]InstallFailoverCluster', '[SqlConfiguration]ShowAdvancedOptions'
            PsDscRunAsCredential   = $SqlInstallCredential
        }
        #endregion
    }

    Node $AllNodes.Where{ $_.Role -eq 'AdditionalServerNode' }.NodeName
    {
        #Waiting the cluster be up and running before joining additional node(s)
        WaitForCluster WaitForCluster
        {
            Name = $Node.ClusterName
            RetryIntervalSec = 30
            RetryCount = 60
            #DependsOn = '[WindowsFeature]AddRSATClusteringCmdInterfaceFeature'
            DependsOn = '[WindowsFeature]AddRSATClustering'
        }

        #Joining the cluster
        Cluster JoinNodeToCluster
        {
            Name = $Node.ClusterName
            StaticIPAddress = $Node.ClusterIPAddress
            DomainAdministratorCredential = $ActiveDirectoryAdministratorCredential
            DependsOn = '[WaitForCluster]WaitForCluster'
        }

        WaitForAny FirstNode
        {
            ResourceName      = '[SqlSetup]InstallFailoverCluster'
            NodeName          = $AllNodes.Where{$_.Role -eq 'FirstServerNode' }.NodeName
            RetryIntervalSec  = 30
            RetryCount        = 30
        }        

        #Installing SQL server in Failover Cluster Mode : Additional Node(s)
        SqlSetup 'AddNode'
        {
            Action                   = 'AddNode'
            InstanceName             = $Node.FailoverClusterInstanceName
            Features                 = $Node.Features
            SourcePath               = "$($Node.SourceShareRoot)\SQLServer2022"
            FailoverClusterGroupName = $Node.FailoverClusterGroupName
            FailoverClusterNetworkName = $Node.FailoverClusterNetworkName
            FailoverClusterIPAddress = $Node.FailoverClusterIPAddress
            InstallSQLDataDir        = "$($Node.Drive)\System"
            # Windows account(s) to provision as SQL Server system administrators.
            SQLSysAdminAccounts      = $Node.SqlSysAdminAccounts
            UpdateEnabled              = 'False'
            <#
            UpdateEnabled              = 'True'
            UpdateSource               = "$($Node.SourceShareRoot)\SQLServer2022\Updates"
            #>
            UpdateSource             = "$($Node.SourceShareRoot)\SQLServer2022\Updates"
            AgtSvcAccount            = $SqlAgentServiceCredential
            AgtSvcStartupType        = 'Automatic'
            SQLSvcAccount            = $SqlServiceCredential
            SqlSvcStartupType        = 'Automatic'
            # Specifies a Windows collation or an SQL collation to use for the Database Engine.
            SQLCollation             = "Latin1_General_CI_AS"
            # The default is Windows Authentication. Use "SQL" for Mixed Mode Authentication.
            SecurityMode             = 'SQL'
            # Default directory for the Database Engine user databases.
            SQLUserDBDir             = "$($Node.Drive)\DATA"
            # Default directory for the Database Engine user database logs.
            SQLUserDBLogDir          = "$($Node.Drive)\LOG"
            # Directories for Database Engine TempDB files.
            SQLTempDBDir             = "$($Node.Drive)\TEMPDB"
            # Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed.
            InstallSharedDir         = "C:\Program Files\Microsoft SQL Server"
            # Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed.
            InstallSharedWOWDir      = "C:\Program Files (x86)\Microsoft SQL Server"
            # Specify 0 to disable or 1 to enable the TCP/IP protocol.
            #TcpEnabled                   = 1 
            # Specify 0 to disable or 1 to enable the Named Pipes protocol.
            #NpEnabled                    = 0
            # Startup type for Browser Service         
            #BrowserSvcStartupType  = "Automatic"
            #ForceReboot                  = $true
            PsDscRunAsCredential         = $SqlInstallCredential

            #DependsOn              = '[File]Backup', '[File]Data', '[File]Log', '[File]TempDB'
            DependsOn                = '[WaitForAny]FirstNode', '[WindowsFeature]NetFramework45'
        }
    }
}
