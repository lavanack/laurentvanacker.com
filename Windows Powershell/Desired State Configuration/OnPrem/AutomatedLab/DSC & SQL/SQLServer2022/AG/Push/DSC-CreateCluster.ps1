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

        #Installing SQL server as Standalone Instance
        SqlSetup 'InstallAG'
        {
            InstanceName         = $Node.InstanceName
            #InstanceID           = $Node.InstanceName
            Features             = $Node.Features
            SourcePath           = "$($Node.SourceShareRoot)\SQLServer2022"
            InstallSQLDataDir    = "$($Node.Drive)\System"
            # Windows account(s) to provision as SQL Server system administrators.
            SQLSysAdminAccounts  = $Node.SQLSysAdminAccounts
            #UpdateEnabled        = 'False'
            UpdateEnabled        = 'True'
            UpdateSource         = "$($Node.SourceShareRoot)\SQLServer2022\Updates"
            AgtSvcAccount        = $SqlAgentServiceCredential
            AgtSvcStartupType    = 'Automatic'
            SQLSvcAccount        = $SqlServiceCredential
            SqlSvcStartupType    = 'Automatic'
            SAPwd                = $SqlSACredential
            # Specifies a Windows collation or an SQL collation to use for the Database Engine.
            SQLCollation         = "Latin1_General_CI_AS"
            # The default is Windows Authentication. Use "SQL" for Mixed Mode Authentication.
            SecurityMode         = 'SQL'
            # The number of Database Engine TempDB files.
            SqlTempdbFileCount   = 8
            # Specifies the initial size of a Database Engine TempDB data file in MB.
            #SqlTempdbFileSize    = 1024
            SqlTempdbFileSize    = 128
            # Specifies the automatic growth increment of each Database Engine TempDB data file in MB.
            #SqlTempdbFileGrowth  = 1024
            SqlTempdbFileGrowth  = 128
            # Specifies the initial size of the Database Engine TempDB log file in MB.
            #SqlTempdbLogFileSize = 1024
            SqlTempdbLogFileSize = 128
            # Specifies the automatic growth increment of the Database Engine TempDB log file in MB.
            SqlTempdbLogFileGrowth = 512
            # Default directory for the Database Engine user databases.
            SQLUserDBDir           = "$($Node.Drive)\DATA"
            # Default directory for the Database Engine user database logs.
            SQLUserDBLogDir        = "$($Node.Drive)\LOG"
            # Directories for Database Engine TempDB files.PRIM
            SQLTempDBDir           = "$($Node.Drive)\TEMPDB"
            # Specify the root installation directory for shared components.  This directory remains unchanged after shared components are already installed.
            InstallSharedDir       = "C:\Program Files\Microsoft SQL Server"
            # Specify the root installation directory for the WOW64 shared components.  This directory remains unchanged after WOW64 shared components are already installed.
            InstallSharedWOWDir    = "C:\Program Files (x86)\Microsoft SQL Server"
            # Specify 0 to disable or 1 to enable the TCP/IP protocol.
            TcpEnabled             = 1 
            # Specify 0 to disable or 1 to enable the Named Pipes protocol.
            NpEnabled              = 0
            # Startup type for Browser Service.
            BrowserSvcStartupType  = "Automatic"
            PsDscRunAsCredential   = $SqlInstallCredential
        }

        #SQL Server AlwaysOn Service
        SqlAlwaysOnService 'EnableAlwaysOn'
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            RestartTimeout       = 120
            DependsOn            = '[SqlSetup]InstallAG'
        }
        
        #region SQL Server Registry Management
        Registry DisableNp
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Np"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]InstallAG'
        }

        Registry DisableSm
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\sm"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]InstallAG'
        }

        Registry TcpPort
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpPort"
            ValueData   = $Node.SQLTCPPort
            ValueType   = "String"
            DependsOn   = '[SqlSetup]InstallAG'
        }

        Registry TcpDynamicPorts
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpDynamicPorts"
            ValueData   = ""
            ValueType   = "String"
            DependsOn   = '[SqlSetup]InstallAG'
        }
        #endregion

        #region SQL Server Configuration Management
        SqlConfiguration ShowAdvancedOptions
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'show advanced options'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG'
        }

        SqlConfiguration MaxDegreeOfParallelism
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'max degree of parallelism'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration AgentXPs
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'Agent XPs'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration CostThresholdForParallelism
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'cost threshold for parallelism'
            OptionValue    = 32767
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration MaxServerMemoryMB
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'max server memory (MB)'
            OptionValue    = 480000
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG', '[SqlConfiguration]ShowAdvancedOptions'
        }
        #endregion

        #Adding SQL Server Login for 'NT SERVICE\ClusSvc'
        SqlLogin 'AddNTServiceClusSvc'
        {
            Ensure               = 'Present'
            Name                 = 'NT SERVICE\ClusSvc'
            LoginType            = 'WindowsUser'
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn      = '[SqlSetup]InstallAG'
        }

        #Adding SQL Server Permissions for 'NT SERVICE\ClusSvc'
        # Add the required permissions to the cluster service login
        SqlPermission 'AddNTServiceClusSvcPermissions'
        {
            DependsOn            = '[SqlLogin]AddNTServiceClusSvc'
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            Name                 = 'NT SERVICE\ClusSvc'
            Permission   = @(
                ServerPermission
                {
                    State      = 'Grant'
                    Permission = @('AlterAnyAvailabilityGroup', 'ViewServerState')
                }
                ServerPermission
                {
                    State      = 'GrantWithGrant'
                    Permission = @()
                }
                ServerPermission
                {
                    State      = 'Deny'
                    Permission = @()
                }
            )
            #Credential           = $SqlInstallCredential
        }

        # Create a DatabaseMirroring endpoint
        SqlEndpoint 'HADREndpoint'
        {
            EndPointName         = 'HADR'
            EndpointType         = 'DatabaseMirroring'
            Ensure               = 'Present'
            Port                 = $Node.SQLEndPointTCPPort
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn            = '[SqlSetup]InstallAG'
        }

<#
        # To uncomment if you want to install SSMS
        Package SSMS
        {
            Name      = "SQL Server Management Studio"
            Ensure    = "Present"
            Path      = "$($Node.SourceShareRoot)\SQLServerTools\SSMS-Setup-ENU.exe"
            Arguments = "/install /passive /norestart"
            ProductId = "ECC23FD6-535B-43CB-894B-F47FA605EBB3" 
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

    Node $AllNodes.Where{$_.Role -eq 'PrimaryReplica' }.NodeName
    {
        #region WSFC
        #Cluster Creation: First Node
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

        #Waiting all secondary replica nodes be up and running before validating the cluster.
        WaitForAll JoinAdditionalServerNodeToCluster
        {
            ResourceName      = '[Cluster]JoinNodeToCluster'
            NodeName          = $AllNodes.Where{$_.Role -eq 'SecondaryReplica' }.NodeName
            RetryIntervalSec  = 30
            RetryCount        = 60
        }        

        #Cluster validation
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
            DependsOn = '[WaitForAll]JoinAdditionalServerNodeToCluster'
        }
        #endregion        

        #region SQL Server       
        #Disabling And Enabling the SQL Server AlwaysOn feature
        Script DisableAndEnableSqlAlwaysOn {
            GetScript  = {
                if ($($using:Node).InstanceName -eq "MSSQLServer")
                {
                    $InstanceName = $env:COMPUTERNAME
                }
                else
                {
                    $InstanceName = Join-Path -Path $($using:Node).NodeName -ChildPath $($using:Node).InstanceName
                }

                $PrimaryReplica = $($($using:AllNodes).Where{$_.Role -eq 'PrimaryReplica' }.NodeName)
                $AvailabilityGroups = [string]$(Invoke-Sqlcmd -Query "SELECT Groups.[Name] AS AGname FROM sys.dm_hadr_availability_group_states States INNER JOIN master.sys.availability_groups Groups ON States.group_id = Groups.group_id WHERE primary_replica = '$PrimaryReplica';"  -ServerInstance $InstanceName).AGname -join ','
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $AvailabilityGroups
                }
            }
     
            SetScript  = {
                if ($($using:Node).InstanceName -eq 'MSSQLSERVER')
                {
                    $InstanceName = "Default"
                }
                else
                {
                    $InstanceName = $($using:Node).InstanceName
                }
                $SqlAlwaysOnPath = "SQLSERVER:\SQL\$($using:Node.NodeName)\$InstanceName"
                Write-Verbose -Message "`$SqlAlwaysOnPath : $SqlAlwaysOnPath"
                Import-Module -Name SQLServer
                Disable-SqlAlwaysOn $SqlAlwaysOnPath -Force -Verbose
                Enable-SqlAlwaysOn $SqlAlwaysOnPath -Force -Verbose
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ($state.Result -split ",") -contains $($using:Node).AvailabilityGroupName
            }
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn             = '[SqlAlwaysOnService]EnableAlwaysOn', '[SqlEndpoint]HADREndpoint', '[SqlPermission]AddNTServiceClusSvcPermissions'
        }

        #region SQL Availability Group Management
        # Create the availability group on the instance tagged as the primary replica
        SqlAG AddAG
        {
            Ensure                = 'Present'
            Name                  = $Node.AvailabilityGroupName
            InstanceName          = $Node.InstanceName
            
            FailoverMode          = 'Manual'
            ServerName            = $Node.NodeName
            DatabaseHealthTrigger = $true
            DependsOn             = '[SqlAlwaysOnService]EnableAlwaysOn', '[SqlEndpoint]HADREndpoint', '[SqlPermission]AddNTServiceClusSvcPermissions', '[Script]DisableAndEnableSqlAlwaysOn'
            PsDscRunAsCredential  = $SqlInstallCredential
        }

        SqlAGListener AvailabilityGroupListener
		{	
            Ensure               = 'Present'
		    Port 				 = 1433
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            AvailabilityGroup    = $Node.AvailabilityGroupName
            Name                 = $Node.AvailabilityGroupName
            IpAddress 			 = $Node.AvailabilityGroupIPAddress
			
			
            DependsOn            = '[SqlAG]AddAG'
		    PsDscRunAsCredential = $SqlInstallCredential
		
		}

        WaitForAll WaitForAddReplica
        {
            ResourceName      = '[SqlAGReplica]AddReplica'
            NodeName          = $AllNodes.Where{ $_.Role -eq 'SecondaryReplica' }.NodeName
            RetryIntervalSec  = 30
            RetryCount        = 30
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
            DependsOn            = '[SqlSetup]InstallAG', '[WaitForAll]WaitForAddReplica'#, '[SqlAGListener]AvailabilityGroupListener'
        }

        #Adding a Sample database
        SqlDatabase CreateSampleDatabase
        {
            Ensure               = 'Present'
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            Name                 = $Node.SampleDatabaseName
            #DependsOn            = '[SqlAGListener]AvailabilityGroupListener'
            DependsOn            = '[SqlSetup]InstallAG', '[WaitForAll]WaitForAddReplica'#, '[SqlAGListener]AvailabilityGroupListener'
            PsDscRunAsCredential = $SqlInstallCredential
        }

        SqlAGDatabase 'AddAGDatabase'
        {
            AvailabilityGroupName   = $Node.AvailabilityGroupName
            BackupPath              = $Node.BackupPath
            DatabaseName            = $Node.SampleDatabaseName
            InstanceName            = $Node.InstanceName
            ServerName              = $Node.NodeName
            Ensure                  = 'Present'
            ReplaceExisting         = $false
            PsDscRunAsCredential    = $SqlInstallCredential
            #DependsOn              = '[SqlScriptQuery]GrantCreateAnyDatabaseToAG', '[SqlDatabase]CreateSampleDatabase', '[SqlAG]AddAG'
            DependsOn              = '[SqlDatabase]CreateSampleDatabase'
        }
        #endregion

        #region SQL Server Service Management
        if ($Node.InstanceName -eq "MSSQLServer")
        {
            $ServiceName = 'SQLSERVERAGENT'
        }
        else
        {
            $ServiceName = 'SQLAGENT${0}' -f $Node.InstanceName
        }

        Service SQLServerAgent
        {
            Name        = $ServiceName
            Ensure      = 'Present'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[SqlSetup]InstallAG'
        }
        #endregion
        #endregion
    }

    Node $AllNodes.Where{ $_.Role -eq 'SecondaryReplica' }.NodeName
    {
        #region WSFC
        #Waiting the cluster be up and running before joining additional node(s)
        WaitForCluster WaitForCluster
        {
            Name = $Node.ClusterName
            RetryIntervalSec = 10
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
        #endregion 

        #region SQL Server
        #region SQL Availability Group Management
        # Wait for SQL AG to be created on primary node before attempting to join secondary node
        SqlWaitForAG SQLConfigureAGWait
        {
            Name                 = $Node.AvailabilityGroupName
            InstanceName         = $Node.InstanceName
            RetryIntervalSec     = 20
            RetryCount           = 30
            ServerName           = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryReplica' } ).NodeName
            PsDscRunAsCredential = $SqlInstallCredential
        }
    
       Script DisableAndEnableSqlAlwaysOn {
            GetScript  = {
                if ($($using:Node).InstanceName -eq "MSSQLServer")
                {
                    $InstanceName = $env:COMPUTERNAME
                }
                else
                {
                    $InstanceName = Join-Path -Path $($using:Node).NodeName -ChildPath $($using:Node).InstanceName
                }
                $PrimaryReplica = $($($using:AllNodes).Where{$_.Role -eq 'PrimaryReplica' }.NodeName)
                $AvailabilityGroups = [string]$(Invoke-Sqlcmd -Query "SELECT Groups.[Name] AS AGname FROM sys.dm_hadr_availability_group_states States INNER JOIN master.sys.availability_groups Groups ON States.group_id = Groups.group_id WHERE primary_replica = '$PrimaryReplica';"  -ServerInstance $InstanceName).AGname -join ','
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $AvailabilityGroups
                }
            }
     
            SetScript  = {
                if ($($using:Node).InstanceName -eq 'MSSQLSERVER')
                {
                    $InstanceName = "Default"
                }
                else
                {
                    $InstanceName = $($using:Node).InstanceName
                }
                $SqlAlwaysOnPath = "SQLSERVER:\SQL\$($using:Node.NodeName)\$InstanceName"
                Write-Verbose -Message "`$SqlAlwaysOnPath : $SqlAlwaysOnPath"
                Import-Module -Name SQLServer
                Disable-SqlAlwaysOn $SqlAlwaysOnPath -Force -Verbose
                Enable-SqlAlwaysOn $SqlAlwaysOnPath -Force -Verbose
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ($state.Result -split ",") -contains $($using:Node).AvailabilityGroupName
            }
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn             = '[SqlAlwaysOnService]EnableAlwaysOn', '[SqlWaitForAG]SQLConfigureAGWait'
        }
        
        # Add the availability group replica to the availability group
        SqlAGReplica AddReplica
        {
            Ensure                     = 'Present'
            Name                       = $Node.NodeName
            AvailabilityGroupName      = $Node.AvailabilityGroupName
            AvailabilityMode           = 'AsynchronousCommit'
            FailoverMode               = 'Manual'
            ServerName                 = $Node.NodeName
            InstanceName               = $Node.InstanceName
            PrimaryReplicaServerName   = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryReplica' } ).NodeName
            PrimaryReplicaInstanceName = ( $AllNodes | Where-Object { $_.Role -eq 'PrimaryReplica' } ).InstanceName
            DependsOn                  = '[SqlAlwaysOnService]EnableAlwaysOn', '[SqlWaitForAG]SQLConfigureAGWait', '[Script]DisableAndEnableSqlAlwaysOn'
            PsDscRunAsCredential       = $SqlInstallCredential
        }
        #endregion

        #region SQL Server Service Management
        if ($Node.InstanceName -eq "MSSQLServer")
        {
            $ServiceName = 'SQLSERVERAGENT'
        }
        else
        {
            $ServiceName = 'SQLAGENT${0}' -f $Node.InstanceName
        }

        Service SQLServerAgent
        {
            Name        = $ServiceName
            Ensure      = 'Present'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[SqlSetup]InstallAG'
        }
        #endregion
        #endregion 
    }

}
