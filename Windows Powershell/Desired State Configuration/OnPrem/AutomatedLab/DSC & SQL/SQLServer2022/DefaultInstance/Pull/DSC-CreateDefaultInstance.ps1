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
#requires -Version 5 -Modules PSDesiredStateConfiguration, ComputerManagementDsc, SqlServerDsc -RunAsAdministrator 


Configuration CreateDefaultInstance {
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

    Import-DscResource -ModuleName ActiveDirectoryDsc, PSDesiredStateConfiguration, ComputerManagementDsc, SqlServerDsc

    Node $AllNodes.NodeName
    {
        #region Required Windows Features
        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Core'
            Ensure = 'Present'
        }
        #endregion 

        #Setting Up The Server For High Performance
        PowerPlan SetPlanHighPerformance
        {
            IsSingleInstance = 'Yes'
            Name             = 'High performance'
        }

        #Installing SQL server as Standalone Instance
        SqlSetup 'DefaultInstance'
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
            DependsOn              = '[WindowsFeature]NetFramework45'
        }

        #region SQL Server Registry Management
        Registry DisableNp
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Np"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]DefaultInstance'
        }

        Registry DisableSm
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\sm"
            ValueName   = "Enabled"
            ValueData   = "0"
            ValueType   = "Dword"
            DependsOn   = '[SqlSetup]DefaultInstance'
        }

        Registry TcpPort
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpPort"
            ValueData   = $Node.SQLTCPPort
            ValueType   = "String"
            DependsOn   = '[SqlSetup]DefaultInstance'
        }

        Registry TcpDynamicPorts
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.$($Node.InstanceName)\$($Node.InstanceName)\SuperSocketNetLib\Tcp\IpAll"
            ValueName   = "TcpDynamicPorts"
            ValueData   = ""
            ValueType   = "String"
            DependsOn   = '[SqlSetup]DefaultInstance'
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
            DependsOn      = '[SqlSetup]DefaultInstance'
        }

        SqlMaxDop 'MaxDegreeOfParallelism'
        {
            Ensure               = 'Present'
            DynamicAlloc         = $false
            MaxDop               = 1
            ServerName           = $Node.NodeName
            InstanceName         = $Node.InstanceName
            PsDscRunAsCredential = $SqlInstallCredential
            DependsOn      = '[SqlSetup]DefaultInstance', '[SqlConfiguration]ShowAdvancedOptions'
        }
        <#
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
        #>

        <#
        SqlConfiguration MaxDegreeOfParallelism
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'max degree of parallelism'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]DefaultInstance', '[SqlConfiguration]ShowAdvancedOptions'
        }
        #>

        SqlConfiguration AgentXPs
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'Agent XPs'
            OptionValue    = 1
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]DefaultInstance', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration CostThresholdForParallelism
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'cost threshold for parallelism'
            OptionValue    = 32767
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]DefaultInstance', '[SqlConfiguration]ShowAdvancedOptions'
        }

        SqlConfiguration MaxServerMemoryMB
        {
 
            ServerName     = $Node.NodeName
            InstanceName   = $Node.InstanceName
            OptionName     = 'max server memory (MB)'
            OptionValue    = 480000
            RestartService = $false
            PsDscRunAsCredential   = $SqlInstallCredential
            DependsOn      = '[SqlSetup]DefaultInstance', '[SqlConfiguration]ShowAdvancedOptions'
        }
        #endregion

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
    }
}
