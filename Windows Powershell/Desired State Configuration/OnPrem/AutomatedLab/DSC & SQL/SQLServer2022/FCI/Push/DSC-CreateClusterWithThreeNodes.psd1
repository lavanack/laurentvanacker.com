@{
    AllNodes = @(
        @{
            NodeName= '*'
            <#
                NOTE! THIS IS NOT RECOMMENDED IN PRODUCTION.
                This is added so that AppVeyor automatic tests can pass, otherwise the tests will fail on
                passwords being in plain text and not being encrypted. Because there is not possible to have
                a certificate in AppVeyor to encrypt the passwords we need to add parameter
                'PSDscAllowPlainTextPassword'.
                NOTE! THIS IS NOT RECOMMENDED IN PRODUCTION.
            #>
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true

            #region WSFC
            ClusterName = 'SQLCLUSTER'
            ClusterIPAddress = '10.0.0.101'
            SourceShareRoot = "\\FS01\Sources"
            #endregion

            #region SQL Server
            SQLSysAdminAccounts = @("DBA_SQL", "SQLAdministrator")
            Features = 'SQLENGINE,FullText,Replication'
            FailoverClusterInstanceName  = 'INSTANCENAME'
            FailoverClusterGroupName = 'GROUPNAME'
            FailoverClusterNetworkName = 'NETWORKNAME'
            FailoverClusterIPAddress = '10.0.0.102'
            Drive = 'E:'
            SQLTCPPort = 1433
            #endregion
        },

        # SQLNODE01 - First cluster node.
        @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE01'

            # This is used in the configuration to know which resource to compile.
            Role = 'FirstServerNode'
         },
         # SQLNODE02 - Second cluster node
         @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE02'

            # This is used in the configuration to know which resource to compile.
            Role = 'AdditionalServerNode'
         }
         ,
         # SQLNODE03 - Third cluster node
         @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE03'

            # This is used in the configuration to know which resource to compile.
            Role = 'AdditionalServerNode'
         }
    )
}