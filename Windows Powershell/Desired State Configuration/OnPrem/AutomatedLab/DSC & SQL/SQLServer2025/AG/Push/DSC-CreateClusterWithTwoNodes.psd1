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

            <#
                Replace with your own CNO (Cluster Name Object) and IP address.
 
                Please note that if the CNO is prestaged, then the computer object must be disabled for the
                resource xCluster to be able to create the cluster.
                If the CNO is not prestaged, then the credential used in the xCluster resource must have
                the permission in Active Directory to create the CNO (Cluster Name Object).
            #>
            #region WSFC
            ClusterName = 'SQLCLUSTER'
            ClusterIPAddress = '10.0.0.101'
            SourceShareRoot = "\\FS01\Sources"
            # Default settings: "CN=Computers,DC=contoso,DC=biz" 
            ClusterOUDistinguishedName = "OU=Clusters,DC=contoso,DC=com"
            #endregion

            #region SQL Server
            SQLSysAdminAccounts = @("DBA_SQL", "SQLAdministrator")
            Features = 'SQLENGINE,FullText,Replication'
            InstanceName  = 'MSSQLSERVER'
            AvailabilityGroupName = 'SQLAGN'
            AvailabilityGroupIPAddress = '10.0.0.102/255.0.0.0'
            BackupPath = '\\FS01\Backup'
            SampleDatabaseName = 'Contoso'
            Drive = 'D:'
            SQLTCPPort = 1433
            SQLEndPointTCPPort = 5022
            #endregion
        },

        # SQLNODE01 - First cluster node.
        @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE01'

            # This is used in the configuration to know which resource to compile.
            Role = 'PrimaryReplica'
         },
         # SQLNODE02 - Second cluster node
         @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE02'

            # This is used in the configuration to know which resource to compile.
            Role = 'SecondaryReplica'
         }
<#
         ,
         # SQLNODE03 - Third cluster node
         @{
            # Replace with the name of the actual target node.
            NodeName = 'SQLNODE03'

            # This is used in the configuration to know which resource to compile.
            Role = 'SecondaryReplica'
         }
#>
    )
}