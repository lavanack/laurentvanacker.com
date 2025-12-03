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
            SourceShareRoot = "\\FS01\Sources"

            #region SQL Server
            SQLSysAdminAccounts = @("DBA_SQL", "SQLAdministrator")
            Features = 'SQLENGINE,FullText,Replication'
            InstanceName  = 'MSSQLSERVER'
            BackupPath = '\\FS01\Backup'
            Drive = 'D:'
            SQLTCPPort = 1433
            #endregion
        },
        @{
            # Replace with the name of the actual target node.
            NodeName = 'localhost'
         }
    )
}