@{
    AllNodes  = @(
        @{
            NodeName   = 'WinSrv2019'
            Role       = 'WebServer'
        }
    )

    WebServer = @{
        Features = 'Web-Server', 'Web-Mgmt-Console'
        WebSites = @(
            @{
                Name         = 'Site1'
                PhysicalPath = 'C:\inetpub\wwwroot'
                Port         = 81
            }
            @{
                Name         = 'Site2'
                PhysicalPath = 'C:\inetpub\wwwroot'
                Port         = 82
            }
        )
    }
}