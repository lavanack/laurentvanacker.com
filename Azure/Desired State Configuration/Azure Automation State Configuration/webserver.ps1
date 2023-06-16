Configuration WebServer
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName WebAdministrationDsc

    node $AllNodes.Where( { $_.Role -eq 'WebServer' }).NodeName
    {
        $nodeConfig = $configurationData[$Node.Role]

        # Copy content
        $dependencies = @()
        # Install features
        foreach ($feature in $nodeConfig.Features)
        {
            $dependencies += "[WindowsFeature]$feature"
            WindowsFeature $feature
            {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Create web sites
        foreach ($site in $nodeConfig.WebSites)
        {
            WebSite $site.Name
            {
                Name         = $site.Name
                PhysicalPath = $site.PhysicalPath
                State        = 'Started'
                DependsOn    = $dependencies
                BindingInfo     = @(
                    DSC_WebBindingInformation
                    {
                        Protocol              = 'HTTP'
                        Port                  = $site.Port
                    }
                )                              
            }
        }
    }
}
