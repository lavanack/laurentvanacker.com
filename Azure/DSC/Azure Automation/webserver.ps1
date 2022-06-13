configuration WebServer
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration

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
            xWebSite $site.Name
            {
                Name         = $site.Name
                PhysicalPath = $site.PhysicalPath
                DependsOn    = $dependencies
                BindingInfo     = @(
                    MSFT_xWebBindingInformation
                    {
                        Protocol              = 'HTTP'
                        Port                  = $site.Port
                    }
                )                              
            }
        }
    }
}
