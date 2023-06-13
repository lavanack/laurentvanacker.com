Import-Module PSDesiredStateConfiguration

Configuration WebServerConfiguration
{    
	Param ( 
		[String[]]$ComputerName = "localhost"
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $ComputerName
    {                
        #Changing some default LCM Settings
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode  = 'ApplyAndAutoCorrect'
        }
    
        WindowsFeature WebServer
        {
            Name   = "Web-Server"
            Ensure = "Present"
        }

        WindowsFeature AspNet45
        {
            Name      = "Web-Asp-Net45"
            Ensure    = "Present"
            DependsOn = '[WindowsFeature]WebServer'
        }

        WindowsFeature ManagementTools
        {
            Name      = "Web-Mgmt-Tools"
            Ensure    = "Present"
            DependsOn = '[WindowsFeature]WebServer'
        }

		File IISDefaultPage
        {
            DestinationPath = "C:\inetpub\wwwroot\iisstart.htm"
            Contents = "<HTML><HEAD><TITLE>Installed via Azure DSC</TITLE></HEAD><BODY><H1>If you are seeing this page, It means DSC Rocks !!!</H1></BODY></HTML>"
            Ensure = "Present"
            Type = "File" 
            Force = $True
            DependsOn = '[WindowsFeature]WebServer'
        }

    }
}
