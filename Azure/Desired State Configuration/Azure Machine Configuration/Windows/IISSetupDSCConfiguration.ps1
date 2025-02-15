Configuration IISSetupDSCConfiguration
{
    param (
        [string] $FilePath = "C:\inetpub\wwwroot\iisstart.htm",
        [string] $FileContent = "<HTML><HEAD><TITLE>Installed via Azure Machine Configuration</TITLE></HEAD><BODY><H1>If you are seeing this page. It means the website is under maintenance and Azure Machine Configuration rocks !!!</H1></BODY></HTML>"
    )

    Import-DscResource -ModuleName 'PSDscResources', 'WebAdministrationDsc'

    Node $AllNodes.NodeName
    {
        # Install the IIS role
        WindowsFeature IIS
        {
            Ensure          = 'Present'
            Name            = 'Web-Server'
        }

        # Install the IIS role
        WindowsFeature WebScriptingTools
        {
            Ensure          = 'Present'
            Name            = 'Web-Scripting-Tools'
            DependsOn       = '[WindowsFeature]IIS'
        }

        # Install the ASP .NET 4.5 role
        WindowsFeature AspNet45
        {
            Ensure          = 'Present'
            Name            = 'Web-Asp-Net45'
            DependsOn       = '[WindowsFeature]IIS'
        }

        # Install the Management Console
        WindowsFeature MgmtConsole
        {
            Ensure          = 'Present'
            Name            = 'Web-Mgmt-Console'
            DependsOn       = '[WindowsFeature]IIS'
        }

        # Stop the default website
        WebSite DefaultSite
        {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            State           = 'Started'
            PhysicalPath    = $(Split-Path $FilePath -Parent)
            DependsOn       = '[WindowsFeature]WebScriptingTools'
        }

        Script IISDefaultPage
        {
            GetScript = {
                return @{ 'Result' = $(Get-Content -Path $using:FilePath -Raw -ErrorAction Ignore) }
            }
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable,
                # which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                #return ( $state['Result'] -eq $using:Filecontent )
                return $false
            }
            SetScript = {
                Set-Content -Path $using:FilePath -Value $using:FileContent -Force  
            }
            DependsOn       = '[WindowsFeature]IIS'
        }
    }
}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
        }
    )
}

IISSetupDSCConfiguration -ConfigurationData $ConfigurationData
