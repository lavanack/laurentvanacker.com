<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

Configuration IISSetupDSCConfiguration
{
    param (
        [System.Management.Automation.PSCredential] $Credential,
        [string] $WebSiteName = 'www.contoso.com',
        [string] $FilePath = "C:\inetpub\wwwroot\iisstart.htm",
        [string] $FileContent = "<HTML><HEAD><TITLE>Installed via Azure Machine Configuration</TITLE></HEAD><BODY><H1>If you are seeing this page. It means the website is under maintenance and Azure Machine Configuration rocks !!!</H1></BODY></HTML>"
    )

    Import-Module -Name 'WebAdministration'
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

        User $Credential.UserName {
            Ensure   = 'Present'
            UserName = $Credential.UserName
            Password = $Credential
        }

        # Stop the default website
        WebSite DefaultSite
        {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            State           = 'Stopped'
            DependsOn       = '[WindowsFeature]WebScriptingTools'
        }

        WebAppPool $WebSiteName
        {
            Name                           = $WebSiteName
            Ensure                         = 'Present'
            identityType                   = 'SpecificUser'
            Credential                     = $Credential
            idleTimeout                    = (New-TimeSpan -Minutes 0).ToString()
            logEventOnProcessModel         = 'IdleTimeout'
            logEventOnRecycle              = 'Time,Requests,Schedule,Memory,IsapiUnhealthy,OnDemand,ConfigChange,PrivateMemory'
            restartTimeLimit               = (New-TimeSpan -Minutes 0).ToString()
            restartSchedule                = @('00:00:00', '08:00:00', '16:00:00')
            DependsOn                      = '[WindowsFeature]WebScriptingTools'
        }
        
        WebSite $WebSiteName
        {
            Ensure          = 'Present'
            Name            = $WebSiteName
            State           = 'Started'
            PhysicalPath    = $(Split-Path $FilePath -Parent)
            ApplicationPool = $WebSiteName
            DependsOn       = "[WebAppPool]$WebSiteName", '[WindowsFeature]WebScriptingTools'
        }

        Script IISDefaultPage
        {
            GetScript = {
                $Result = [string]$(Get-Content -Path $using:FilePath -ErrorAction Ignore)
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $Result
                }
}
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable,
                # which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ( $state.Result -eq $using:Filecontent )
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
            PSDscAllowPlainTextPassword = $true
        }
    )
}


<#
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
#>

$WebSiteName = 'www.contoso.com'
$UserName = 'IISAppPoolUsr'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force

$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($UserName, $SecurePassword)
IISSetupDSCConfiguration -WebSiteName $WebSiteName -Credential $Credential -ConfigurationData $ConfigurationData
<#
Start-DscConfiguration -Path .\IISSetupDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>