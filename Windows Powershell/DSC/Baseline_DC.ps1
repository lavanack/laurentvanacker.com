#Requires -RunAsAdministrator 
#Requires -Version 4
Clear-Host 
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Set-Location -Path $CurrentDir

$ConfigName = "BaselineDC"
$RegKey = Get-Content -Path "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
$ServerURL = "https://PULL.contoso.com:8080/PSDSCPullServer.svc"
#If you want dynamically get the list of all Domain Controllers
Install-WindowsFeature -Name RSAT-AD-Tools
#$DomainControllers = "DC01"
$DomainControllers = (Get-ADDomainController).HostName

#region Definfing the DSC configuration
# Baseline de configuration des controleurs de domaine
Configuration BaselineDC
{
	param (
        [string[]]$ComputerName = 'localhost'
    )

	Import-DscResource -ModuleName PSDesiredStateConfiguration
	Node $ComputerName 
    {
        WindowsFeature ActiveDirectory
        #verification de la presence du role Active Directory
        #2008R2 / 2016
        {
            Name = "AD-Domain-Services"
            Ensure = "Present"
        }
    
        WindowsFeature DNS
        #verification de la presence du role DNS
        #2008R2 / 2016
        {
            Name = "DNS"
            DependsOn = '[WindowsFeature]ActiveDirectory'
            Ensure = "Present"
        }
    
        Service Firewall
        #Parametrage du service firewall en adequation avec les conditions de support Microsoft
        #https://technet.microsoft.com/fr-fr/library/cc766337(v=ws.10).aspx
        #2008R2 / 2016
        {
            name = "MPSSvc"
            ensure = "Present"
            startuptype = "automatic"
            BuiltInAccount = "LocalService"
        }
        Service WindowsUpdate
        #Parametrage du service firewall en adequation avec les conditions de support Microsoft
        #https://technet.microsoft.com/fr-fr/library/cc766337(v=ws.10).aspx
        #2008R2 / 2016
        {
            name = "wuauserv"
            ensure = "Present"
            startuptype = "Manual"
            BuiltInAccount = 'LocalSystem'
        }

        Service Winrm
        #Parametrage du service WinRM
        #2008R2 / 2016
        {
            name = "Winrm"
            ensure = "Present"
            startuptype = "automatic"
            BuiltInAccount = "NetworkService"
        }

        Registry IPv6
        #Configuration du protocole IPv6 pour désactivation
        #https://support.microsoft.com/en-us/help/929852/how-to-disable-ipv6-or-its-components-in-windows
        #2008R2 / 2016
        {
            key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
            valuename = "DisabledComponents"
            ensure = "Present"
            hex = $true
            valuedata = "0xff"
            valuetype = "Dword"
        }

        Registry AutoAdminLogon
        #Configuration autologon https://technet.microsoft.com/fr-FR/library/cc939702.aspx
        #2008R2 Review if applicable for Windows Server 2016
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            ValueName = "AutoAdminLogon"
            ValueData = "0"
            ValueType = "String"
        }

        Registry EnableTCPChimney
        #https://support.microsoft.com/en-us/help/951037/information-about-the-tcp-chimney-offload,-receive-side-scaling,-and-network-direct-memory-access-features-in-windows-server-2008
        #2008R2 (Value 1) /Windows Server 2012 and above (Value 0)
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            ValueName = "EnableTCPChimney"
            ValueData = "0"
            ValueType = "Dword"
        }
        
        Registry EnableTCPA
        #https://support.microsoft.com/en-us/help/951037/information-about-the-tcp-chimney-offload,-receive-side-scaling,-and-network-direct-memory-access-features-in-windows-server-2008
        #2008R2 (Value 1) /Windows Server 2012 and above (Value 0)
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            ValueName = "EnableTCPA"
            ValueData = "0"
            ValueType = "Dword"
        }
    
        Registry TaskOffload
        #https://docs.microsoft.com/en-us/windows-hardware/drivers/network/using-registry-values-to-enable-and-disable-task-offloading
        #2008R2 Windows Server 2012 and above 
        {
            Ensure = "Present"  
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            ValueName = "DisableTaskOffload"
            ValueData = "0"
            ValueType = "Dword"
        }
    }
}
#endregion

#region Setting up the DSC configuration on the the PULL server(s)
BaselineDC

#Copy-Item -Path .\BaselineDC\localhost.mof -Destination "C:\Program Files\WindowsPowerShell\DscService\Configuration\$ConfigName.mof"
#New-DscChecksum "C:\Program Files\WindowsPowerShell\DscService\Configuration\$ConfigName.mof" -Force
Remove-Item ".\BaselineDC\$ConfigName.mof" -Force -ErrorAction Ignore
Rename-Item -Path .\BaselineDC\localhost.mof -NewName "$ConfigName.mof"
Import-Module xPSDesiredStateConfiguration
Publish-DSCModuleAndMof -Source .\BaselineDC -Force

Get-ChildItem -Path 'C:\Program Files\WindowsPowerShell\DscService\Configuration\'
#endregion

#region Setting up the LCM on the target node(s)

[DSCLocalConfigurationManager()]
configuration LCMBaselineDC
{
	param (
        [string[]]$ComputerName = 'localhost'
    )

	Node $ComputerName 
	{
		Settings
		{
			RefreshMode = 'Pull'
			RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyAndAutoCorrect"
		}
		ConfigurationRepositoryWeb PullServer
		{
			ServerURL = $ServerURL
			RegistrationKey = $RegKey
			ConfigurationNames = @($ConfigName)
			AllowUnsecureConnection = $true
		}      

        ReportServerWeb CONTOSO-PullSrv
        {
            ServerURL       = $ServerURL
            RegistrationKey = $RegKey
            AllowUnsecureConnection = $true
        }
	}
}


# Generating the LCM MOF file(s)
LCMBaselineDC -ComputerName $DomainControllers

$DCCimSession = New-CimSession -ComputerName $DomainControllers #-Credential (Get-Credential)
# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $DCCimSession

# Setting the LCM Configuration on the targeted nodes
Set-DscLocalConfigurationManager -Path .\LCMBaselineDC -Verbose -CimSession $DCCimSession

# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $DCCimSession
(Get-DscLocalConfigurationManager -CimSession $DCCimSession).ConfigurationDownloadManagers

# Forcing the configuration to refresh
Update-DscConfiguration -CimSession $DCCimSession -Wait -Verbose
#endregion

Restart-Computer -ComputerName $DomainControllers -Force -Wait