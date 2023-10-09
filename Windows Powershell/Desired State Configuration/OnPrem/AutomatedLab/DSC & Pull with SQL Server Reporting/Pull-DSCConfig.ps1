#requires -Version 5 -RunAsAdministrator 

Clear-Host 
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

Set-Location -Path $CurrentDir

[DSCLocalConfigurationManager()]
configuration PullClientRegKey
{
	param(
        [string[]] $ComputerName = 'localhost',
        [string] $RegistrationKey,
        [string[]] $ConfigurationName
    )
    Node $ComputerName
	{
		Settings
		{
			RefreshMode = 'Pull'
			RefreshFrequencyMins = 30 
			RebootNodeIfNeeded = $true
		}
		ConfigurationRepositoryWeb PullServer
		{
			ServerURL = 'https://PULL.contoso.com/PSDSCPullServer.svc'
			RegistrationKey = $RegistrationKey
			ConfigurationNames = $ConfigurationName
		}      
		ReportServerWeb  PullServer
		{
			ServerURL = 'https://PULL.contoso.com/PSDSCPullServer.svc'
			RegistrationKey = $RegistrationKey
		}      
	}
}

$RegistrationKey = Get-Content -Path "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt"
$TargetNodes = 'ms1','ms2'
# Generating the LCM MOF file(s)
PullClientRegKey -ComputerName $TargetNodes -ConfigurationName PullTestConfig -RegistrationKey $RegistrationKey

# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $TargetNodes

# Setting the LCM Configuration on the targeted nodes
Set-DscLocalConfigurationManager -Path .\PullClientRegKey -Verbose -CimSession $TargetNodes

# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $TargetNodes
(Get-DscLocalConfigurationManager -CimSession $TargetNodes).ConfigurationDownloadManagers

# Forcing the configuration to refresh
Update-DscConfiguration -CimSession $TargetNodes -Wait -Verbose

# Testing if the path exists
Invoke-Command -ComputerName $TargetNodes -ScriptBlock { Test-Path 'C:\MyTemp'}