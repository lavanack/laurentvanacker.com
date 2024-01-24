<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

$ConfigurationName = "CreateDefaultInstance"
$RegistrationKey = Get-Content -Path "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt"
$TargetNodes = 'SQLNODE01' #, 'SQLNODE02'
# Generating the LCM MOF file(s)
PullClientRegKey -ComputerName $TargetNodes -ConfigurationName $ConfigurationName -RegistrationKey $RegistrationKey

# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $TargetNodes

# Setting the LCM Configuration on the targeted nodes
Set-DscLocalConfigurationManager -Path .\PullClientRegKey -Verbose -CimSession $TargetNodes

# Getting the LCM Configuration on the targeted nodes
Get-DscLocalConfigurationManager -CimSession $TargetNodes
(Get-DscLocalConfigurationManager -CimSession $TargetNodes).ConfigurationDownloadManagers

# Forcing the configuration to refresh
Update-DscConfiguration -CimSession $TargetNodes -Wait -Verbose

Test-DscConfiguration -ComputerName $TargetNodes -Detailed
