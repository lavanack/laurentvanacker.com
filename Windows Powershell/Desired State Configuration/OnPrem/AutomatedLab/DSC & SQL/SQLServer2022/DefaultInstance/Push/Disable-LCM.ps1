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
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

Set-Location -Path $CurrentDir

[DscLocalConfigurationManager()]
Configuration Disable-LCM
{
	param(
		[string[]] $ComputerName = 'localhost'
	)

	Node $ComputerName
	{
		Settings {
			RefreshMode = 'Disabled'
		}
	}
}

$TargetNodes = 'SQLNODE01', 'SQLNODE02', 'SQLNODE03'
# Generating the LCM MOF file(s)
Disable-LCM  -ComputerName $TargetNodes

# Setting the local LCM configuration
Set-DscLocalConfigurationManager -Path .\Disable-LCM -Verbose

# Getting the local LCM configuration (for checking of the configuration was applied)
Get-DscLocalConfigurationManager