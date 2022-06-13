#Mode details on https://automatedlab.org/en/latest/Wiki/Basic/install/
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
#requires -Version 5 -Modules PSDscResources, NetworkingDsc -RunAsAdministrator 
#Azure ARC : OnBoarding an Azure VM

<#
#From https://docs.microsoft.com/en-us/azure/azure-arc/servers/plan-evaluate-on-azure-virtual-machine
Get-Service WindowsAzureGuestAgent | Stop-Service -PassThru | Set-Service -StartupType Disabled
New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
#>

<#
# For installing required PowerShell modules
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSDscResources, NetworkingDsc -Force
#>


Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

Import-Module -Name 'PSDscResources' -Force

Configuration AzureVMAzureArcOnBoardingPreRequisitesDSC {
    param(
    )

    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'PSDscResources' 
    Import-DSCResource -ModuleName 'NetworkingDsc' 

    Node localhost 
    {
        LocalConfigurationManager 
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            ActionAfterReboot = 'ContinueConfiguration'
        }
        
        #region Disabling IE Enhanced Security
        #Alternative https://github.com/dsccommunity/ComputerManagementDsc/wiki/IEEnhancedSecurityConfiguration
        Registry DisableIESCForAdmins
        {
			Key       = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
			ValueName = 'IsInstalled'
			ValueData = '0'
			ValueType = 'DWORD'
			Ensure    = 'Present'
		}		

        Registry DisableIESCForUsers
        {
			Key       = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
			ValueName = 'IsInstalled'
			ValueData = '0'
			ValueType = 'DWORD'
			Ensure    = 'Present'
            DependsOn = "[Registry]DisableIESCForAdmins"
		}		
        #endregion

        #region Azure ARC : OnBoarding an Azure VM
        Service WindowsAzureGuestAgent
        {
            Name        = "WindowsAzureGuestAgent"
            StartupType = 'Disabled'
            State       = 'Stopped'
        }

        Firewall BlockAzureIMDS
        {
            Name                  = 'BlockAzureIMDS'
            DisplayName           = 'Block access to Azure IMDS'
            Ensure                = 'Present'
            Enabled               = 'True'
            Profile               = 'Any'
            Direction             = 'OutBound'
            Protocol              = 'TCP'
            Action                = 'Block'
            RemoteAddress         = '169.254.169.254'
        }  
        #endregion
    }
}

<#
Set-Location -Path $CurrentDir
Try {
    Enable-PSRemoting -Force 
} catch {}
AzureVMAzureArcOnBoardingPreRequisitesDSC 

Set-DscLocalConfigurationManager -Path .\AzureVMAzureArcOnBoardingPreRequisitesDSC -Force -Verbose
Start-DscConfiguration -Path .\AzureVMAzureArcOnBoardingPreRequisitesDSC -Force -Wait -Verbose
#>
