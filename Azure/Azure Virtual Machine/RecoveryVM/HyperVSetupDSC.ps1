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
#requires -Version 5 -Modules PSDscResources, StorageDsc, HyperVDsc, xPSDesiredStateConfiguration, ComputerManagementDsc -RunAsAdministrator 

<#
# For installing prerequisites
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module -Name 'PSDscResources', 'StorageDsc', 'xPSDesiredStateConfiguration', 'ComputerManagementDsc' -Force -Verbose 
Install-Module -Name HyperVDsc -AllowPrerelease -Force -Verbose 
#>

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#Import-Module -Name 'PSDscResources', 'HyperVDsc', 'xPSDesiredStateConfiguration', 'ComputerManagementDsc' -Force

Configuration HyperVSetupDSC {
    param(
        [ValidateScript({$_ -match "^[E-Z]$"})]
        [string] $DriveLetter = 'F',
        [ValidateScript({$_  -gt 0})]
        [int16] $DiskId = 1
    )

    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'PSDscResources'
    Import-DSCResource -ModuleName 'StorageDsc'
    Import-DSCResource -ModuleName 'HyperVDsc'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc'

    Node localhost 
    {
        LocalConfigurationManager 
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
            ActionAfterReboot = 'ContinueConfiguration'
        }

        Registry DisablePrivacyExperience
        {
			Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE'
			ValueName = 'DisablePrivacyExperience'
			ValueData = '1'
			ValueType = 'DWORD'
			Ensure    = 'Present'
		}		

        IEEnhancedSecurityConfiguration 'DisableForAdministrators'
        {
            Role    = 'Administrators'
            Enabled = $false
        }
        
        IEEnhancedSecurityConfiguration 'DisableForUsers'
        {
            Role    = 'Users'
            Enabled = $false
        }
        
        WindowsFeature HyperV {
            Name                 = 'Hyper-V'
            Ensure               = 'Present'
        }
        
        WindowsFeature RSATHyperVTools {
            Name                 = 'RSAT-Hyper-V-Tools'
            Ensure               = 'Present'
            DependsOn            = '[WindowsFeature]HyperV'
        }
        

         
        <#
        PendingReboot RebootAfterHyperVInstall
        {
            Name      = 'RebootNeededAfterHyperVInstall'
            DependsOn = '[WindowsFeature]HyperV'
        }
        #>
        
	    Script InitializeDisk 
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript = {
                    Get-Disk -Number $using:DiskId | Initialize-Disk
            }

            TestScript = {
                return ((Get-Disk -Number $using:DiskId).Partitionstyle -ne 'raw')
            }
        }

        WaitForDisk "Disk$DiskId"
        {
            DiskId           = $DiskId
            RetryIntervalSec = 60
            RetryCount       = 60
        }
        
        Disk DataDisk
        {
            DiskId      = $DiskId
            DriveLetter = $DriveLetter
            FSLabel     = 'Data'
            FSFormat    = 'NTFS'
            DependsOn   = "[WaitForDisk]Disk$DiskId"
        }

        File TempFolder
        {
            DestinationPath = "$($env:SystemDrive)\Temp"
            Type            = 'Directory'
            Ensure          = "Present"
            Force           = $true
        }

        File HyperVPath
        {
            DestinationPath = "$($DriveLetter):\Virtual Machines\Hyper-V"
            Type            = 'Directory'
            Ensure          = "Present"
            Force           = $true
            DependsOn       = "[Disk]DataDisk"
        }

        VMHost HyperVHostPaths
        {
            IsSingleInstance    = 'Yes'
            VirtualHardDiskPath = "$($DriveLetter):\Virtual Machines\Hyper-V"
            VirtualMachinePath  = "$($DriveLetter):\Virtual Machines\Hyper-V"
            DependsOn           = '[File]HyperVPath', '[WindowsFeature]RSATHyperVTools'
        }

	    Script RelaxExecutionPolicy 
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript = {
                Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force
            }
 
            TestScript = {
                return ((Get-ExecutionPolicy -Scope LocalMachine) -eq 'Unrestricted')
            }
        }

        xRemoteFile DownloadSysinternalsSuiteZipFile
        {
            DestinationPath = "$env:SystemDrive\Temp\SysinternalsSuite.zip"
            Uri             = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
            UserAgent       = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
            Headers         = @{'Accept-Language' = 'en-US'}
            MatchSource     = $false
            DependsOn       = '[File]TempFolder'            
        }

        Archive ExpandSysinternalsSuiteZipFile
        {
            Path        = "$env:SystemDrive\Temp\SysinternalsSuite.zip"
            Destination = 'C:\Tools'
            DependsOn   = '[xRemoteFile]DownloadSysinternalsSuiteZipFile'
            Force       = $true
        }

        {
            GetScript  = {
                @{
                    GetScript = $GetScript
                    SetScript = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript  = {
                $null = New-Item -Path "$($using:DriveLetter):\AutomatedLab-VMs" -ItemType Directory -Force
                Start-Process -FilePath C:\Tools\junction.exe -ArgumentList '-accepteula', "C:\AutomatedLab-VMs", "$($using:DriveLetter):\AutomatedLab-VMs" -Wait
            }
 
            TestScript = {
                return (Test-Path -Path "$($using:DriveLetter):\AutomatedLab-VMs" -PathType Container)

            }
            DependsOn = '[Script]InstallAutomatedLabModule'
        }    
    }
}

<#
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
Try {
    Enable-PSRemoting -Force 
} catch {}
HyperVSetupDSC -DIskId 2 -ConfigurationData $CurrentDir\ConfigurationData.psd1


Set-DscLocalConfigurationManager -Path .\HyperVSetupDSC -Force -Verbose
Start-DscConfiguration -Path .\HyperVSetupDSC -Force -Wait -Verbose
(Test-DscConfiguration -Detailed).ResourcesNotInDesiredState.ResourceId
Start-DscConfiguration -UseExisting -Force -Wait -Verbose
#>