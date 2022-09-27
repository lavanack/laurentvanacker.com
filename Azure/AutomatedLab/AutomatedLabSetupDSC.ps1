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
#requires -Version 5 -Modules PSDscResources, StorageDsc, xHyper-V, xPSDesiredStateConfiguration, ComputerManagementDsc -RunAsAdministrator 

<#
# For installing prerequisites
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module -Name 'PSDscResources', 'StorageDsc', 'xHyper-V', 'xPSDesiredStateConfiguration', 'ComputerManagementDsc' -Force
#>


Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$VSCodeExtension = [ordered]@{
    #"PowerShell" = "ms-vscode.powershell"
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
}

#Import-Module -Name 'PSDscResources', 'StorageDsc', 'xHyper-V', 'xPSDesiredStateConfiguration', 'ComputerManagementDsc' -Force

Configuration AutomatedLabSetupDSC {
    param(
        [ValidateScript({$_ -match "^[E-Z]$"})]
        [string] $DriveLetter = 'F'
    )

    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'PSDscResources'
    Import-DSCResource -ModuleName 'StorageDsc'
    Import-DSCResource -ModuleName 'xHyper-V'
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

        WindowsOptionalFeature  HyperVAll
        {
            Name   = 'Microsoft-Hyper-V-All'
            Ensure = 'Present'
        }

        <#
        PendingReboot RebootAfterHyperVInstall
        {
            Name      = 'RebootNeededAfterHyperVInstall'
            DependsOn = '[WindowsOptionalFeature]HyperVAll'
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
                    Get-Disk -Number 1 | Initialize-Disk
            }

            TestScript = {
                return ((Get-Disk -Number 1).Partitionstyle -ne 'raw')
            }
        }

        WaitForDisk Disk1
        {
            DiskId           = 1
            RetryIntervalSec = 60
            RetryCount       = 60
        }

        Disk AutomatedLabVolume
        {
            DiskId      = 1
            DriveLetter = $DriveLetter
            FSLabel     = 'Data'
            FSFormat    = 'NTFS'
            DependsOn   = '[WaitForDisk]Disk1'
        }

        File GitHubFolder
        {
            DestinationPath = "$($env:SystemDrive)\Source Control\GitHub"
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
            DependsOn       = '[Disk]AutomatedLabVolume'
        }

        xVMHost HyperVHostPaths
        {
            IsSingleInstance    = 'Yes'
            VirtualHardDiskPath = "$($DriveLetter):\Virtual Machines\Hyper-V"
            VirtualMachinePath  = "$($DriveLetter):\Virtual Machines\Hyper-V"
            DependsOn           = '[File]HyperVPath'
        }

	    Script InstallAutomatedLabModule 
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript = {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
                #Install-Module -Name AutomatedLab -RequiredVersion 5.42.0 -SkipPublisherCheck -AllowClobber -Force
                Install-Module -Name AutomatedLab -SkipPublisherCheck -AllowClobber -Force
            }
 
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                # $state = [scriptblock]::Create($GetScript).Invoke()
                return ((Get-InstalledModule -Name 'AutomatedLab' -ErrorAction Ignore) -ne $null)
            }
        }


	    Script InstallAzureLabModule 
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript = {
                $AzModules = "Az.Accounts", "Az.Storage", "Az.Compute", "Az.Network", "Az.Resources", "Az.Websites"
                Install-Module -Name $AzModules -Force -Verbose
            }
 
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                #$state = [scriptblock]::Create($GetScript).Invoke()
                $AzModules = "Az.Accounts", "Az.Storage", "Az.Compute", "Az.Network", "Az.Resources", "Az.Websites"
                $InstalledModule = @((Get-InstalledModule -Name $AzModules -ErrorAction Ignore))
                #return ((([system.linq.enumerable]::Intersect([string[]]$AzModules,[string[]](Get-InstalledModule).Name)) -as [array])).Count -eq $AzModules.Count
                return $($InstalledModule.Count -eq $AzModules.Count)
            }
        }

        Environment DisableAutomatedLabTelemetry
        {
            Name      = 'AUTOMATEDLAB_TELEMETRY_OPTIN'
            Value     = 'False'
            Ensure    = "Present"
            Target    = 'Process', 'Machine'
            DependsOn = '[Script]InstallAutomatedLabModule'
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

	    Script EnableLabHostRemoting 
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript = {
                Enable-LabHostRemoting -Force
            }
 
            TestScript = {
                return Test-LabHostRemoting
            }
            DependsOn = '[Environment]DisableAutomatedLabTelemetry', '[Script]RelaxExecutionPolicy'
        }

        Script AutomatedLabModuleLabSourcesLocation
        {
            GetScript = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
           
            SetScript = {
                New-LabSourcesFolder -DriveLetter $using:DriveLetter
            }
 
            TestScript = {
                return ([boolean]$(Get-LabSourcesLocation))
            }
            DependsOn = '[Script]EnableLabHostRemoting'
        }
        
        xRemoteFile DownloadGit
        {
            DestinationPath = $(Join-Path -Path $env:TEMP -ChildPath 'Git-Latest.exe')
            #To always have the latest Git version for Windows x64
            #Uri            = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.InnerText -eq "64-bit Git For Windows Setup"}).href
            Uri             = 'https://github.com/git-for-windows/git/releases/download/v2.37.1.windows.1/Git-2.37.1-64-bit.exe'
            UserAgent       = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
            Headers         = @{'Accept-Language' = 'en-US'}
        }

        Package InstallGit
        {
            Ensure    = "Present"
            Path      = $(Join-Path -Path $env:TEMP -ChildPath 'Git-Latest.exe')
            Arguments = '/SILENT /CLOSEAPPLICATIONS'
            Name      = "Git"
            ProductId = ""
            DependsOn = "[xRemoteFile]DownloadGit"
        }

	    Script InstallPowerShellCrossPlatform 
        {
            GetScript  = {
                @{
                    GetScript = $GetScript
                    SetScript = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript  = {
                Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
            }
 
            TestScript = {
                return ((Get-ChildItem -Path $env:ProgramFiles -Filter pwsh.exe -Recurse -File -ErrorAction SilentlyContinue) -ne $null)
            }
        }


	    Script InstallVSCode 
        {
            GetScript  = {
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                }
            }
 
            SetScript  = {
                #Variables below are needed by the Install-VSCode.ps1 in this script DSC ressource (Not needed in a normal call)
                $IsLinux   = $false
                $IsMacOS   = $false
                $IsWindows = $true
                $pacMan    = ''
                $AdditionalExtensions = $($using:VSCodeExtension).Values -join ','
                #try is necessary because the addition extensions raised some errors for the moment :code.cmd : (node:4812) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
                try
                {
                    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $AdditionalExtensions" -ErrorAction Ignore -Verbose
                } catch {}
            }
 
            TestScript = {
                return (Test-Path -Path "C:\Program Files\Microsoft VS Code\Code.exe" -PathType Leaf)
            }
            DependsOn  = @("[Script]InstallPowerShellCrossPlatform", "[Package]InstallGit")
        }    


        xRemoteFile DownloadSysinternalsSuiteZipFile
        {
            DestinationPath = $(Join-Path -Path $env:TEMP -ChildPath 'SysinternalsSuite.zip')
            Uri             = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
            UserAgent       = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
            Headers         = @{'Accept-Language' = 'en-US'}
            
        }

        Archive ExpandSysinternalsSuiteZipFile
        {
            Path        = $(Join-Path -Path $env:TEMP -ChildPath 'SysinternalsSuite.zip')
            Destination = 'C:\Tools'
            DependsOn   = '[xRemoteFile]DownloadSysinternalsSuiteZipFile'
        }


	    Script JunctionAutomatedLab-VMs
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
Set-Location -Path $CurrentDir
Try {
    Enable-PSRemoting -Force 
} catch {}
AutomatedLabSetupDSC 

Set-DscLocalConfigurationManager -Path .\AutomatedLabSetupDSC -Force -Verbose
Start-DscConfiguration -Path .\AutomatedLabSetupDSC -Force -Wait -Verbose
#>