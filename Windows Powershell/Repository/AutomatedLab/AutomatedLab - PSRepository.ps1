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
#requires -Version 5 -Modules AutomatedLab -RunAsAdministrator 
trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
} 
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
#$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$PSREPO01IPv4Address = '10.0.0.11'

$LabName = 'PSRepository'

#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
} -AddressSpace $NetworkID
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }


#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = 4
}

$PSREPO01NetAdapter = @()
$PSREPO01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PSREPO01IPv4Address -InterfaceName 'Corp'
$PSREPO01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName 'Internet'

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name PSREPO01 -NetworkAdapter $PSREPO01NetAdapter -MinMemory 6GB -MaxMemory 6GB -Memory 6GB -Processors 2
#endregion

#Installing servers
Install-Lab -Verbose
Checkpoint-LabVM -SnapshotName FreshInstall -All
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Enabling Nested Virtualization on PSREPO01
#Restarting all VMs
Stop-LabVM -All -Wait
Set-VMProcessor -VMName PSREPO01 -ExposeVirtualizationExtensions $true
Start-LabVM -All -Wait
#endregion

#region Installing Required Windows Features
$machines = Get-LabVM -All
$Jobs = @()
$Jobs += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -PassThru -AsJob
#endregion

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD Setup & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.MicrosoftEdge::PreventFirstRunPage
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main' -ValueName "PreventFirstRunPage" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    #https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::HideFirstRunExperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\WireShark\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion
}

Install-LabWindowsFeature -FeatureName Web-Server, Web-Mgmt-Console, Web-Asp-Net45 -ComputerName PSREPO01 -IncludeManagementTools -PassThru

Invoke-LabCommand -ActivityName 'French KeyBoard Setup' -ComputerName $machines -ScriptBlock {
    Set-WinUserLanguageList fr-fr -Force
}

<#
Checkpoint-LabVM -SnapshotName BeforeDockerSetup -All
#Restore-LabVMSnapshot -SnapshotName BeforeDockerSetup -All -Verbose

1..2 | ForEach-Object -Process {
    #We have to run twice : 1 run form the HyperV and containers setup (reboot required) and 1 run for the docker setup
    Invoke-LabCommand -ActivityName 'Docker Setup' -ComputerName PSREPO01 -ScriptBlock {
        #From https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=dockerce#windows-server-1
        Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1) } -HyperV -NoRestart -Verbose"

        Set-Location -Path $env:Temp
        ##Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-DockerCE/install-docker-ce.ps1" -OutFile install-docker-ce.ps1
        #.\install-docker-ce.ps1 -HyperV -Force -Verbose
        #.\install-docker-ce.ps1 -NoRestart -HyperV

    } -Verbose
    Restart-LabVM -ComputerName PSREPO01 -Wait
}

Checkpoint-LabVM -SnapshotName DockerSetup -All
#Restore-LabVMSnapshot -SnapshotName 'DockerSetup' -All -Verbose
#>

Invoke-LabCommand -ActivityName 'Creating a Test PowerShell Module' -ComputerName PSREPO01 -ScriptBlock {
    Get-PackageProvider -Name Nuget -ForceBootstrap -Force
    $ModuleName = "TestModule"
    $ModuleVersion = '1.0.0.0'
    $PSModulePath = Join-Path -Path $($env:ProgramFiles) -ChildPath "WindowsPowerShell\Modules"
    $ModuleVersionFolder = Join-Path -Path $PSModulePath -ChildPath "$ModuleName\$ModuleVersion"
    $ModuleFilePath = Join-Path -Path $ModuleVersionFolder -ChildPath "$ModuleName.psm1"
    $ModuleManifestFilePath = Join-Path -Path $ModuleVersionFolder -ChildPath "$ModuleName.psd1"
    #$FunctionToExport = 'Test-Domaincontroller', 'Install-RequiredModule', 'Connect-Azure', 'Register-AzRequiredResourceProvider', 'Install-FSLogixGPOSetting', 'Install-AVDGPOSetting', 'New-AzHostPoolSessionCredentialKeyVault', 'Reset-PooledHostPoolIndex', 'Reset-PersonalHostPoolIndex', 'Set-PooledHostPoolIndex', 'Set-PersonalHostPoolIndex', 'Get-PooledHostPoolIndex', 'Get-PersonalHostPoolIndex', 'New-PooledHostPool', 'New-PersonalHostPool', 'New-AzureComputeGallery', 'Remove-AzAvdHostPoolSetup', 'Test-AzAvdStorageAccountNameAvailability', 'Test-AzAvdKeyVaultNameAvailability', 'New-AzAvdHostPoolBackup', 'New-AzAvdHostPoolSetup', 'New-AzAvdScalingPlan', 'New-AzAvdRdcMan', 'Restart-AzAvdSessionHost', 'Start-MicrosoftEntraIDConnectSync', 'Invoke-AzAvdOperationalInsightsQuery'
    $FunctionToExport = 'Test-Function1', 'Test-Function2', 'Test-Function3'

    $moduleSettings = @{
        Path                   = $ModuleManifestFilePath
        Author                 = $(whoami)
        PowerShellVersion      = '5.1'
        FunctionsToExport      = $FunctionToExport
        Description            = 'Test Module'
        ModuleVersion          = $ModuleVersion
        Tags                   = 'Test'
        RootModule             = Split-Path -Path $ModuleFilePath -Leaf
        CompatiblePSEditions   = 'Desktop'
        Copyright              = $(Get-Date -Format yyyy)
        DotNetFrameworkVersion = '4.0'
        CLRVersion             = '4.0'
    }

    $FunctionPattern = @'

    function <FUNCTION> {
        [CmdletBinding()]
        Param (
        )
        return "Hello World !"
    }
'@

    $FunctionContent = $FunctionToExport | ForEach-Object -Process {
        $FunctionPattern -replace '\<FUNCTION\>', $_
    }

    $ModuleFileContent = @"
    $FunctionContent

    Export-ModuleMember -Function $($FunctionToExport -join ', ')
"@

    Remove-Module -Name $ModuleName -Force -Verbose -ErrorAction Ignore
    $null = New-Item -Path $ModuleFilePath -ItemType File -Value $ModuleFileContent -Force
    New-ModuleManifest @moduleSettings

    Get-Module -Name $ModuleName -ListAvailable
    Get-Command -Module $ModuleName
    (Get-Module -Name $ModuleName -ListAvailable).ModuleBase
    Remove-Module -Name $ModuleName -Force -Verbose -ErrorAction Ignore
}


#region SMB Share PowerShell Repository
Checkpoint-LabVM -SnapshotName BeforeSMBRepo -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeSMBRepo' -All -Verbose

#From https://powershellexplained.com/2017-05-30-Powershell-your-first-PSScript-repository/
Invoke-LabCommand -ActivityName 'Setting up SMB Share Repository' -ComputerName PSREPO01 -ScriptBlock {
    #region Setting up PowerShell Repository
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $Name = "SMBPSRepository"
    $Path = "C:\{0}\{1}" -f $using:LabName, $Name
    $null = New-Item -Path $Path -ItemType Directory -Force
    $SmbShare = New-SmbShare -Name $Name -Path $Path -FullAccess "Administrators" -ReadAccess "Everyone"
    Import-Module PowerShellGet

    $URI = "\\{0}\$Name" -f $env:COMPUTERNAME
    $Parameters = @{
        Name               = $Name
        SourceLocation     = $URI
        PublishLocation    = $URI
        InstallationPolicy = 'Trusted'
    }
    Register-PSRepository @Parameters
    #endregion

    #region Publishing Module(s)
    Publish-Module -Name TestModule -Repository $Parameters['Name'] -Force -Verbose

    Find-Module -Name TestModule -Repository $Parameters['Name']
    #endregion
} -PassThru
#endregion 

#region IIS PowerShell Repository
Checkpoint-LabVM -SnapshotName BeforeIISRepo -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeIISRepo' -All -Verbose

$LocalPath = Copy-LabFileItem -Path $CurrentDir\NuGetRepository.zip -DestinationFolderPath C:\ -ComputerName PSREPO01 -PassThru

#From https://pscustomobject.github.io/powershell/howto/Setup-Internal-PowerShell-Repository/
Invoke-LabCommand -ActivityName 'Setting up IIS Repository' -ComputerName PSREPO01 -ScriptBlock {
    #region Setting up PowerShell Repository
    Import-Module -Name WebAdministration
    $Path = "C:\{0}\IIS" -f $using:LabName
    $WebSiteName = $using:LabName
    $null = New-Item -Path $Path, $(Join-Path -Path $Path -ChildPath "Packages") -ItemType Directory -Force
    Copy-Item -Path C:\inetpub\wwwroot\* $Path -Recurse -Force
    #Replicating the required IIS ACL
    Get-Acl -Path C:\inetpub\wwwroot | Set-Acl -Path $Path
    Get-WebSite | Remove-WebSite #-Name "Default Web Site"

    New-WebAppPool -Name $WebSiteName -Force
    New-WebSite -Name $WebSiteName -Port 80 -PhysicalPath $Path -ApplicationPool $WebSiteName -Force
    Expand-Archive -Path $using:LocalPath -DestinationPath $Path -Force
    ConvertTo-WebApplication -PSPath "IIS:\Sites\$WebSiteName\NuGetRepository"
    #Generating an optional API Key 
    $APIKey = (New-Guid).Guid
    
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($using:LabName)/NuGetRepository"  -filter "appSettings/add[@key='requireApiKey']" -name "value" -value "false"
    #Disabling all authentications
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($using:LabName)/NuGetRepository"  -filter "appSettings/add[@key='apiKey']" -name "value" -value $APIKey


    $URI = 'http://psrepo01/NuGetRepository/nuget'
    $Parameters = @{
        Name               = 'IISPSRepository'
        SourceLocation     = $URI
        PublishLocation    = $URI
        InstallationPolicy = 'Trusted'
    }

    Register-PSRepository @Parameters
    #endregion

    #region Publishing Module(s)
    Publish-Module -Name TestModule -Repository $Parameters['Name'] -NuGetApiKey $APIKey -Force -Verbose    

    Find-Module -Name TestModule -Repository $Parameters['Name']
    #endregion
} -PassThru
#endregion

#region Github PowerShell Repository

<# DOESN'T WORK: https://stackoverflow.com/questions/54367822/powershell-find-package-command-doesnt-work-with-nuget-v3-package-source
#region PowerShellGet
#From https://stackoverflow.com/questions/75597606/is-it-possible-to-install-module-from-public-github-packages-location
Checkpoint-LabVM -SnapshotName BeforeGitHubRepo -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeGitHubRepo' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up Github Repository' -ComputerName PSREPO01 -ScriptBlock {
    #region Setting up PowerShell Repository
    $APIKey = "Put Your Own API Key"
    # Define clear text string for username and password
    $UserName = 'Put Your Own GitHub User Name'

    # Convert to SecureString
    $SecurePassword = ConvertTo-SecureString $APIKey -AsPlainText -Force

    $Credential = [System.Management.Automation.PSCredential]::new($UserName, $SecurePassword)

    $URI = "https://nuget.pkg.github.com/$UserName/index.json"
    $Parameters = @{
        Name = 'GitHubPSRepository'
        SourceLocation = $URI
        PublishLocation = $URI
        InstallationPolicy = 'Trusted'
        Credential  = $Credential 
    }

    Get-PSRepository -Name $Parameters['Name'] -ErrorAction Ignore | Unregister-PSRepository -Verbose
    Register-PSRepository @Parameters
    #endregion

    #region Publishing Module(s)
    Publish-Module -Name TestModule -Repository $Parameters['Name'] -NuGetApiKey $APIKey -Credential $Credential -Force -Verbose
    #endregion
}
#endregion
#>

#region PSResourceGet
#From https://learn.microsoft.com/en-us/powershell/gallery/powershellget/supported-repositories?view=powershellget-3.x#publish-to-github-packages
Checkpoint-LabVM -SnapshotName BeforeGitHubRepo -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeGitHubRepo' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up Github Repository' -ComputerName PSREPO01 -ScriptBlock {
    #region PSResourceGet
    #region Setting up PowerShell Repository
    $APIKey = "Put Your Own API Key"
    # Define clear text string for username and password
    $UserName = 'Put Your Own GitHub User Name'

    # Convert to SecureString
    $SecurePassword = ConvertTo-SecureString $APIKey -AsPlainText -Force

    $Credential = New-Object System.Management.Automation.PSCredential ($UserName, $SecurePassword)

    Install-Module -Name Microsoft.PowerShell.PSResourceGet -Scope AllUsers -Force -Verbose
    $URI = "https://nuget.pkg.github.com/$UserName/index.json"
    $Parameters = @{
        Name    = 'GitHubPSRepository'
        URI     = $URI
        Trusted = $true
    }

    Get-PSResourceRepository -Name $Parameters['Name'] -ErrorAction Ignore | Unregister-PSResourceRepository -Verbose
    Register-PSResourceRepository @Parameters    
    #endregion

    #region Publishing Module(s)
    $Path = (Get-Module -Name TestModule -ListAvailable).ModuleBase
    Publish-PSResource -Path $Path -Repository $Parameters['Name'] -ApiKey $APIKey -Credential $Credential -Verbose

    Find-PSResource -Name TestModule -Repository $Parameters['Name'] -Credential $Credential
    #endregion

} -PassThru
#endregion
#endregion

#endregion

<# TO BE COMPLETED ==> Work only with Linux containers
#region Docker PowerShell Repository
Checkpoint-LabVM -SnapshotName BeforeDockerRepo -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeDockerRepo' -All -Verbose

#From https://powershellexplained.com/2018-03-03-Powershell-Using-a-NuGet-server-for-a-PSRepository/?utm_source=blog&utm_medium=blog&utm_content=psscriptrepo
Invoke-LabCommand -ActivityName 'Docker Configuration' -ComputerName PSREPO01 -ScriptBlock {

    #region Setting up PowerShell Repository
    Start-Service Docker
    #Pulling IIS image
    #docker pull mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

    #Stopping all previously running containers if any
    if ($(docker ps -a -q)) {
        docker stop 
        #To delete all containers
        docker rm -f $(docker ps -a -q)
    }

    $null = New-Item -Path C:\Images\nuget\database, C:\Images\nuget\packages -ItemType Directory -Force
    $APIKey = New-Guid
    $arguments = @(
        'run'
        '--detach=true'
        '--publish 80:80'
        '--env', "NUGET_API_KEY=$APIKey"
        '--volume', 'C:\Images\nuget\database:/var/www/db'
        '--volume', 'C:\Images\nuget\packages:/var/www/packagefiles'
        '--name', 'nuget-server'
        'sunside/simple-nuget-server'
        '--restart always'
    )

    Start-Process Docker -ArgumentList $arguments -NoNewWindow

    #Getting the IP v4 address of the container
    $ContainerIPv4Address = (docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" $Name | Out-String) -replace "`n"
    Write-Host "The internal IPv4 address for the container [$Name] is [$ContainerIPv4Address]" -ForegroundColor Yellow

    docker update --restart always $(docker ps -q)
    #endregion

    #region Publishing Module(s)
    $URI = 'http://localhost'
    $Parameters = @{
        Name = 'DockerPSRepository'
        SourceLocation = $URI
        PublishLocation = $URI
        InstallationPolicy = 'Trusted'
    }
    Register-PSRepository @Parameters
    Publish-Module -Name TestModule -Repository $Parameters['Name'] -NuGetApiKey $APIKey -Force -Verbose
    #endregion
} -Verbose
#endregion
#>

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName PSREPO01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

#Waiting for background jobs
$Jobs | Wait-Job | Out-Null

#For updating the GPO
Restart-LabVM -ComputerName $machines -Wait

Show-LabDeploymentSummary -Detailed

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference

Checkpoint-LabVM -SnapshotName 'FullInstall' -All
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript