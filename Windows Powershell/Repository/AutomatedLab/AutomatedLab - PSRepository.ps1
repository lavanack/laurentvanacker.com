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
[CmdletBinding()]
Param(
)

trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
    $VerbosePreference = $PreviousVerbosePreference
    $ErrorActionPreference = $PreviousErrorActionPreference
    [console]::beep(3000, 750)
    Send-ALNotification -Activity 'Lab started' -Message ('Lab deployment failed !') -Provider (Get-LabConfigurationItem -Name Notifications.SubscribedProviders)
    break
} 
Clear-Host
Import-Module -Name AutomatedLab
try { while (Stop-Transcript) {} } catch {}

#region Helper functions
# Adding certificate exception and TLS 1.2 
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-Process {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$CommandLine,
        [Parameter(Mandatory = $false)]
        [string]$LogDir,
        [switch]$Stdout
    )
    
    Write-Verbose "Running: $CommandLine"
    if ($LogDir) {
        $TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
        $StdErrFile = $(Join-Path -Path $LogDir -ChildPath $("{0}_stderr.txt" -f $TimeStamp))
        $StdOutFile = $(Join-Path -Path $LogDir -ChildPath $("{0}_stdout.txt" -f $TimeStamp))
        Write-Verbose "`$StdErrFile: $StdErrFile"
        Write-Verbose "`$StdOutFile: $StdOutFile"
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $CommandLine -Wait -RedirectStandardOutput $StdOutFile -RedirectStandardError $StdErrFile
        if ($Stdout) {
            Write-Verbose -Message "`r`n$(Get-Content -Path $StdOutFile -Raw)"
        }
        if ((Test-Path -Path $StdErrFile -PathType Leaf) -and ((Get-Item -Path $StdErrFile).Length -gt 0)) {
            Write-Warning -Message "$StdErrFile is not empty. The command line was : $CommandLine"
            Write-Warning -Message "`r`n$(Get-Content -Path $StdErrFile -Raw)"
        }
    }
    else {
        #You'll have to close the prompt Windows by yourself by using [X] at the top right.
        Start-Process -FilePath $env:ComSpec -ArgumentList "/k", $CommandLine -Wait
    }
}
#endregion


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
$Logon = 'administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$PSREPO01IPv4Address = '10.0.0.11'
$PSREPO02IPv4Address = '10.0.0.12'


$MSEdgeEntUri = 'http://go.microsoft.com/fwlink/?LinkID=2093437'

$UserHome = (Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH)
#Run ssh-keygen to generate keys if needed
$SSHPublicKeyPath = Join-Path -Path $UserHome -Child "\.ssh\id_rsa.pub"
$SSHPrivateKeyPath = Join-Path -Path $UserHome -Child "\.ssh\id_rsa"

If (-Not(Test-Path -Path $SSHPublicKeyPath -PathType Leaf)) {
    Write-Error -Exception "The $SSHPublicKeyPath (Public key file) doesn't exist" -ErrorAction Stop
}

If (-Not(Test-Path -Path $SSHPrivateKeyPath -PathType Leaf)) {
    Write-Error -Exception "The $SSHPrivateKeyPath (Private key file) doesn't exist" -ErrorAction Stop
}
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
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:DnsServer1'      = $DC01IPv4Address
    #'Add-LabMachineDefinition:Gateway'         = $DC01IPv4Address
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = 4
}

$PSREPO01NetAdapter = @()
$PSREPO01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PSREPO01IPv4Address -InterfaceName 'Corp'
$PSREPO01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName 'Internet'

$PSREPO02NetAdapter = @()
$PSREPO02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PSREPO02IPv4Address -InterfaceName Corp
$PSREPO02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#Servers for PS Repository
Add-LabMachineDefinition -Name PSREPO01 -NetworkAdapter $PSREPO01NetAdapter
Add-LabMachineDefinition -Name PSREPO02 -OperatingSystem 'CentOS Stream 9' -DomainName contoso.com -NetworkAdapter $PSREPO02NetAdapter -MinMemory 5GB -MaxMemory 5GB -Memory 5GB -SshPublicKeyPath $SSHPublicKeyPath -SshPrivateKeyPath $SSHPrivateKeyPaths
#endregion

#Installing servers
Install-Lab -Verbose
Do {
    Write-Verbose -Message "Sleeping for 1 minute (Waiting PSREPO02 be available on SSH port (TCP/22)) ..." -Verbose
    Start-Sleep -Seconds 60
} While (-Not((Test-NetConnection -ComputerName PSREPO02 -Port 22 -InformationLevel "Detailed").TcpTestSucceeded))

Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Installing Required Windows Features
$machines = Get-LabVM -IncludeLinux
$WindowsServers = $machines | Where-Object -FilterScript { $_.OperatingSystem -like "Windows*" }
$WindowsServerGroupMembers = $WindowsServers | Where-Object -FilterScript { $_.Name -notin "DC01" }
$LinuxServerGroupMembers = $machines | Where-Object -FilterScript { $_ -notin $WindowsServers }

$Jobs = @()
$Jobs += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $WindowsServers -IncludeManagementTools -PassThru -AsJob
#endregion


$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName $WindowsServers -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $WindowsServers -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp (used in the Security lab)
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
    
    #Changing the default Edit action for .ps1 file to open in Powershell ISE
    #Set-ItemProperty -Path Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\Edit\Command -Name "(Default)" -Value "$env:windir\System32\WindowsPowerShell\v1.0\powershell_ise.exe"  -Force
}

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


Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName PSREPO01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

#region Docker PowerShell Repository
#Invoke-Process -CommandLine "ssh -l root PSREPO02 -vvv"
#Switch to french keyboard
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo localectl set-keymap fr" -LogDir $CurrentDir -Stdout -Verbose

#region Docker Setup
#From https://docs.docker.com/engine/install/centos/
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo yum install -y yum-utils" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo systemctl start docker" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo docker run hello-world" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo pwsh -Command 'if (`$(docker ps -a -q)) { docker rm -f `$(docker ps -a -q) }'" -LogDir $CurrentDir -Stdout -Verbose
#endregion

#region Setting up PowerShell Repository
$APIKey = (New-Guid).Guid
Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo docker run --detach=true --publish 5000:80 --env NUGET_API_KEY=$APIKey --volume /srv/docker/nuget/database:/var/www/db --volume /srv/docker/nuget/packages:/var/www/packagefiles --name nuget-server sunside/simple-nuget-server" -LogDir $CurrentDir -Stdout -Verbose

Invoke-Process -CommandLine "ssh -o StrictHostKeyChecking=no root@PSREPO02 sudo pwsh -Command 'docker update --restart always `$(docker ps -q)'" -LogDir $CurrentDir -Stdout -Verbose

Start-Sleep -Seconds 60

Invoke-LabCommand -ActivityName 'Registering Docker PS repository' -ComputerName PSREPO01 -ScriptBlock {
    $uri = 'http://PSREPO02:5000'
    $Parameters = @{
        Name               = 'DockerPSRepository'
        SourceLocation     = $uri
        PublishLocation    = $uri
        InstallationPolicy = 'Trusted'
    }
    Register-PSRepository @Parameters

    #region Publishing Module(s)
    Publish-Module -Name TestModule -Repository $Parameters['Name'] -NuGetApiKey $using:APIKey -Force -Verbose    
    #endregion
}

#Please allow few minutes for the module(s) to show up in the search results.
Start-Sleep -Seconds 600
Invoke-LabCommand -ActivityName "Finding the 'TestModule' PowerShell module in the 'DockerPSrepository' PowerShell Repository" -ComputerName PSREPO01 -ScriptBlock {
    Find-Module -Name TestModule -Repository 'DockerPSRepository'
} -PassThru

#endregion
#endregion

#Waiting for background jobs
$Jobs | Wait-Job | Out-Null

#For updating the GPO
#Restart-LabVM -ComputerName $machines -Wait

Show-LabDeploymentSummary

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference

Checkpoint-LabVM -SnapshotName 'FullInstall' -All
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript