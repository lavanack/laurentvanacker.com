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
#requires -Version 5 -Modules AutomatedLab, iSCSIDsc -RunAsAdministrator 

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

$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$10YearsFromNow = $Now.AddYears(10)
$CertValidityPeriod = New-TimeSpan -Start $Now -End $10YearsFromNow
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$PSWSAppPoolUsr = 'PSWSAppPoolUsr'

#SQL Server
$SQLServer2019EnterpriseISO = "$labSources\ISOs\en_sql_server_2019_enterprise_x64_dvd_5e1ecc6b.iso"

$NetworkID = '10.0.0.0/16' 
$DCIPv4Address = '10.0.0.1'
$PULLIPv4Address = '10.0.0.11'
$SQLIPv4Address = '10.0.0.21'
$MS1IPv4Address = '10.0.0.101'
$MS2IPv4Address = '10.0.0.102'

#URI for the PowerBI Desktop
$PBIDesktopX64Uri = "https://download.microsoft.com/download/8/8/0/880BCA75-79DD-466A-927D-1ABF1F5454B0/PBIDesktopSetup_x64.exe"
#URI for MS Edge
$MSEdgeEntUri = 'http://go.microsoft.com/fwlink/?LinkID=2093437'
#SQL Server Management Studio
$SQLServerManagementStudioURI = 'https://aka.ms/ssmsfullsetup'

$LabName = 'DSCSQLReporting'
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{ SwitchType = 'Internal' } -AddressSpace $NetworkID
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }


#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the Machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the Machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 2GB
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:Memory'          = 4GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 2
}

$PULLNetAdapter = @()
$PULLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $PULLIPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$PULLNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC -Roles RootDC, CARoot -IpAddress $DCIPv4Address
#PULL Server
Add-LabMachineDefinition -Name PULL -NetworkAdapter $PULLNetAdapter
#Member server
Add-LabMachineDefinition -Name MS1 -IpAddress $MS1IPv4Address
#Member server
Add-LabMachineDefinition -Name MS2 -IpAddress $MS2IPv4Address 
#SQL Server
$SQLServer2019Role = Get-LabMachineRoleDefinition -Role SQLServer2019
Add-LabIsoImageDefinition -Name SQLServer2019 -Path $SQLServer2019EnterpriseISO
Add-LabMachineDefinition -Name SQL -Roles $SQLServer2019Role -IpAddress $SQLIPv4Address -Processors 4 #-Memory 4GB -MinMemory 2GB -MaxMemory 4GB
#endregion

#Installing servers
Install-Lab -Verbose
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName FreshInstall -All -Verbose

#region Installing Required Windows Features
$AllLabVMs = Get-LabVM
$TargetNodes = $AllLabVMs | Where-Object -FilterScript { -not($_.Roles) -and ($_.Name -notmatch 'BUILD|PULL')}


$Jobs = @()
$Jobs += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $AllLabVMs -IncludeManagementTools -AsJob -PassThru
$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName $AllLabVMs -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru
#Installing PowerBI Desktop on the SQL Server (or any machine in the lab)
$PBIDesktopX64 = Get-LabInternetFile -Uri $PBIDesktopX64Uri -Path $labSources\SoftwarePackages -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName PULL -Path $PBIDesktopX64.FullName -CommandLine "-quiet -norestart LANGUAGE=en-us ACCEPT_EULA=1 INSTALLDESKTOPSHORTCUT=0" -AsJob -PassThru
#region Installing SQL Management Studio on the SQL Server Nodes
$SQLServerManagementStudio = Get-LabInternetFile -Uri $SQLServerManagementStudioURI -Path $labSources\SoftwarePackages -FileName 'SSMS-Setup-ENU.exe' -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName SQL -Path $SQLServerManagementStudio.FullName -CommandLine "/install /passive /norestart" -AsJob -PassThru
#endregion

#cf. https://docs.microsoft.com/en-us/archive/blogs/fieldcoding/visualize-dsc-reporting-with-powerbi#powerbi---the-interesting-part
#Copying the DSC Dashboard on the machine where you have installed PowerBI Desktop 
Copy-LabFileItem -Path "$CurrentDir\DSC Dashboard.pbix" -ComputerName PULL
#Coping the PowerShell Script to have a local report of the DSC deployments
Copy-LabFileItem -Path "$CurrentDir\Get-DSC*.ps1" -ComputerName $TargetNodes
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC & TLS 1.3" -ComputerName $AllLabVMs -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force
    Rundll32 iesetup.dll, IEHardenLMSettings
    Rundll32 iesetup.dll, IEHardenUser
    Rundll32 iesetup.dll, IEHardenAdmin
    Remove-Item -Path $AdminKey -Force
    Remove-Item -Path $UserKey -Force

    #Changing the default Open action for .ps1 file to open in Powershell ISE
    Set-ItemProperty -Path Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\Open\Command -Name "(Default)" -Value "`"$env:windir\System32\WindowsPowerShell\v1.0\powershell_ise.exe`" `"%1`""  -Force

    #Renaming the main NIC adapter to Corp
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue

    <#
    #region Disabling TLSv1.3 at the server level
    Write-Host "Disabling TLSv1.3"
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -Value 0 -PropertyType DWORD
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType DWORD
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -Value 0 -PropertyType DWORD
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -Value 1 -PropertyType DWORD
    #endregion
    #>
}

Invoke-LabCommand -ActivityName 'DNS, AD Setup & GPO Settings on DC' -ComputerName DC -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #endregion

    #Creating user for the PSWS application pool used for the Pull web site to replace localsystem by this user
    New-ADUser -Name $Using:PSWSAppPoolUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -Description "PSWS Application Pool User"

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #Bonus : To open the .net core website on all machines
    $StartPage = "https://pull.$($using:FQDNDomainName)/PSDSCPullServer.svc"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName 0 -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "$StartPage"

    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\WireShark\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion
}

Copy-LabFileItem -Path $CurrentDir\CreateDscSqlDatabase.ps1 -DestinationFolderPath C:\Temp -ComputerName SQL
Invoke-LabCommand -ActivityName 'Add Permissions to SQL Database for DSC Reporting' -ComputerName SQL -ScriptBlock {
    C:\Temp\CreateDscSqlDatabase.ps1 -DomainAndComputerName $using:NetBiosDomainName\$using:PSWSAppPoolUsr
} -Verbose

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 5-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer5Years -DisplayName 'WebServer5Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ValidityPeriod $CertValidityPeriod -ComputerName $CertificationAuthority
#Generating a new template for 5-year document encryption certificate
New-LabCATemplate -TemplateName DocumentEncryption5Years -DisplayName 'DocumentEncryption5Years' -SourceTemplateName CEPEncryption -ApplicationPolicy 'Document Encryption' -KeyUsage KEY_ENCIPHERMENT, DATA_ENCIPHERMENT -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -SamAccountName 'Domain Computers' -ValidityPeriod $CertValidityPeriod -ComputerName $CertificationAuthority

$PULLWebSiteSSLCert = Request-LabCertificate -Subject "CN=pull.$FQDNDomainName" -SAN "pull", "pull.$FQDNDomainName" -TemplateName WebServer5Years -ComputerName PULL -PassThru
$PULLDocumentEncryptionCert = Request-LabCertificate -Subject "CN=pull.$FQDNDomainName" -SAN "pull", "pull.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName PULL -PassThru
$DCDocumentEncryptionCert = Request-LabCertificate -Subject "CN=dc.$FQDNDomainName" -SAN "dc", "dc.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName DC -PassThru
$MS1DocumentEncryptionCert = Request-LabCertificate -Subject "CN=ms1.$FQDNDomainName" -SAN "ms1", "ms1.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName MS1 -PassThru
$MS2DocumentEncryptionCert = Request-LabCertificate -Subject "CN=MS2.$FQDNDomainName" -SAN "ms2", "ms2.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName MS2 -PassThru

Invoke-LabCommand -ActivityName 'Requesting and Exporting Document Encryption Certificate & Disabling Windows Update service' -ComputerName $AllLabVMs -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
    
    $DocumentEncryption5YearsCert = Get-ChildItem Cert:\LocalMachine\My -DocumentEncryptionCert | Select-Object -Last 1    
    New-Item -Path \\pull\c$\PublicKeys\ -ItemType Directory -Force
    Export-Certificate -Cert $DocumentEncryption5YearsCert -FilePath "\\pull\c$\PublicKeys\$env:COMPUTERNAME.cer" -Force
} 

Invoke-LabCommand -ActivityName 'Generating CSV file for listing certificate data' -ComputerName PULL -ScriptBlock {
    $PublicKeysFolder = "C:\PublicKeys"
    $CSVFile = Join-Path -Path $PublicKeysFolder -ChildPath "index.csv"
    $CertificateFiles = Get-ChildItem -Path $PublicKeysFolder -Filter *.cer -File
    $CSVData = $CertificateFiles | ForEach-Object -Process {
        $Path=$_.FullName
        $CurrentCertificate = Get-PfxCertificate $Path
        if ($CurrentCertificate.Subject -match "CN=(?<NETBIOS>\w*)\.(.*)+$")
        {
            $Node=$Matches["NETBIOS"]
        }
        else
        {
            $Node=$_.BaseName
        }
        $Thumbprint = $CurrentCertificate.Thumbprint
        $GUID = (New-Guid).Guid
        [PSCustomObject]@{Node=$Node;Path=$Path;Thumbprint=$Thumbprint;GUID=$GUID}
    }
    $CSVData | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8
} 
#endregion

Invoke-LabCommand -ActivityName 'Installing preprequisites for PULL server' -ComputerName PULL -ScriptBlock {
    #Adding TLS 1.2 to the supported protocol list
    Get-PackageProvider -Name Nuget -ForceBootstrap -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-Module -Name xPSDesiredStateConfiguration -Force -Verbose
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools 
}

#Checkpoint-LabVM -SnapshotName BeforePullSetup -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'BeforePullSetup' -All -Verbose

Invoke-LabCommand -ActivityName 'Setting up the HTTPS Pull Server' -ComputerName PULL -ScriptBlock {
    Get-Website -Name "Default Web Site" | Remove-Website
    Configuration CreateHTTPSPullServer
    {
	    param
	    (
		    [string[]] $ComputerName = 'localhost',
            [string] $Guid = $((New-Guid).Guid),
            [Parameter(Mandatory = $true)]
            [string] $CertificateThumbPrint
	    )

	    Import-DSCResource -ModuleName PSDesiredStateConfiguration
	    Import-DSCResource -ModuleName xPSDesiredStateConfiguration

	    Node $ComputerName
	    {
		    WindowsFeature DSCServiceFeature
		    {
			    Ensure = 'Present'
			    Name   = 'DSC-Service'
		    }
            WindowsFeature IISConsole {
                Ensure    = 'Present'
                Name      = 'Web-Mgmt-Console'
                DependsOn = '[WindowsFeature]DSCServiceFeature'
            }
		    xDscWebService PSDSCPullServer
		    {
			    Ensure                       = 'Present'
			    EndpointName                 = 'PSDSCPullServer'
			    Port                         = 443
			    PhysicalPath                 = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
			    CertificateThumbPrint        = $CertificateThumbPrint
			    ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
			    ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
			    State                        = 'Started'
			    DependsOn                    = '[WindowsFeature]DSCServiceFeature'
			    UseSecurityBestPractices     = $false
                AcceptSelfSignedCertificates = $false
                SqlProvider                  = $true
                SqlConnectionString          = "Provider=SQLOLEDB.1;Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=master;Data Source=SQL"
            }
            File RegistrationKeyFile {
                Ensure = "Present"
                Type = "File"
                DestinationPath = "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt"
                Contents = $Guid
                DependsOn = "[xDscWebService]PSDSCPullServer"
            }
	    }
    }

    # Build the MOF
    CreateHTTPSPullServer -CertificateThumbPrint $PULLWebSiteSSLCert.Thumbprint

    # Apply the configuration.
    Start-DscConfiguration .\CreateHTTPSPullServer -Wait -Verbose -Force

    #Changing the application pool identity from localsystem to a domain account
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "identityType" -value "SpecificUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "userName" -value "$using:NetBiosDomainName\$using:PSWSAppPoolUsr"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='PSWS']/processModel" -name "password" -value $using:ClearTextPassword
    Stop-WebAppPool -Name PSWS -ErrorAction Ignore
    Start-WebAppPool -Name PSWS
    
    #Disabling TLS 1.3 at the website level
    #Import-Module -Name IISAdministration
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='PSDSCPullServer']/bindings/binding[@protocol='https' and @bindingInformation='*:443:']" -name "sslFlags" -value $([Microsoft.Web.Administration.SslFlags]::DisableTLS13)
    #Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='PSDSCPullServer']/bindings/binding[@protocol='https' and @bindingInformation='*:443:']" -name "sslFlags" -value 32

    <#
        #Disabling TLS 1.3 at the website level
        $DisableTLS13 = [Microsoft.Web.Administration.SslFlags]::DisableTLS13
        $BindingInformation = "*:443:secure.contoso.com"
        $siteName = "contoso"
        PhysicalPath = "$env:systemdrive\inetpub\wwwroot"
        $Thumbprint = $certificate.ThumbPrint
        $IISSite = New-IISSite -Name $siteName -PhysicalPath $PhysicalPath -BindingInformation $BindingInformation -Protocol https -CertificateThumbPrint $certificate.Thumbprint -SslFlag $DisableTLS13 -CertStoreLocation $storeLocation -passthru
    #>
} -Variable (Get-Variable -Name PULLWebSiteSSLCert) -Verbose

$Jobs | Wait-Job | Out-Null

Copy-LabFileItem -Path $CurrentDir\*DSCConfig.ps1 -DestinationFolderPath C:\$LabName -ComputerName PULL

#Restarting VM to update the GPO(s).
Restart-LabVM -ComputerName $AllLabVMs -Wait

Checkpoint-LabVM -SnapshotName 'FullInstall' -All

Show-LabDeploymentSummary

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript