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
    break
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

$PHPNetBiosName = 'PHP'
$PHPWebSiteName = "$PHPNetBiosName.$FQDNDomainName"
$PHPIPv4Address = '10.0.0.101'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$IIS01IPv4Address = '10.0.0.11'

$LatestPHPZipFileURI = "https://windows.php.net/" + ((Invoke-WebRequest -Uri https://windows.php.net/downloads/releases/).Links.href | Where-Object -FilterScript { $_ -match "php-\d+\.\d+\.\d+-nts-Win32-vs16-x64.zip"} | Sort-Object -Descending | Select-Object -First 1)
$VS16VCRedistURI = "https://aka.ms/vs/16/release/VC_redist.x64.exe"

$LabName = 'PHP'
$Job = @()
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

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot -IpAddress $DC01IPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -IpAddress $IIS01IPv4Address
#endregion

#Installing servers
Install-Lab
Checkpoint-LabVM -SnapshotName FreshInstall -All
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

$machines = Get-LabVM
#region Installing Required Windows Features
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -AsJob
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD Setup & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entries for the websites 
    Add-DnsServerResourceRecordA -Name "$using:PHPNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:PHPIPv4Address" -CreatePtr
    #endregion

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #Bonus : To open the .net core website on all machines
    $StartPage = "https://$using:PHPWebSiteName"
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


#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for SSL Web Server certificate
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the anonymous website
$PHPWebSiteSSLCert = Request-LabCertificate -Subject "CN=$PHPWebSiteName" -SAN $PHPNetBiosName, "$PHPWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#region

Install-LabWindowsFeature -FeatureName Web-Server, Web-CGI -ComputerName IIS01 -IncludeManagementTools

#region PHP pre-requisites
#region Downloading the latest PHP Zip File
#$LatestPHPZipFile = Get-LabInternetFile -Uri $LatestPHPZipFileURI -Path $labSources\SoftwarePackages -PassThru -Verbose -Force
Start-BitsTransfer $LatestPHPZipFileURI -Destination $labSources\SoftwarePackages -Verbose
$LatestPHPZipFile = Join-Path -Path $labSources\SoftwarePackages -ChildPath $(Split-Path $LatestPHPZipFileURI -Leaf)
#endregion 
$VS16VCRedist = Get-LabInternetFile -Uri $VS16VCRedistURI -Path $labSources\SoftwarePackages -PassThru -Verbose -Force
#endregion

Invoke-LabCommand -ActivityName 'Setting up the IIS website' -ComputerName IIS01 -ScriptBlock {    
    #Creating directory tree for hosting web sites
    $PHPWebSitePath =  "C:\WebSites\$using:PHPWebSiteName"
    $null = New-Item -Path $PHPWebSitePath -ItemType Directory -Force
    
    #applying the required ACL (via PowerShell Copy and Paste)
    Get-Acl C:\inetpub\wwwroot | Set-Acl C:\WebSites
    
    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #region : Default Settings
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'
    #Configuring The Anonymous Authentication to use the AppPoolId
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "userName" -value ""
    #Disabling the Anonymous authentication for all websites
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "enabled" -value "False"
    #endregion 

    #region : PHP website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:PHPIPv4Address –PrefixLength 24 –InterfaceAlias "Corp"
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:PHPWebSiteName" -Force


    #Creating a dedicated web site
    New-WebSite -Name "$using:PHPWebSiteName" -Port 443 -IPAddress $using:PHPIPv4Address -PhysicalPath $PHPWebSitePath -ApplicationPool "$using:PHPWebSiteName" -Ssl -SslFlags 0 -Force
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:PHPIPv4Address!443!$using:PHPWebSiteName" -Thumbprint $($using:PHPWebSiteSSLCert).Thumbprint -sslFlags 0
    #Require SSL
    #Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:BasicWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:PHPWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl"
    
    #Setting up the dedicated application pool to "No Managed Code"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:PHPWebSiteName']" -name "managedRuntimeVersion" -value ""

    #Enabling the Anonymous authentication
    #Creating a dedicated web site
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:PHPWebSiteName" -filter 'system.webServer/security/authentication/AnonymousAuthentication' -name 'enabled' -value 'True'

    #region PHP Default Page
    "<?php phpinfo(); ?>" | Out-File $PHPWebSitePath\index.php -Encoding utf8 -Force
    Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($using:PHPWebSiteName)"  -filter "system.webServer/defaultDocument/files" -name "." -value @{value='index.php'}
    #endregion

    #endregion
}

#copying PHP Zip file locally
$LocalLatestPHPZipFile = Copy-LabFileItem -Path $LatestPHPZipFile -DestinationFolderPath C:\ -ComputerName IIS01 -PassThru
#Installing Microsoft Visual C++ 2015-2019 
Install-LabSoftwarePackage -ComputerName IIS01 -Path $VS16VCRedist.FullName -CommandLine "/install /passive /norestart"

Invoke-LabCommand -ActivityName 'Setting up the IIS website' -ComputerName IIS01 -ScriptBlock {    
    Expand-Archive -Path $using:LocalLatestPHPZipFile -DestinationPath C:\PHP -Force
    Copy-Item -Path C:\PHP\php.ini-production -Destination C:\PHP\php.ini
    [Environment]::SetEnvironmentVariable("PATH", $Env:PATH + ";C:\PHP", [EnvironmentVariableTarget]::Machine)
    
    #PHP Handler Mapping 
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/handlers" -name "." -value @{name='PHP';path='*.php';verb='*';modules='FastCgiModule';scriptProcessor='C:\PHP\php-cgi.exe';resourceType='File'}
    #PHP FastCGI
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/fastCgi" -name "." -value @{fullPath='C:\PHP\php-cgi.exe'}

}

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName IIS01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

#Waiting for background jobs
$Job | Wait-Job | Out-Null

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript