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
$ErrorActionPreference = 'Stop'
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
$MusicStoreAppPool = 'MusicStoreAppPool'
$MusicStoreAppPoolUsr = 'MusicStoreAppPoolUsr'
$WDeployConfigWriter = 'WDeployConfigWriter'
$WebDeploySqlUsr = 'WebDeploySqlUsr'

$NetworkID='10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$SQL01IPv4Address = '10.0.0.11'
$IIS01IPv4Address = '10.0.0.21'
$CLIENT01IPv4Address = '10.0.0.31'

$MusicStoreIPv4Address = '10.0.0.101'
$MvcMusicStoreFilesZipPath = Join-Path -Path $CurrentDir -ChildPath "MvcMusicStore.zip"
$MusicStoreNetBiosName = 'musicstore'
$MusicStoreWebSiteName = "$MusicStoreNetBiosName.$FQDNDomainName"

$WebPIUri = "https://go.microsoft.com/fwlink/?LinkId=287166"
$WebPIX64MSIFileName = "WebPlatformInstaller_x64_en-US.msi"
$WebPIX64MSIPath = Join-Path -Path $CurrentDir -ChildPath $WebPIX64MSIFileName


#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors)

$LabName = 'IISWebDeploy'
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List))
{
    Remove-Lab -name $LabName -confirm:$false -ErrorAction SilentlyContinue
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
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = $LabMachineDefinitionProcessors
}

$IIS01NetAdapter = @()
$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $IIS01IPv4Address
$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

$SQL01NetAdapter = @()
$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQL01IPv4Address
#Adding an Internet Connection on the DC (Required for the SQL Setup via AutomatedLab)
$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

#SQL Server
$SQLServer2019Role = Get-LabMachineRoleDefinition -Role SQLServer2019 -Properties @{ Features = 'SQL,Tools' }
Add-LabIsoImageDefinition -Name SQLServer2019 -Path $labSources\ISOs\en_sql_server_2019_standard_x64_dvd_cdcd4b9f.iso

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#SQL Server
Add-LabMachineDefinition -Name SQL01 -Roles $SQLServer2019Role -NetworkAdapter $SQL01NetAdapter #-Memory 2GB -Processors 2
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -NetworkAdapter $IIS01NetAdapter
#IIS front-end server
Add-LabMachineDefinition -Name CLIENT01 -IpAddress $CLIENT01IPv4Address
#endregion

#Installing servers
Install-Lab
#Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose

#region Installing Required Windows Features
$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled -Value 0 -Force
    Rundll32 iesetup.dll, IEHardenLMSettings
    Rundll32 iesetup.dll, IEHardenUser
    Rundll32 iesetup.dll, IEHardenAdmin
    Remove-Item -Path $AdminKey -Force
    Remove-Item -Path $UserKey -Force
    #Setting the Keyboard to French
    #Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp (used in the Security lab)
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entries for the websites 
    Add-DnsServerResourceRecordA -Name "$using:MusicStoreNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:MusicStoreIPv4Address" -CreatePtr
    #endregion

    #Creating AD Users
    #Application Pool User
    New-ADUser -Name $Using:MusicStoreAppPoolUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -PassThru
    #Web Deploy
    New-ADUser -Name $Using:WDeployConfigWriter -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    New-ADUser -Name $Using:WebDeploySqlUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    $GPO = New-GPO -Name "Autoenrollment Policy" | New-GPLink -Target $DefaultNamingContext
    #region User Enrollment Policy
    #https://www.sysadmins.lv/retired-msft-blogs/xdot509/troubleshooting-autoenrollment.aspx : 0x00000007 = Enabled, Update Certificates that user certificates templates configured, Renew expired certificates, update pending certificates, and remove revoked certificates configured
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0x00000007 
    #endregion

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0

    #Setting MusicStore.contoso.com in the Local Intranet Zone for all servers : mandatory for MusicStore authentication       
    #1 for Intranet Zone, 2 for Trusted Sites, 3 for Internet Zone and 4 for Restricted Sites Zone.
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:MusicStoreWebSiteName" -ValueName http -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 1

    #Changing the start page for IE
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Internet Explorer\Main' -ValueName "Start Page" -Type String -Value "http://$using:MusicStoreWebSiteName"
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion

    Invoke-GPUpdate -Computer CLIENT01 -Force
}

Invoke-LabCommand -ActivityName 'Adding some users to the SQL sysadmin group' -ComputerName SQL01 -ScriptBlock {
    #SQL Server Management Studio (SSMS), beginning with version 17.0, doesn't install either PowerShell module. To use PowerShell with SSMS, install the SqlServer module from the PowerShell Gallery.
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name SqlServer -Force -AllowClobber
    #Adding some AD users to SQL server as sysadmin (used for Web Deploy lab)
    $SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$Using:NetBiosDomainName\$Using:MusicStoreAppPoolUsr" -LoginType "WindowsUser" -Enable
    $SQLLogin.AddToRole("sysadmin")
    $SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$Using:NetBiosDomainName\$Using:WDeployConfigWriter" -LoginType "WindowsUser" -Enable
    $SQLLogin.AddToRole("sysadmin")
    $SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$Using:NetBiosDomainName\$Using:WebDeploySqlUsr" -LoginType "WindowsUser" -Enable
    $SQLLogin.AddToRole("sysadmin")
}

#Downloading Microsoft Web Platform Installer and copying the on the IIS Server 
Invoke-WebRequest -Uri $WebPIUri -OutFile $WebPIX64MSIPath
$LocalWebPIInstaller = Copy-LabFileItem -Path $WebPIX64MSIPath -DestinationFolderPath C:\Temp -ComputerName IIS01 -PassThru

$LocalMvcMusicStoreFilesZipPath = Copy-LabFileItem -Path $MvcMusicStoreFilesZipPath -ComputerName IIS01 -DestinationFolderPath C:\Temp -PassThru

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IIS01 -ScriptBlock {        
    #PowerShell module for IIS Management
    
    New-NetIPAddress –IPAddress $using:MusicStoreIPv4Address –PrefixLength 24 –InterfaceAlias "Corp"

    Add-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth, Web-Mgmt-Service -IncludeManagementTools
    Import-Module -Name WebAdministration

    #Creating directory tree for hosting web sites
    $WebSiteRootPath = New-Item -Path C:\WebSites -ItemType Directory -Force
    #applying the required ACL (via PowerShell Copy and Paste)
    Get-ACl C:\inetpub\wwwroot | Set-Acl $WebSiteRootPath.FullName

    $MusicStoreWebSitePath = Join-Path -Path $WebSiteRootPath.FullName -ChildPath $using:MusicStoreWebSiteName
    $null = New-Item -Path $MusicStoreWebSitePath -ItemType Directory -Force

    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement" -Value "1" -PropertyType DWord -Force 
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "LoggingDirectory" -Value "%SystemDrive%\Inetpub\logs\WMSvc" -PropertyType String -Force 
    Restart-Service -Name WMSVC

    #region : Default Settings
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'
    #Configuring The Anonymous Authentication to use the AppPoolId
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/anonymousAuthentication" -name "userName" -value ""
    #endregion 

    #region : MusicStore website management
    #region Creating a dedicated application pool
    New-WebAppPool -Name $using:MusicStoreAppPool -Force
    #Loading user profile for SQL Express
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:MusicStoreAppPool']/processModel" -name "loadUserProfile" -value "True"
			
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:MusicStoreAppPool']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:MusicStoreAppPool']/processModel" -name 'userName' -value "$using:NetBiosDomainName\$Using:MusicStoreAppPoolUsr"
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:MusicStoreAppPool']/processModel" -name 'password' -value $using:ClearTextPassword
    #endregion 

    #region Creating a dedicated web site
    New-WebSite -Name "$using:MusicStoreWebSiteName" -IPAddress $using:MusicStoreIPv4Address -Port 80 -PhysicalPath $MusicStoreWebSitePath -ApplicationPool "$using:MusicStoreAppPool" -Force

    #region Web Deploy management
    Start-Process -FilePath $using:LocalWebPIInstaller -Argument "/passive" -Wait
    Start-Process "$env:ProgramFiles\Microsoft\Web Platform Installer\WebPICMD.exe"-Argument "/Install /Products:WDeploy36,SQLExpress /AcceptEULA /SQLPassword:$using:ClearTextPassword" -Wait
    Start-Process "$env:ProgramFiles\IIS\Microsoft Web Deploy V3\msdeploy" -Argument "-verb:sync -source:package='$using:LocalMvcMusicStoreFilesZipPath' -dest:auto -setparam:name='IIS Web Application Name',value='$using:MusicStoreWebSiteName/' -setparam:name='MusicStoreEntities-Deployment Connection String',value='Server=SQL01;Database=MvcMusicStoreDb;Integrated Security=true' -setparam:name='Sql script variable `$(poolUser) in MusicStoreEntities-Deployment scripts',value='$using:NetBiosDomainName\$Using:MusicStoreAppPoolUsr' -setparam:name='MusicStoreEntities-Web.config Connection String',value='Server=SQL01;Database=MvcMusicStoreDb;Integrated Security=true'" -Wait
    #endregion
}

Invoke-LabCommand -ActivityName 'Cleanup on SQL Server' -ComputerName SQL01 -ScriptBlock {
    Remove-Item -Path "C:\vcredist_x*.*" -Force
    Remove-Item -Path "C:\SSMS-Setup-ENU.exe" -Force
    #Disabling the Internet Connection on the SQL Server (Required only for the SQL Setup via AutomatedLab)
    Get-NetAdapter -Name Internet | Disable-NetAdapter -Confirm:$false
}

#Removing the Internet Connection on the SQL Server (Required only for the SQL Setup via AutomatedLab)
Get-VM -Name 'SQL01' | Remove-VMNetworkAdapter -Name 'Default Switch' -ErrorAction SilentlyContinue
#Removing the Internet Connection on the IIS Server (Required for Web Platform Installer)
Get-VM -Name 'IIS01' | Remove-VMNetworkAdapter -Name 'Default Switch' -ErrorAction SilentlyContinue
#Get-LabVM -All | Where-Object -FilterScript {'Default Switch' -in $_.Network } | Get-VM | Remove-VMNetworkAdapter -Name 'Default Switch'

#Setting processor number to 1 for all VMs (The AL deployment fails with 1 CPU)
Get-LabVM -All | Stop-VM -Passthru | Set-VMProcessor -Count 1
Get-LabVM -All | Start-VM

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript