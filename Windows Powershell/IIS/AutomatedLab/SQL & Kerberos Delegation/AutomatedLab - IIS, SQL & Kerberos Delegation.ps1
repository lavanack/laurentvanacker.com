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
trap { Write-Host "Stopping Transcript ..."; Stop-Transcript} 
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (get-date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$IISAppPoolUser = 'IISAppPoolUser'

$NetworkID='10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$SQL01IPv4Address = '10.0.0.11'
$IIS01IPv4Address = '10.0.0.21'
$CLIENT01IPv4Address = '10.0.0.31'

$WideWorldImportersIPv4Address = '10.0.0.101'
$WideWorldImportersNetBiosName = 'wideworldimporters'
$WideWorldImportersWebSiteName = "$WideWorldImportersNetBiosName.$FQDNDomainName"
#From https://github.com/mytecbits/MyTecBits-MVC5-Bootstrap3-EF6-DatabaseFirst
$WideWorldImportersFilesZipPath = Join-Path -Path $CurrentDir -ChildPath "WideWorldImporters.zip"

$WebPIUri = "https://go.microsoft.com/fwlink/?LinkId=287166"
$WebPIX64MSIFileName = "WebPlatformInstaller_x64_en-US.msi"
$WebPIX64MSIPath = Join-Path -Path $CurrentDir -ChildPath $WebPIX64MSIFileName

$LabName = 'IISSQLKerbDeleg'
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
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Standard (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 4
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

#region Installing Required Windows Features
$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $machines -ScriptBlock {
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
    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

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
    Add-DnsServerResourceRecordA -Name "$using:WideWorldImportersNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:WideWorldImportersIPv4Address" -CreatePtr
    #endregion


    #Creating AD Users
    #Application Pool User
    $AppPoolUser = New-ADUser -Name $Using:IISAppPoolUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -PassThru

    #region WideWorldImporters Delegation
    $AppPoolUser | Set-ADObject -Add @{"msDS-AllowedToDelegateTo" = "MSSQLSvc/SQL01.$($using:FQDNDomainName):1433" }
    $AppPoolUser | Set-ADAccountControl -TrustedForDelegation $true   
    #region Setting SPN on the Application Pool Identity for kerberos authentication
    $AppPoolUser | Set-ADUser -ServicePrincipalNames @{Add="HTTP/$using:WideWorldImportersWebSiteName", "HTTP/$using:WideWorldImportersNetBiosName"}
    #endregion

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    $GPO = New-GPO -Name "User Enrollment Policy" | New-GPLink -Target $DefaultNamingContext
    #region User Enrollment Policy
    #https://www.sysadmins.lv/retired-msft-blogs/xdot509/troubleshooting-autoenrollment.aspx : 0x00000007 = Enabled, Update Certificates that user certificates templates configured, Renew expired certificates, update pending certificates, and remove revoked certificates configured
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type Dword -value 0x00000007 
    #endregion

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type Dword -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type Dword -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type Dword -value 0

    #Setting WideWorldImporters.contoso.com in the Local Intranet Zone for all servers : mandatory for WideWorldImporters authentication       
    #1 for Intranet Zone, 2 for Trusted Sites, 3 for Internet Zone and 4 for Restricted Sites Zone.
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:WideWorldImportersWebSiteName" -ValueName http -Type Dword -value 1

    #Changing the start page for IE
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Internet Explorer\Main' -ValueName "Start Page" -Type String -Value "http://$using:WideWorldImportersWebSiteName"
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
    #$SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$Using:NetBiosDomainName\$Using:IISAppPoolUser" -LoginType "WindowsUser" -Enable
    #$SQLLogin.AddToRole("sysadmin")
    #Adding AD users to SQL server as sysadmin
    $SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$Using:NetBiosDomainName\Domain Users" -LoginType "WindowsUser" -Enable
    $SQLLogin.AddToRole("sysadmin")
}

#Installing SQL Server Sample databases
Install-LabSqlSampleDatabases -Machine $(Get-LabVM -ComputerName SQL01)

#Downloading Microsoft Web Platform Installer and copying the on the IIS Server 
Invoke-WebRequest -Uri $WebPIUri -OutFile $WebPIX64MSIPath
$LocalWebPIInstaller = Copy-LabFileItem -Path $WebPIX64MSIPath -DestinationFolderPath C:\Temp -ComputerName IIS01 -PassThru

#Copying web content on the IIS server
$LocalWideWorldImportersFilesZipPath = Copy-LabFileItem -Path $WideWorldImportersFilesZipPath -ComputerName IIS01 -DestinationFolderPath C:\Temp -PassThru

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IIS01 -ScriptBlock {        
    
    New-NetIPAddress –IPAddress $using:WideWorldImportersIPv4Address –PrefixLength 24 –InterfaceAlias "Corp"

    #Installing IIS
    Add-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth, Web-Mgmt-Service -IncludeManagementTools
    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #Creating directory tree for hosting web sites
    $WebSiteRootPath = New-Item -Path C:\WebSites -ItemType Directory -Force
    #Applying the required ACL (via PowerShell Copy and Paste)
    Get-ACl C:\inetpub\wwwroot | Set-Acl $WebSiteRootPath.FullName
    $WideWorldImportersWebSitePath = Join-Path -Path $WebSiteRootPath.FullName -ChildPath $using:WideWorldImportersWebSiteName
    $null = New-Item -Path $WideWorldImportersWebSitePath -ItemType Directory -Force

    #region : Web Management Service
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement" -Value "1" -PropertyType DWord -Force 
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "LoggingDirectory" -Value "%SystemDrive%\Inetpub\logs\WMSvc" -PropertyType String -Force 
    Restart-Service -Name WMSVC
    #endregion

    #region : Default Settings
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'
    #Configuring The Anonymous Authentication to use the AppPoolId
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/anonymousAuthentication" -name "userName" -value ""
    #endregion 

    #region : WideWorldImporters website management
    #region Creating a dedicated application pool
    New-WebAppPool -Name $using:WideWorldImportersWebSiteName -Force
			
    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:WideWorldImportersWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:WideWorldImportersWebSiteName']/processModel" -name 'userName' -value "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:WideWorldImportersWebSiteName']/processModel" -name 'password' -value $using:ClearTextPassword
    #endregion 

    #region Creating a dedicated web site
    New-WebSite -Name "$using:WideWorldImportersWebSiteName" -IPAddress $using:WideWorldImportersIPv4Address -Port 80 -PhysicalPath $WideWorldImportersWebSitePath -ApplicationPool "$using:WideWorldImportersWebSiteName" -Force

    #region Web Deploy management
    Start-Process -FilePath $using:LocalWebPIInstaller -Argument "/passive" -Wait
    Start-Process "$env:ProgramFiles\Microsoft\Web Platform Installer\WebPICMD.exe"-Argument "/Install /Products:WDeploy36 /AcceptEULA" -Wait
    Start-Process "$env:ProgramFiles\IIS\Microsoft Web Deploy V3\msdeploy" -Argument @"
-verb:sync -source:package='$using:LocalWideWorldImportersFilesZipPath' -dest:auto -setparam:name='IIS Web Application Name',value='$using:WideWorldImportersWebSiteName/' -setparam:name='WideWorldImportersEntities-Web.config Connection String',value='metadata=res://*/Models.WideWorldImportersModel.csdl|res://*/Models.WideWorldImportersModel.ssdl|res://*/Models.WideWorldImportersModel.msl;provider=System.Data.SqlClient;provider connection string="data source=SQL01;initial catalog=WideWorldImporters;integrated security=True;MultipleActiveResultSets=True;App=EntityFramework" '
"@ -Wait
    #endregion

    #region website post-configuration
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:WideWorldImportersWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:WideWorldImportersWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:WideWorldImportersWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:WideWorldImportersWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:WideWorldImportersWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #endregion
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

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript