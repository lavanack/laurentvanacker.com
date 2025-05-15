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
$IISAppPoolUser = 'IISAppPoolUser'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$SQL01IPv4Address = '10.0.0.11'
$IIS01IPv4Address = '10.0.0.21'
$CLIENT01IPv4Address = '10.0.0.31'

$WideWorldImportersIPv4Address = '10.0.0.101'
$WideWorldImportersNetBiosName = 'wideworldimporters'
$WideWorldImportersWebSiteName = "$WideWorldImportersNetBiosName.$FQDNDomainName"
#From https://github.com/mytecbits/MyTecBits-MVC5-Bootstrap3-EF6-DatabaseFirst
$WideWorldImportersFilesZipPath = Join-Path -Path $CurrentDir -ChildPath "WideWorldImporters.zip"

$WebDeployUri = "https://download.visualstudio.microsoft.com/download/pr/e1828da1-907a-46fe-a3cf-f3b9ea1c485c/035860f3c0d2bab0458e634685648385/webdeploy_amd64_en-us.msi"
$WebDeployMSIFileName = Split-Path -Path $WebDeployUri -Leaf
$WebDeployMSIFilePath = Join-Path -Path $CurrentDir -ChildPath $WebDeployMSIFileName

#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)
#[int]$LabMachineDefinitionProcessors = 4

$LabName = 'IISSQLKerbDeleg'
#endregion

#region Tools to download and install
#Microsoft Edge : Latest version
$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"
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
    'Add-LabMachineDefinition:MinMemory'       = 2GB
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
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
$SQLServer2022Role = Get-LabMachineRoleDefinition -Role SQLServer2022 -Properties @{ Features = 'SQL,Tools' }
Add-LabIsoImageDefinition -Name SQLServer2022 -Path $labSources\ISOs\enu_sql_server_2022_enterprise_edition_x64_dvd_aa36de9e.iso

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#SQL Server
Add-LabMachineDefinition -Name SQL01 -Roles $SQLServer2022Role -NetworkAdapter $SQL01NetAdapter
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -NetworkAdapter $IIS01NetAdapter
#IIS front-end server
Add-LabMachineDefinition -Name CLIENT01 -IpAddress $CLIENT01IPv4Address
#endregion

#Installing servers
Install-Lab #-Verbose

$machines = Get-LabVM -All

$Jobs = @()
#region Installing Microsoft Edge
#Updating MS Edge on all machines (because even the latest OS build ISO doesn't necessary contain the latest MSEdge version)
#-Force is used to be sure to download the latest MS Edge version 
$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Jobs += Install-LabSoftwarePackage -ComputerName $machines -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru
#endregion

#region Installing Required Windows Features
$Jobs += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -AsJob -PassThru
#endregion

Invoke-LabCommand -ActivityName "Renaming NICs" -ComputerName $machines -ScriptBlock {
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
    $AppPoolUser | Set-ADUser -ServicePrincipalNames @{Add = "HTTP/$using:WideWorldImportersWebSiteName", "HTTP/$using:WideWorldImportersNetBiosName" }
    #endregion

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    $GPO = New-GPO -Name "Autoenrollment Policy" | New-GPLink -Target $DefaultNamingContext
    #region User Enrollment Policy
    #https://www.sysadmins.lv/retired-msft-blogs/xdot509/troubleshooting-autoenrollment.aspx : 0x00000007 = Enabled, Update Certificates that user certificates templates configured, Renew expired certificates, update pending certificates, and remove revoked certificates configured
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0x00000007 
    #endregion

    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.MicrosoftEdge::PreventFirstRunPage
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main' -ValueName "PreventFirstRunPage" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #Hide the First-run experience and splash screen on Edge : https://docs.microsoft.com/en-us/deployedge/microsoft-edge-policies#hidefirstrunexperience
    #https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::HideFirstRunExperience
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Edge' -ValueName "HideFirstRunExperience" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1

    #Bonus : To open all the available websites accross all nodes
    $StartPages = "http://$using:WideWorldImportersWebSiteName"
    $i=0
    $StartPages | ForEach-Object -Process {
        Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName ($i++) -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "$_"
    }
    #endregion

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0

    #Setting WideWorldImporters.contoso.com in the Local Intranet Zone for all servers : mandatory for WideWorldImporters authentication       
    #1 for Intranet Zone, 2 for Trusted Sites, 3 for Internet Zone and 4 for Restricted Sites Zone.
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ValueName "ListBox_Support_ZoneMapKey" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -ValueName "AutoDetect" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" -ValueName "http://$using:WideWorldImportersWebSiteName" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::String)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" -ValueName "http://IIS01.$using:FQDNDomainName" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::String)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:FQDNDomainName\$using:WideWorldImportersNetBiosName" -ValueName "http" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:FQDNDomainName\IIS01" -ValueName "http" -Value 1 -Type ([Microsoft.Win32.RegistryValueKind]::DWord)
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\WireShark\ssl-keys.log'
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

Invoke-LabCommand -ActivityName 'Changing the $PSDefaultParameterValues for the Invoke-Sqlcmd cmdlet to set TrustServerCertificate=$true' -ComputerName SQL01 -ScriptBlock {        
    $PSDefaultParameterValues = @{
        #'Invoke-Sqlcmd:TrustServerCertificate' = $true
    }
}
#Installing SQL Server Sample databases
Install-LabSqlSampleDatabases -Machine $(Get-LabVM -ComputerName SQL01) -Verbose

#Downloading Microsoft Web Platform Installer and copying the on the IIS Server 
Invoke-WebRequest -Uri $WebDeployUri -OutFile $WebDeployMSIFilePath
$LocalWebDeployInstaller = Copy-LabFileItem -Path $WebDeployMSIFilePath -DestinationFolderPath C:\Temp -ComputerName IIS01 -PassThru

#Copying web content on the IIS server
$LocalWideWorldImportersFilesZipPath = Copy-LabFileItem -Path $WideWorldImportersFilesZipPath -ComputerName IIS01 -DestinationFolderPath C:\Temp -PassThru

#Checkpoint-LabVM -SnapshotName 'BeforeIIS' -All
#Restore-LabVMSnapshot -SnapshotName 'BeforeIIS' -All -Verbose

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IIS01 -ScriptBlock {        
    
    New-NetIPAddress –IPAddress $using:WideWorldImportersIPv4Address –PrefixLength 24 –InterfaceAlias "Corp"

    #Installing IIS
    Add-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth, Web-Mgmt-Service -IncludeManagementTools
    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #Creating directory tree for hosting web sites
    $WebSiteRootPath = New-Item -Path C:\WebSites -ItemType Directory -Force
    #Applying the required ACL (via PowerShell Copy and Paste)
    Get-Acl C:\inetpub\wwwroot | Set-Acl $WebSiteRootPath.FullName
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
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "msiexec /i $using:LocalWebDeployInstaller ADDLOCAL=ALL /qn /norestart LicenseAccepted='0'" -Wait

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
Get-LabVM -All | Stop-VM -Passthru -Force | Set-VMProcessor -Count 1
Get-LabVM -All | Start-VM

#Waiting for background jobs
$Jobs | Wait-Job | Out-Null

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript