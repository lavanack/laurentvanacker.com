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
$LabName = 'IISWSPlus2019'
#endregion

#Importing lab
Import-Lab -Name $LabName
#Restoring to the snapshot after the installation
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose
Get-LabVM -All | Start-VM

$AllMachines = Get-LabVM
Invoke-LabCommand -ActivityName "Keyboard management" -ComputerName $AllMachines -ScriptBlock {
    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force
}

#region Module 1
#region Module 1 - Lab 1 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 1 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    Add-WindowsFeature Web-Server, Web-Asp-Net45, Web-Asp -IncludeManagementTools -Source C:\Sources\Sxs
}
#endregion 
#region Module 1 - Lab 1 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 1 - Lab 1 - Exercice 2' -ComputerName IIS02 -ScriptBlock {
    Enable-WindowsOptionalFeature –Online –FeatureName IIS-WebServerRole, IIS-ASPNET, IIS-ASPNET45 -Source C:\Sources\Sxs -All
}
#endregion 
#region Module 1 - Lab 2 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 1 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    Copy-Item 'C:\LabFiles\1. Architecture\hello*.*' C:\inetpub\wwwroot -Force
    #endregion
}
#endregion 
#region Module 1 - Lab 2 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 1 - Lab 2 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    netsh http show iplisten
    netsh http show urlacl
    netsh http show servicestate
    #endregion
}
#endregion 
#region Module 1 - Lab 2 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 1 - Lab 2 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
    Set-Location -Path C:\
    logman query providers > providers.txt
    notepad providers.txt
    logman query providers Microsoft-Windows-HttpService > httpProviders.txt
    notepad httpProviders.txt
    logman start httptrace -p Microsoft-Windows-HttpService 0xFFFF 0x4 -ets
    Invoke-WebRequest -Uri "http://localhost"
    Invoke-WebRequest -Uri "http://localhost/iisstart.png"
    Invoke-WebRequest -Uri "http://localhost/iisstart.htm"
    logman stop httptrace -ets
    tracerpt httptrace.etl
    notepad summary.txt 
    notepad dumpfile.xml 
}
#endregion 

#Checkpoint after Module 1
Checkpoint-LabVM -SnapshotName 'Module 1' -All
#endregion

#region Module 2
#region Module 2 - Lab 1 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName DC01 -ScriptBlock {
    #region Task 1
    New-Item -Path C:\sharedConfig -ItemType Directory -Force  
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    $ClearTextPassword = 'MicrosoftII$10'
	$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
	Export-IISConfiguration -PhysicalPath \\DC01\c$\sharedConfig -KeyEncryptionPassword $SecurePassword -Force
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 2
	Enable-IISSharedConfig  -PhysicalPath \\DC01\c$\sharedConfig -KeyEncryptionPassword $SecurePassword -Force   
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS02 -ScriptBlock {
    #region Task 2
    $ClearTextPassword = 'MicrosoftII$10'
	$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
	Enable-IISSharedConfig  -PhysicalPath \\DC01\c$\sharedConfig -KeyEncryptionPassword $SecurePassword -Force   
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 4
	Disable-IISSharedConfig
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS02 -ScriptBlock {
    #region Task 4
	Disable-IISSharedConfig
    #endregion
}
#endregion 
#region Module 2 - Lab 2 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 2 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    C:\windows\system32\inetsrv\appcmd add backup testBackup
}
#endregion 
#region Module 2 - Lab 2 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 2 - Lab 2 - Exercice 2' -ComputerName IIS02 -ScriptBlock {
	Set-ExecutionPolicy RemoteSigned -Force
	Import-Module WebAdministration
	Backup-WebConfiguration -Name PowerShellBackup
}
#endregion 
#region Module 2 - Lab 2 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 2 - Lab 2 - Exercice 3' -ComputerName IIS02 -ScriptBlock {
	Remove-Item C:\Windows\System32\inetsrv\Config\applicationHost.config -Force
	Get-ChildItem C:\inetpub\history\ -Recurse -File -Filter applicationhost.config	| Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1 | Copy-Item -Destination C:\Windows\System32\inetsrv\Config 	
}
#endregion 
#region Module 2 - Lab 3 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 2 - Lab 3 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
	#region Task1
    Add-WindowsFeature Web-Mgmt-Service
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement" -Value "1" -PropertyType DWord -Force 
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "LoggingDirectory" -Value "%SystemDrive%\Inetpub\logs\WMSvc" -PropertyType String -Force 
	Restart-Service WMSVC
	#endregion
}
#endregion		
#region Module 2 - Lab 4 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
	#region Task1
	#Creating a dedicated application pool
	New-WebAppPool -Name MusicStoreAppPool  -Force
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
	#region Task2			
	#Changing the application pool identity for an AD Account : mandatory for MusicStore authentication
	Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='MusicStoreAppPool']/processModel" -name 'identityType' -value 3
	Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='MusicStoreAppPool']/processModel" -name 'userName' -value "CONTOSO\MusicStoreAppPoolUsr"
	Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='MusicStoreAppPool']/processModel" -name 'password' -value "P@ssw0rd"
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
	#region Task3			
	New-Item -Path c:\inetpub\MusicStoreRoot -ItemType Directory -Force
	#Creating a dedicated web site
	New-WebSite -Name "MusicStoreSite" -Port 8088 -PhysicalPath "c:\inetpub\MusicStoreRoot" -ApplicationPool "MusicStoreAppPool" -Force
	#endregion
}
#endregion 
#region Module 2 - Lab 4 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task 1
    $LocalWebPIInstaller = "C:\LabFiles\2. Administration\InstallSource\WebPlatformInstaller_x64_en-US.msi" 
	Start-Process -FilePath $LocalWebPIInstaller -Argument "/passive" -Wait
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task 2
	Start-Process "$env:ProgramFiles\Microsoft\Web Platform Installer\WebPICMD.exe"-Argument "/Install /Products:WDeploy36 /AcceptEULA" -Wait
    #endregion
}
#endregion 
#region Module 2 - Lab 4 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    Start-Process "C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy" -Argument "-verb:sync -source:package='C:\LabFiles\2. Administration\MvcMusicStore.zip' -dest:auto -setparam:name='IIS Web Application Name',value='MusicStoreSite/' -setparam:name='MusicStoreEntities-Deployment Connection String',value='Server=SQL01;Database=MvcMusicStoreDb;Integrated Security=true' -setparam:name='Sql script variable `$(poolUser) in MusicStoreEntities-Deployment scripts',value='CONTOSO\MusicStoreAppPoolUsr' -setparam:name='MusicStoreEntities-Web.config Connection String',value='Server=SQL01;Database=MvcMusicStoreDb;Integrated Security=true'" -Wait
    #endregion
}

#endregion 
#region Module 2 - Lab 4 - Exercice 4
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 4' -ComputerName SQL01 -ScriptBlock {
	#region Task 1
    Invoke-SqlCmd -ServerInstance . `
        -Query "IF EXISTS (SELECT name FROM master.dbo.sysdatabases WHERE name ='MvcMusicStoreDb') `
                    BEGIN `
                        ALTER DATABASE [MvcMusicStoreDb] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; `
                        DROP DATABASE [MvcMusicStoreDb]; `
                    END;" `
	#endregion 
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 4' -ComputerName IIS01 -ScriptBlock {
	#region Task 1
    Remove-Item -Path c:\inetpub\MusicStoreRoot -Recurse -Force 
	New-Item -Path c:\inetpub\MusicStoreRoot -ItemType Directory -Force
	#endregion 
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 4' -ComputerName IIS01 -ScriptBlock {
	#region Task 2
    #Loading the Web Administration DLL for handling ServerManager
	#$null = [System.Reflection.Assembly]::LoadFrom( "$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll" )
    
    [System.Reflection.Assembly]::LoadWithPartialName(“Microsoft.Web.Management”) 
    [Microsoft.Web.Management.Server.ManagementAuthentication]::CreateUser("MusicStoreAdmin", "P@ssw0rd")
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 4' -ComputerName IIS01 -ScriptBlock {
	#region Task 3
    #Allowing this IIS User to the MusicStoreSite website
    [Microsoft.Web.Management.Server.ManagementAuthorization]::Grant("MusicStoreAdmin", "MusicStoreSite", $FALSE)

	icacls C:\InetPub\MusicStoreRoot /T /grant --% "Contoso\WDeployConfigWriter":(F)
    #endregion
}

Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 5' -ComputerName IIS02 -ScriptBlock {
	#To avoid errors if some web deploy dependencies are not present
    $LocalWebDeployInstaller = "C:\LabFiles\2. Administration\InstallSource\WebDeploy_amd64_en-US.msi" 
	Start-Process -FilePath $LocalWebDeployInstaller -Argument "/passive" -Wait
}
#endregion 
#region Module 2 - Lab 4 - Exercice 5			
Invoke-LabCommand -ActivityName 'Module 2 - Lab 4 - Exercice 5' -ComputerName IIS01 -ScriptBlock {
	#region Task 2
    #Loading the Web Administration DLL for handling ServerManager
	#$null = [System.Reflection.Assembly]::LoadFrom( "$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll" )
	Add-Type -Path "$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll"
	#Creating a ServerManager Object
	$ServerManager = New-Object -TypeName Microsoft.Web.Administration.ServerManager
	$Configuration = $ServerManager.GetAdministrationConfiguration()
	$delegationSection = $Configuration.GetSection("system.webServer/management/delegation")
	$delegationRulesCollection = $delegationSection.GetCollection()
	#Clearing the existing collection
	$delegationRulesCollection.Clear()

	#Adding first rule
	$newRule = $delegationRulesCollection.CreateElement("rule")
	$newRule.Attributes["providers"].Value = "iisApp,CreateApp,setAcl"
	$newRule.Attributes["actions"].Value = "*"
	$newRule.Attributes["path"].Value = "{userScope}"
	$newRule.Attributes["pathType"].Value = "PathPrefix"
	$newRule.Attributes["enabled"].Value = $true

	$runAs = $newRule.GetChildElement("runAs")
	$runAs.Attributes["identityType"].Value = "SpecificUser"
	$runAs.Attributes["userName"].Value = "Contoso\WDeployConfigWriter"
	$runAs.Attributes["password"].Value = "P@ssw0rd"
			
	$permissions = $newRule.GetCollection("permissions")
	$user = $permissions.CreateElement("user")
	$user.Attributes["name"].Value = "*"
	$user.Attributes["accessType"].Value = "Allow"
	$user.Attributes["isRole"].Value = "False"
	$permissions.Add($user) | out-null
	$delegationRulesCollection.Add($newRule) | out-null

	#Adding second rule
	$newRule = $delegationRulesCollection.CreateElement("rule")
	$newRule.Attributes["providers"].Value = "dbFullSql"
	$newRule.Attributes["actions"].Value = "*"
	$newRule.Attributes["path"].Value = "Server=SQL01;Database=MvcMusicStoreDb;Integrated Security=true"
	$newRule.Attributes["pathType"].Value = "ConnectionString"
	$newRule.Attributes["enabled"].Value = $true

	$runAs = $newRule.GetChildElement("runAs")
	$runAs.Attributes["identityType"].Value = "SpecificUser"
	$runAs.Attributes["userName"].Value = "Contoso\WebDeploySqlUsr"
	$runAs.Attributes["password"].Value = "P@ssw0rd"
			
	$permissions = $newRule.GetCollection("permissions")
	$user = $permissions.CreateElement("user")
	$user.Attributes["name"].Value = "*"
	$user.Attributes["accessType"].Value = "Allow"
	$user.Attributes["isRole"].Value = "False"
	$permissions.Add($user) | out-null
	$delegationRulesCollection.Add($newRule) | out-null

	$serverManager.CommitChanges()
    #endregion 
}
#endregion 

#Checkpoint after Module 2
Checkpoint-LabVM -SnapshotName 'Module 2' -All
#endregion 

#region Module 3
#region Module 3 - Lab 1 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName DC01 -ScriptBlock {
	#region Task 1
    Import-Module ActiveDirectory
	New-ADUser SecurityUser1 -AccountPassword (ConvertTo-SecureString -AsPlainText 'P@ssw0rd' -Force) -AccountExpirationDate $null -Enabled $true -PasswordNeverExpires $true
	New-ADUser SecurityUser2 -AccountPassword (ConvertTo-SecureString -AsPlainText 'P@ssw0rd' -Force) -AccountExpirationDate $null -Enabled $true -PasswordNeverExpires $true
	New-ADGroup -Name "Security Users" -Description "Security Users" -GroupScope DomainLocal
	Add-ADGroupMember "Security Users" -Members "SecurityUser1"
	New-ADUser MyAppPoolId -AccountPassword (ConvertTo-SecureString -AsPlainText 'P@ssw0rd' -Force) -AccountExpirationDate $null -Enabled $true
	Invoke-Command -ScriptBlock {Add-LocalGroupMember -Group "Remote Desktop Users" -Member SecurityUser1, SecurityUser2} -ComputerName IIS01, IIS02

	#dnscmd . /recordadd contoso.com security.contoso.com. A 10.0.0.109
	Add-DnsServerResourceRecordA -Name "security" -ZoneName "contoso.com" -IPv4Address "10.0.0.109" -CreatePtr  
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    & "C:\LabFiles\3. Security\Windows Authentication, SPN and NTFS Permissions\IIS01_LabSetup.cmd"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 2
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "security.contoso.com" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "security.contoso.com" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/security.contoso.com" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    icacls c:\MyWebContents\security.contoso.com --% /grant "CONTOSO\Security Users":(R) /T
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName IIS02 -ScriptBlock {
    #region Task 2
	#Setting security.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
	$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\security.contoso.com" -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\security.contoso.com" -Name http -Value 1 -Type DWord -Force
	$null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\security" -Force
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\security" -Name http -Value 1 -Type DWord -Force
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName IIS02 -ScriptBlock {
    #region Task 3
	$LocalNetMonInstaller = "C:\LabFiles\3. Security\Windows Authentication, SPN and NTFS Permissions\NM34_x64.exe"
	Start-Process -FilePath $LocalNetMonInstaller -Argument "/q" -Wait
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 5
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='security.contoso.com']/processModel" -name 'identityType' -value 3
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='security.contoso.com']/processModel" -name 'userName' -value "CONTOSO\MyAppPoolId"
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='security.contoso.com']/processModel" -name 'password' -value P@ssw0rd
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "security.contoso.com" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 1 - Exercice 1' -ComputerName DC01 -ScriptBlock {
    #region Task 6
	(Get-ADComputer -Identity IIS01 -Properties ServicePrincipalNames).ServicePrincipalNames
	Set-ADComputer -Identity IIS01 -ServicePrincipalNames @{Remove="HTTP/security.contoso.com", "HTTP/security"}
	(Get-ADComputer -Identity IIS01 -Properties ServicePrincipalNames).ServicePrincipalNames
	Set-ADUser -Identity myAppPoolId -ServicePrincipalNames @{Add="HTTP/security.contoso.com", "HTTP/security"}
	(Get-ADUser -Identity myAppPoolId -Properties ServicePrincipalNames).ServicePrincipalNames
    #endregion
}
#endregion 
#region Module 3 - Lab 2 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 1' -ComputerName IIS02 -ScriptBlock {
    #region Task 1
    & "C:\LabFiles\3. Security\SNI and CCS\IIS02_LabSetup.cmd"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
    & "C:\LabFiles\3. Security\SNI and CCS\IIS01_LabSetup.cmd"

	Import-Module ServerManager
	Install-WindowsFeature Web-CertProvider
	Enable-WebCentralCertProvider -CertStoreLocation '\\IIS02\CentralSSLShare' -UserName 'CONTOSO\CentralSSLUser' -Password 'P@ssw0rd' -PrivateKeyPassword 'P@ssw0rd'
    #endregion
}
#endregion 
#region Module 3 - Lab 2 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	netsh http show sslcert  | Out-File C:\CCS_SNI_Before.txt
	New-WebAppPool -Name "securityCCSSNI.contoso.com" -Force
	New-WebSite -Name "securityCCSSNI.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSSNI.contoso.com" -ApplicationPool "securityCCSSNI.contoso.com" -Ssl -SslFlags 3 -HostHeader "securityCCSSNI.contoso.com" -Force
	New-Item -Path "IIS:\SslBindings\!443!securityCCSSNI.contoso.com" -sslFlags 3 -Store CentralCertStore

	netsh http show sslcert  | Out-File C:\CCS_SNI_After.txt
	Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters 
    #endregion 
}
#endregion 
#region Module 3 - Lab 2 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	netsh http show sslcert | Out-File C:\CCS_No_SNI_After.txt
	New-WebAppPool -Name "securityCCSNoSNI.contoso.com" -Force
	New-WebSite -Name "securityCCSNoSNI.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSNoSNI.contoso.com" -ApplicationPool "securityCCSNoSNI.contoso.com" -Ssl -SslFlags 2 -HostHeader "securityCCSNoSNI.contoso.com" -Force

	netsh http show sslcert | Out-File C:\CCS_No_SNI_After.txt
    #endregion 
}
#endregion 
#region Module 3 - Lab 2 - Exercice 4
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 4' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	netsh http show sslcert | Out-File C:\CCS_Wildcard_Before.txt
	New-WebAppPool -Name "securityCCSWildcardCert.contoso.com" -Force
	New-WebSite -Name "securityCCSWildcardCert.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSWildcardCert.contoso.com" -ApplicationPool "securityCCSWildcardCert.contoso.com" -Ssl -sslFlags 3 -HostHeader "securityCCSWildcardCert.contoso.com" -Force
	netsh http show sslcert | Out-File C:\CCS_Wildcard_After.txt
}
#endregion 
#region Module 3 - Lab 2 - Exercice 5
Invoke-LabCommand -ActivityName 'Module 3 - Lab 2 - Exercice 5' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	New-WebAppPool -Name "securityCCSSanCert0.contoso.com" -Force
	New-WebSite -Name "securityCCSSanCert0.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSSanCert0.contoso.com" -ApplicationPool "securityCCSSanCert0.contoso.com" -Ssl -SslFlags 2 -HostHeader "securityCCSSanCert0.contoso.com" -Force

	New-WebAppPool -Name "securityCCSSanCert1.contoso.com" -Force
	New-WebSite -Name "securityCCSSanCert1.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSSanCert1.contoso.com" -ApplicationPool "securityCCSSanCert1.contoso.com" -Ssl -SslFlags 2 -HostHeader "securityCCSSanCert1.contoso.com" -Force

	New-WebAppPool -Name "securityCCSSanCert2.contoso.com" -Force
	New-WebSite -Name "securityCCSSanCert2.contoso.com" -Port 443 -PhysicalPath "C:\MyWebContents\securityCCSSanCert2.contoso.com" -ApplicationPool "securityCCSSanCert2.contoso.com" -Ssl -SslFlags 2 -HostHeader "securityCCSSanCert2.contoso.com" -Force
    #endregion 
}
#endregion 

#Checkpoint after Module 3
Checkpoint-LabVM -SnapshotName 'Module 3' -All
#endregion 
#endregion

#region Module 4
#region Module 4 - Lab 1 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1    
	Set-Location -Path "C:\LabFiles\4. Troubleshooting"
	& "C:\LabFiles\4. Troubleshooting\setup_httperrors.cmd"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 2    
	$LocalWCATInstaller = "C:\LabFiles\4. Troubleshooting\tools\wcat.amd64.msi"
	Start-Process -FilePath $LocalWCATInstaller -Argument "/passive" -Wait
	Set-Location -Path "C:\Program Files\wcat"
	cscript //h:cscript
	Start-Process -FilePath "wcat.wsf" -Argument "-terminate -update -clients localhost" -Wait
    #endregion
}
#Reboot
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 3    
	Set-Location -Path "C:\Program Files\wcat"
	Start-Process -FilePath "wcat.wsf" -Argument "-terminate -run -clients localhost -t C:\WCAT_Test\exercise1.ubr -server localhost -virtualclients 5 -x -singleip" -Wait
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 1' -ComputerName DC01 -ScriptBlock {
    #region Task 4
    & "\\IIS01\c$\Program Files\wcat\log.xml"
    #endregion
}
#endregion 
#region Module 4 - Lab 1 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	$LocalLogParserInstaller = "C:\LabFiles\4. Troubleshooting\tools\LogParser.msi"
	Start-Process -FilePath $LocalLogParserInstaller -Argument "/passive" -Wait
	[System.Environment]::SetEnvironmentVariable('PATH', [System.Environment]::GetEnvironmentVariable('PATH',[System.EnvironmentVariableTarget]::Machine)+";C:\Program Files (x86)\log parser 2.2",[System.EnvironmentVariableTarget]::Machine)
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
    #region Task 2
	& "C:\Program Files (x86)\log parser 2.2\LogParser.exe" "Select cs-uri-stem, count(*) from C:\inetpub\logs\LogFiles\W3SVC1\*.log where sc-status=503 and cs-uri-stem like '%/website/%' group by cs-uri-stem" -i:W3C
	& "C:\Program Files (x86)\log parser 2.2\LogParser.exe" "Select cs-uri-stem, sc-status, count(*) from C:\inetpub\logs\LogFiles\W3SVC1\*.log where cs-uri-stem like '%page1.aspx' group by cs-uri-stem, sc-status" -i:w3c
	& "C:\Program Files (x86)\log parser 2.2\LogParser.exe" "select cs-uri-stem, avg(time-taken) from C:\inetpub\logs\LogFiles\W3SVC1\*.log where cs-uri-stem like '%page1%' and sc-status=200 group by cs-uri-stem" -i:w3c 
	& "C:\Program Files (x86)\log parser 2.2\LogParser.exe" "select cs-uri-stem, avg(time-taken) from C:\inetpub\logs\LogFiles\W3SVC1\*.log where cs-uri-stem like '%page1%' and sc-status=503 group by cs-uri-stem" -i:w3c 
    #endregion
}
#endregion 
#region Module 4 - Lab 1 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
	#region Task 1
    (Get-Content C:\inetpub\wwwroot\website\Page1.aspx).Replace(" %>", ' Trace="True"%>') | Out-File C:\inetpub\wwwroot\website\Page1.aspx
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
	#region Task 2
	#Installing Failed Request Tracing
	Add-WindowsFeature Web-Http-Tracing
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/traceFailedRequestsLogging" -name "enabled" -value "True"
	#FREB
	Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/tracing/traceFailedRequests" -name "." -value @{path='page1.aspx'}
	Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/tracing/traceFailedRequests/add[@path='page1.aspx']/traceAreas" -name "." -value @{provider='ASPNET';areas='Infrastructure,Module,Page,AppServices';verbosity='Verbose'}
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/tracing/traceFailedRequests/add[@path='page1.aspx']/failureDefinitions" -name "statusCodes" -value "503"
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 1 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
	#region Task 3
	Set-Location -Path "C:\Program Files\wcat"
	Start-Process -FilePath "wcat.wsf" -Argument " -terminate -run -clients localhost -t C:\WCAT_Test\exercise1.ubr -server localhost -virtualclients 5 -x -singleip" -Wait
	Set-Location -Path "C:\inetpub\logs\FailedReqLogFiles\W3SVC1"
    & $((Get-ChildItem -File -Filter fr*.xml | Sort-Object -Property Name | Select-Object -Last 1).Fullname)
	#endregion
}
#endregion 
#region Module 4 - Lab 2 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 1
	Add-WindowsFeature Web-Dyn-Compression
	Set-Location -Path "C:\LabFiles\4. Troubleshooting"
	& "C:\LabFiles\4. Troubleshooting\setup_compression.cmd"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 2
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/urlCompression" -name "doStaticCompression" -value "False"
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/urlCompression" -name "doDynamicCompression" -value "False"
	Set-Location -Path "C:\WCAT_Test"
	& "C:\WCAT_Test\perftest.bat"
	Copy-Item -Path "C:\Program Files\Wcat\report.xsl" -Destination "C:\WCAT_Test"
	#& "C:\WCAT_Test\log.xml"
    #endregion
}

Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName DC01 -ScriptBlock {
    #region Task 2
    & "\\IIS01\c$\WCAT_Test\log.xml"
    #endregion
}

Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 3			
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/urlCompression" -name "doStaticCompression" -value "True"
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/urlCompression" -name "doDynamicCompression" -value "True"
	Set-Location -Path "C:\WCAT_Test"
	& "C:\WCAT_Test\perftest.bat"
	Copy-Item -Path "C:\Program Files\Wcat\report.xsl" -Destination "C:\WCAT_Test"
	#& "C:\WCAT_Test\log.xml"
    #endregion
}

Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName DC01 -ScriptBlock {
    #region Task 3
    & "\\IIS01\c$\WCAT_Test\log.xml"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 4
	C:\Windows\System32\inetsrv\appcmd list config "Default Web Site/WebSite" /section:httpCompression
	C:\Windows\System32\inetsrv\appcmd list config "Default Web Site/WebSite" /section:urlCompression
    #endregion
}
#endregion
#region Module 4 - Lab 2 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task1
	logman query providers "IIS: WWW Server"
	logman start iistrace -p "IIS: WWW Server" IISCompression Verbose -ets
	Set-Location -Path "C:\WCAT_Test"
	& "C:\WCAT_Test\perftest.bat"
	logman stop iistrace -ets
	tracerpt iistrace.etl -of csv
	notepad summary.txt
	notepad dumpfile.csv
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task2
	(Get-content "C:\WCAT_Test\perfexercise.ubr").Replace('//setheader', 'setheader').Replace('//{', '{').Replace('//	name = "Accept-Encoding";', '	name = "Accept-Encoding";').Replace('//	value = "gzip,deflate";', '	value = "gzip,deflate";').Replace('//}', '}') | Out-File "C:\WCAT_Test\perfexercise.ubr"
	Set-Location -Path "C:\WCAT_Test"
	& "C:\WCAT_Test\perftest.bat"
	#& "C:\WCAT_Test\log.xml"
    #endregion
}

Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 2' -ComputerName DC01 -ScriptBlock {
    #region Task 3
    & "\\IIS01\c$\WCAT_Test\log.xml"
    #endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 2 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task3
	(Get-content "c:\inetpub\wwwroot\website\default.aspx.cs").Replace("//        ds.EnableDecompression = true;", "        ds.EnableDecompression = true;") | Out-File "c:\inetpub\wwwroot\website\default.aspx.cs"
    #endregion
}
#endregion 
#region Module 4 - Lab 3 - Exercice 1
Invoke-LabCommand -ActivityName 'Module 4 - Lab 3 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
	#region Task 1 
    Set-Location "C:\LabFiles\4. Troubleshooting"
    & "C:\LabFiles\4. Troubleshooting\setup.cmd"
	#endregion
}
Invoke-LabCommand -ActivityName 'Module 4 - Lab 3 - Exercice 1' -ComputerName IIS01 -ScriptBlock {
    #region Task 2 
	#endregion
    #region Task 3 
	$DesktopPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop"
	Copy-Item -Path "C:\LabFiles\4. Troubleshooting\hang.bat" -Destination $DesktopPath
	Copy-Item -Path "C:\LabFiles\4. Troubleshooting\Exercise2.ubr  " -Destination $DesktopPath
	& "$(Join-Path -Path $DesktopPath -ChildPath 'hang.bat')"
	#endregion
}
#endregion 
#region Module 4 - Lab 3 - Exercice 2
Invoke-LabCommand -ActivityName 'Module 4 - Lab 3 - Exercice 2' -ComputerName IIS01 -ScriptBlock {
	#region Task 2
    Add-WindowsFeature -Name  Web-Request-Monitor
	C:\Windows\System32\inetsrv\appcmd list wp
    #endregion
}

#endregion 
#region Module 4 - Lab 3 - Exercice 3
Invoke-LabCommand -ActivityName 'Module 4 - Lab 3 - Exercice 3' -ComputerName IIS01 -ScriptBlock {
	#region Task 1
    $LocalDebugDiagInstaller = "C:\LabFiles\4. Troubleshooting\tools\DebugDiagx64.msi"
	Start-Process -FilePath $LocalDebugDiagInstaller -Argument "/passive" -Wait
    Expand-Archive -Path "C:\LabFiles\4. Troubleshooting\w3wp.zip" -DestinationPath "C:\LabFiles\4. Troubleshooting"
    #endregion
}
#endregion 

#endregion 

#Checkpoint after Module 4
Checkpoint-LabVM -SnapshotName 'Module 4' -All
#endregion 

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript