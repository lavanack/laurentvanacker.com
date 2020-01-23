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
Clear-Host
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'Continue'
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
$ADUser='JohnDoe'
$AnonymousWebSiteName="anonymous.$FQDNDomainName"
$BasicWebSiteName="basic.$FQDNDomainName"
$KerberosWebSiteName="kerberos.$FQDNDomainName"
$NTLMWebSiteName="ntlm.$FQDNDomainName"
$DigestWebSiteName="digest.$FQDNDomainName"
$ADClientCertWebSiteName="adclientcert.$FQDNDomainName"
$IISClientCertWebSiteName="iisclientcert.$FQDNDomainName"
$FormsWebSiteName="forms.$FQDNDomainName"

$LabName = 'IISAuthLab'
#endregion

#region Dirty Clean up
If (Test-Path -Path C:\ProgramData\AutomatedLab\Labs\$LabName\Lab.xml)
{
    #Importing lpreviously existing lab
    $Lab = Import-Lab -Path C:\ProgramData\AutomatedLab\Labs\$LabName\Lab.xml -ErrorAction SilentlyContinue -PassThru
    if ($Lab)
    {
        #Get-LabVM | Get-VM | Restore-VMCheckpoint -Name "FullInstall" -Confirm:$false
        #Getting exisiting VM
        $HyperVLabVM = Get-LabVM | Get-VM -ErrorAction SilentlyContinue
        if ($HyperVLabVM)
        {
            $HyperVLabVMPath = (Get-Item $($HyperVLabVM.Path)).Parent.FullName
            #Turning off existing VM
            $HyperVLabVM | Stop-VM -TurnOff -Force -Passthru | Remove-VM -Force -Verbose
            #Removing related files
            Remove-Item $HyperVLabVMPath -Recurse -Force -Verbose #-WhatIf
        }
        try
        {
            #Clearing lab from an AutomatedLab (AL) perspective
            Remove-Lab -Name $LabName -Verbose -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch 
        {

        }
    }
}
#endregion

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -HyperVProperties @{
    SwitchType = 'Internal'
}  -AddressSpace 10.0.0.0/16

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'       = $LabName
    'Add-LabMachineDefinition:DomainName'    = $FQDNDomainName
    'Add-LabMachineDefinition:Memory'        = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 Standard (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'    = 2
}

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress 10.0.0.1
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress 10.0.0.2
#IIS front-end server
Add-LabMachineDefinition -Name IISNODE01 -IpAddress 10.0.0.21
#IIS front-end server
Add-LabMachineDefinition -Name CLIENT01 -IpAddress 10.0.0.22
#endregion

#Installing servers
Install-Lab
#Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose

#region Installing Required Windows Features
$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools
Install-LabWindowsFeature -FeatureName Web-Server, Web-Asp-Net45, Web-Request-Monitor, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Cert-Auth, Web-Windows-Auth -ComputerName IISNODE01 -IncludeManagementTools

#endregion


Invoke-LabCommand -ActivityName "Disabling IE ESC and Adding $KerberosWebSiteName to the IE intranet zone" -ComputerName $machines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force

    #Only local computer settings are used and all users have the same security settings: https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
    $null = New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name Security_HKLM_only -Value 1 -Type DWord -Force

    #Setting kerberos.contoso.com, ntlm.contoso.com and IISNODE01.contoso.com in the Local Intranet Zone for all servers and all users : mandatory for Windows authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:KerberosWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:KerberosWebSiteName" -Name http -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NTLMWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NTLMWebSiteName" -Name http -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force

    #region Changing the start page for IE
    $path = "HKCU:\Software\Microsoft\Internet Explorer\Main\"
    $name = "start page"
    $value = "http://$using:AnonymousWebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
    #Bonus : To open all the available websites accross all nodes
    $name = "Secondary Start Pages"
    $value="https://$using:BasicWebSiteName", "http://$using:KerberosWebSiteName", "http://$using:NTLMWebSiteName", "http://$using:DigestWebSiteName", "http://$using:ADClientCertWebSiteName", "http://$using:IISClientCertWebSiteName", "http://$using:FormsWebSiteName"
    New-ItemProperty -Path $path -PropertyType MultiString -Name $name -Value $value -Force
    #endregion

}

#Installing and setting up DFS-R on DC for replicated folder on IIS Servers for shared configuration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    #Creating AD Users
    #User for testing authentications
    New-ADUser -Name $Using:ADUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    #Application Pool Identity
    New-ADUser -Name $Using:IISAppPoolUser -AccountPassword $Using:SecurePassword -PasswordNeverExpires $True -CannotChangePassword $True -Enabled $True

    #GPO Settings for setting up the IE start page(s) for all users
    Import-Module GroupPolicy
    Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\" -ValueName "start page" -Type String -Value "http://$using:AnonymousWebSiteName/"
    #Bonus : To open all the available websites accross all nodes
    $value="https://$using:BasicWebSiteName", "http://$using:KerberosWebSiteName", "http://$using:NTLMWebSiteName", "http://$using:DigestWebSiteName", "http://$using:ADClientCertWebSiteName", "http://$using:IISClientCertWebSiteName", "http://$using:FormsWebSiteName"
    Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\" -ValueName "Secondary Start Pages" -Type MultiString -Value $value


    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID '10.0.0.0/16' -ReplicationScope 'Forest' 
    #DNS Host entry for the kerberos.contoso.com website 
    Add-DnsServerResourceRecordA -Name 'anonymous' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.101' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'basic' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.102' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'kerberos' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.103' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'ntlm' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.104' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'digest' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.105' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'adclientcert' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.106' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'iisclientcert' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.107' -CreatePtr
    Add-DnsServerResourceRecordA -Name 'forms' -ZoneName $using:FQDNDomainName -IPv4Address '10.0.0.108' -CreatePtr
    #endregion

    #region Setting SPN on the Application Pool Identity for kerberos authentication
    setspn.exe -S "HTTP/$using:KerberosWebSiteName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/kerberos" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01.$using:FQDNDomainName" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    setspn.exe -S "HTTP/IISNODE01" "$using:NetBiosDomainName\$Using:IISAppPoolUser"
    #endregion
}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for SSL Web Server certificate
New-LabCATemplate -TemplateName WebServerSSL -DisplayName 'Web Server SSL' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate
$BasicWebSiteSSLCert = Request-LabCertificate -Subject "CN=$BasicWebSiteName" -SAN $BasicWebSiteName, "basic", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
$DigestWebSiteSSLCert = Request-LabCertificate -Subject "CN=$DigestWebSiteName" -SAN $DigestWebSiteName, "digest", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
#endregion

#Copying Web site content on all IIS servers
Copy-LabFileItem -Path $CurrentDir\contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName IISNODE01

Invoke-LabCommand -ActivityName 'Adding the AD User to the "Remote Desktop Users" group for RDP connection' -ComputerName CLIENT01 -ScriptBlock {
    #Adding the AD User to the "Remote Desktop Users" group for RDP connection
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Using:ADUser
}


Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IISNODE01 -ScriptBlock {
    #region Assiging dedicated IP address
    New-NetIPAddress –IPAddress 10.0.0.101 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.102 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.103 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.104 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.105 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.106 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.107 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    New-NetIPAddress –IPAddress 10.0.0.108 –PrefixLength 24 –InterfaceAlias "Ethernet" 
    #endregion

    $null=New-Item -Path C:\WebSites -ItemType Directory -Force
    Get-ACl C:\inetpub\wwwroot | Set-Acl C:\WebSites
    #region unzipping site content to dedicated folders
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:AnonymousWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:BasicWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:KerberosWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:NTLMWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:DigestWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:ADClientCertWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:IISClientCertWebSiteName -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath C:\WebSites\$using:FormsWebSiteName -Force
    #endregion

    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'

    #region Creating a dedicated application pools
    New-WebAppPool -Name "$using:AnonymousWebSiteName" -Force
    New-WebAppPool -Name "$using:BasicWebSiteName" -Force
    New-WebAppPool -Name "$using:KerberosWebSiteName" -Force
    New-WebAppPool -Name "$using:NTLMWebSiteName" -Force
    New-WebAppPool -Name "$using:DigestWebSiteName" -Force
    New-WebAppPool -Name "$using:ADClientCertWebSiteName" -Force
    New-WebAppPool -Name "$using:IISClientCertWebSiteName" -Force
    New-WebAppPool -Name "$using:FormsWebSiteName" -Force
    #endregion

    #region Creating a dedicated web sites
    New-WebSite -Name "$using:AnonymousWebSiteName" -Port 80 -IPAddress 10.0.0.101 -PhysicalPath "C:\WebSites\$using:AnonymousWebSiteName" -ApplicationPool $using:AnonymousWebSiteName -Force
    #New-WebSite -Name "$using:BasicWebSiteName" -Port 80 -IPAddress 10.0.0.102 -PhysicalPath "C:\WebSites\$using:BasicWebSiteName" -ApplicationPool $using:BasicWebSiteName -Force
    New-WebSite -Name "$using:BasicWebSiteName" -Port 443 -IPAddress 10.0.0.102 -PhysicalPath "C:\WebSites\$using:BasicWebSiteName" -ApplicationPool $using:BasicWebSiteName -Ssl -SslFlags 0 -Force
    New-WebSite -Name "$using:KerberosWebSiteName" -Port 80 -IPAddress 10.0.0.103 -PhysicalPath "C:\WebSites\$using:KerberosWebSiteName" -ApplicationPool $using:KerberosWebSiteName -Force
    New-WebSite -Name "$using:NTLMWebSiteName" -Port 80 -IPAddress 10.0.0.104 -PhysicalPath "C:\WebSites\$using:NTLMWebSiteName" -ApplicationPool $using:NTLMWebSiteName -Force
    New-WebSite -Name "$using:DigestWebSiteName" -Port 80 -IPAddress 10.0.0.105 -PhysicalPath "C:\WebSites\$using:DigestWebSiteName" -ApplicationPool $using:DigestWebSiteName -Force
    New-WebSite -Name "$using:ADClientCertWebSiteName" -Port 80 -IPAddress 10.0.0.106 -PhysicalPath "C:\WebSites\$using:ADClientCertWebSiteName" -ApplicationPool $using:ADClientCertWebSiteName -Force
    New-WebSite -Name "$using:IISClientCertWebSiteName" -Port 80 -IPAddress 10.0.0.107 -PhysicalPath "C:\WebSites\$using:IISClientCertWebSiteName" -ApplicationPool $using:IISClientCertWebSiteName -Force
    New-WebSite -Name "$using:FormsWebSiteName" -Port 80 -IPAddress 10.0.0.108 -PhysicalPath "C:\WebSites\$using:FormsWebSiteName" -ApplicationPool $using:FormsWebSiteName -Force
    #endregion

    Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='default.aspx'} -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -atIndex 0 -Value @{ value = 'default.aspx' } -Force

    #region : Anonymous website management
    # NOTHING TO DO !
    #endregion

    #region : Basic website management
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\10.0.0.102!443!$using:BasicWebSiteName" -Thumbprint $($using:BasicWebSiteSSLCert).Thumbprint -sslFlags 0
    #Require SSL
    Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:BasicWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:BasicWebSiteName" | Remove-WebBinding
    #Enabling the Basic authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/security/authentication/basicAuthentication' -name 'enabled' -value 'True'
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:BasicWebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : Kerberos website management
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'password' -value $Using:ClearTextPassword

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:KerberosWebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    <#    
    #region : NTLM website management
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:NTLMWebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Clearing the Windows authentication providers:
    Remove-WebConfigurationProperty -location "$using:NTLMWebSiteName" -filter system.webServer/security/authentication/windowsAuthentication/providers -name "."
    #Adding the NTLM provider:
    Add-WebConfiguration -Filter system.webServer/security/authentication/windowsAuthentication/providers -location "$using:NTLMWebSiteName" -Value NTLM

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : Digest website management
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:BasicWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/security/authentication/digestAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:DigestWebSiteName"  -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName"  -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion
    #>
}


Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
#Get-LabVM | Get-VM | Restore-VMCheckpoint -Name "FullInstall" -Confirm:$false
Stop-Transcript