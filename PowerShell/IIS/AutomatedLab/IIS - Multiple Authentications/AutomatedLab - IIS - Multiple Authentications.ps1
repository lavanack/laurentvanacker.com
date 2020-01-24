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

$NetworkID='10.0.0.0/16' 
$DCIPv4Address = '10.0.0.1'
$CAIPv4Address = '10.0.0.2'
$IISNODEIPv4Address = '10.0.0.21'
$CLIENTIPv4Address = '10.0.0.22'

$AnonymousNetBiosName='anonymous'
$AnonymousWebSiteName="$AnonymousNetBiosName.$FQDNDomainName"
$AnonymousIPv4Address = '10.0.0.101'

$BasicNetBiosName='basic'
$BasicWebSiteName="$BasicNetBiosName.$FQDNDomainName"
$BasicIPv4Address = '10.0.0.102'

$KerberosNetBiosName='kerberos'
$KerberosWebSiteName="$KerberosNetBiosName.$FQDNDomainName"
$KerberosIPv4Address = '10.0.0.103'

$NTLMNetBiosName='ntlm'
$NTLMWebSiteName="$NTLMNetBiosName.$FQDNDomainName"
$NTLMIPv4Address = '10.0.0.104'

$DigestNetBiosName='digest'
$DigestWebSiteName="$DigestNetBiosName.$FQDNDomainName"
$DigestIPv4Address = '10.0.0.105'

$ADClientCertNetBiosName='adclientcert'
$ADClientCertWebSiteName="$ADClientCertNetBiosName.$FQDNDomainName"
$ADClientCertIPv4Address = '10.0.0.106'

$IISClientOneToOneCertNetBiosName='iisclientcert-onetoone'
$IISClientOneToOneCertWebSiteName="$IISClientOneToOneCertNetBiosName.$FQDNDomainName"
$IISClientOneToOneCertIPv4Address = '10.0.0.107'

$IISClientManyToOneCertNetBiosName='iisclientcert-manytoone'
$IISClientManyToOneCertWebSiteName="$IISClientManyToOneCertNetBiosName.$FQDNDomainName"
$IISClientManyToOneCertIPv4Address = '10.0.0.108'

$FormsNetBiosName='forms'
$FormsWebSiteName="$FormsNetBiosName.$FQDNDomainName"
$FormsIPv4Address = '10.0.0.109'


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
} -AddressSpace $NetworkID

#and the domain definition with the domain admin account
Add-LabDomainDefinition -Name $FQDNDomainName -AdminUser $Logon -AdminPassword $ClearTextPassword

#these credentials are used for connecting to the machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'       = $LabName
    'Add-LabMachineDefinition:DomainName'    = $FQDNDomainName
    'Add-LabMachineDefinition:Memory'        = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Standard (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'    = 2
}

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DCIPv4Address
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress $CAIPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name IISNODE01 -IpAddress $IISNODEIPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name CLIENT01 -IpAddress $CLIENTIPv4Address
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

    #Setting kerberos.contoso.com, IISNODE01.contoso.com and IISNODE02.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:KerberosWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:KerberosWebSiteName" -Name http -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NTLMWebSiteName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NTLMWebSiteName" -Name http -Value 1 -Type DWord -Force
    $null = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IISNODE01.$using:FQDNDomainName" -Name http -Value 1 -Type DWord -Force

    #Changing the start page for IE
    $path = "HKCU:\Software\Microsoft\Internet Explorer\Main\"
    $name = "start page"
    $value = "http://$using:AnonymousWebSiteName/"
    Set-ItemProperty -Path $path -Name $name -Value $value -Force
    #Bonus : To open all the available websites accross all nodes
    $name = "Secondary Start Pages"
    $value="https://$using:BasicWebSiteName", "http://$using:KerberosWebSiteName", "http://$using:NTLMWebSiteName", "http://$using:DigestWebSiteName", "https://$using:ADClientCertWebSiteName", "https://$using:IISClientOneToOneCertWebSiteName", "https://$using:IISClientManyToOneCertWebSiteName", "http://$using:FormsWebSiteName"
    New-ItemProperty -Path $path -PropertyType MultiString -Name $name -Value $value -Force
}

#Installing and setting up DFS-R on DC for replicated folder on IIS Servers for shared configuration
Invoke-LabCommand -ActivityName 'DNS & DFS-R Setup on DC' -ComputerName DC01 -ScriptBlock {
    #Creating AD Users
    #User for testing authentications
    New-ADUser -Name $Using:ADUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    Add-ADGroupMember -Identity "Administrators" -Member $Using:ADUSer
    #Application Pool Identity
    New-ADUser -Name $Using:IISAppPoolUser -AccountPassword $Using:SecurePassword -PasswordNeverExpires $True -CannotChangePassword $True -Enabled $True

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entry for the kerberos.contoso.com website 
    Add-DnsServerResourceRecordA -Name "$using:AnonymousNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:AnonymousIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:BasicNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:BasicIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:KerberosNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:KerberosIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:NTLMNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:NTLMIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:DigestNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:DigestIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:ADClientCertNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:ADClientCertIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:IISClientOneToOneCertNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:IISClientOneToOneCertIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:IISClientManyToOneCertNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:IISClientManyToOneCertIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:FormsNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:FormsIPv4Address" -CreatePtr
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
New-LabCATemplate -TemplateName ClientAuthentication -DisplayName 'Client Authentication' -SourceTemplateName ClientAuth -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the basic website
$BasicWebSiteSSLCert = Request-LabCertificate -Subject "CN=$BasicWebSiteName" -SAN "basic", "$BasicWebSiteName", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate one to one website
$IISClientOneToOneCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$IISClientOneToOneCertWebSiteName" -SAN "iisclientcert-onetoone", "$IISClientOneToOneCertWebSiteName", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate many to one website
$IISClientManyToOneCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$IISClientManyToOneCertWebSiteName" -SAN "iisclientcert-manytoone", "$IISClientManyToOneCertWebSiteName", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate many to one website
$ADClientCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$ADClientCertWebSiteName" -SAN "adclientcert", "$ADClientCertWebSiteName", "IISNODE01", "IISNODE01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IISNODE01 -PassThru -ErrorAction Stop

#Copying Web site content on all IIS servers
Copy-LabFileItem -Path $CurrentDir\contoso.com.zip -DestinationFolderPath C:\Temp -ComputerName IISNODE01

$IISClientOneToOneCertContent = Invoke-LabCommand -ActivityName 'IIS Client Certificate One To One Management' -ComputerName CLIENT01 -PassThru -ScriptBlock {
    $null = Add-LocalGroupMember -Group "Administrators" -Member "$using:NetBiosDomainName\$using:ADUser" 
    #Getting a IIS client Certificate for the IIS client certificate website
    $IISClientOneToOneCert = Get-Certificate -Template ClientAuthentication -Url ldap: -CertStoreLocation Cert:\CurrentUser\My
    if ($IISClientOneToOneCert)
    {
        #Getting the content of the IIS client Certificate for the IIS client certificate website (needed later in the IIS Configuration)
        [System.Convert]::ToBase64String($IISClientOneToOneCert.Certificate.RawData, [System.Base64FormattingOptions]::None)
    }
     
}

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IISNODE01 -ScriptBlock {
    #For decryptinging SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    [Environment]::SetEnvironmentVariable("SSLKEYLOGFILE", "$env:USERPROFILE\AppData\Local\ssl-keys.log", "User")
    
    #region Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:AnonymousIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:BasicIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:KerberosIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:NTLMIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:DigestIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:ADClientCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:IISClientOneToOneCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:IISClientManyToOneCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    New-NetIPAddress –IPAddress $using:FormsIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
 
    #endregion

    #Creating directory tree for hosting web sites
    $null=New-Item -Path C:\WebSites -ItemType Directory -Force
    #applying the required ACL (via PowerShell Copy and Paste)
    Get-ACl C:\inetpub\wwwroot | Set-Acl C:\WebSites
    
    #region unzipping site content to dedicated folders
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:AnonymousWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:BasicWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:KerberosWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:NTLMWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:DigestWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:ADClientCertWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:IISClientOneToOneCertWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:IISClientManyToOneCertWebSiteName" -Force
    Expand-Archive 'C:\Temp\contoso.com.zip' -DestinationPath "C:\WebSites\$using:FormsWebSiteName" -Force
    #endregion

    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #region : Default Settings
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site'
    #Configuring The Anonymous Authentication to use the AppPoolId
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/anonymousAuthentication" -name "userName" -value ""
    #Disabling the Anonymous authentication for all websites
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled" -value "False"
    #Changing the defaut page order
    Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value='default.aspx'} -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -atIndex 0 -Value @{ value = 'default.aspx' } -Force
    #endregion 
    
    #region Creating a dedicated application pools
    New-WebAppPool -Name "$using:AnonymousWebSiteName" -Force
    New-WebAppPool -Name "$using:BasicWebSiteName" -Force
    New-WebAppPool -Name "$using:KerberosWebSiteName" -Force
    New-WebAppPool -Name "$using:NTLMWebSiteName" -Force
    New-WebAppPool -Name "$using:DigestWebSiteName" -Force
    New-WebAppPool -Name "$using:ADClientCertWebSiteName" -Force
    New-WebAppPool -Name "$using:IISClientOneToOneCertWebSiteName" -Force
    New-WebAppPool -Name "$using:IISClientManyToOneCertWebSiteName" -Force
    New-WebAppPool -Name "$using:FormsWebSiteName" -Force
    #endregion

    #region Creating a dedicated web sites
    New-WebSite -Name "$using:AnonymousWebSiteName" -Port 80 -IPAddress $using:AnonymousIPv4Address -PhysicalPath "C:\WebSites\$using:AnonymousWebSiteName" -ApplicationPool "$using:AnonymousWebSiteName" -Force
    New-WebSite -Name "$using:BasicWebSiteName" -Port 443 -IPAddress $using:BasicIPv4Address -PhysicalPath "C:\WebSites\$using:BasicWebSiteName" -ApplicationPool "$using:BasicWebSiteName" -Ssl -SslFlags 0 -Force
    New-WebSite -Name "$using:KerberosWebSiteName" -Port 80 -IPAddress $using:KerberosIPv4Address -PhysicalPath "C:\WebSites\$using:KerberosWebSiteName" -ApplicationPool "$using:KerberosWebSiteName" -Force
    New-WebSite -Name "$using:NTLMWebSiteName" -Port 80 -IPAddress $using:NTLMIPv4Address -PhysicalPath "C:\WebSites\$using:NTLMWebSiteName" -ApplicationPool "$using:NTLMWebSiteName" -Force
    New-WebSite -Name "$using:DigestWebSiteName" -Port 80 -IPAddress $using:DigestIPv4Address -PhysicalPath "C:\WebSites\$using:DigestWebSiteName" -ApplicationPool "$using:DigestWebSiteName" -Force
    New-WebSite -Name "$using:ADClientCertWebSiteName" -Port 443 -IPAddress $using:ADClientCertIPv4Address -PhysicalPath "C:\WebSites\$using:ADClientCertWebSiteName" -ApplicationPool "$using:ADClientCertWebSiteName" -Ssl -SslFlags 0 -Force
    New-WebSite -Name "$using:IISClientOneToOneCertWebSiteName" -Port 443 -IPAddress $using:IISClientOneToOneCertIPv4Address -PhysicalPath "C:\WebSites\$using:IISClientOneToOneCertWebSiteName" -ApplicationPool "$using:IISClientOneToOneCertWebSiteName" -Ssl -SslFlags 0 -Force
    New-WebSite -Name "$using:IISClientManyToOneCertWebSiteName" -Port 443 -IPAddress $using:IISClientManyToOneCertIPv4Address -PhysicalPath "C:\WebSites\$using:IISClientManyToOneCertWebSiteName" -ApplicationPool "$using:IISClientManyToOneCertWebSiteName" -Ssl -SslFlags 0 -Force
    New-WebSite -Name "$using:FormsWebSiteName" -Port 443 -IPAddress $using:FormsIPv4Address -PhysicalPath "C:\WebSites\$using:FormsWebSiteName" -ApplicationPool "$using:FormsWebSiteName" -Ssl -SslFlags 0 -Force
    #endregion

    #region : Anonymous website management
    #Enabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:AnonymousWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #endregion

    #region : Basic website management
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:BasicIPv4Address!443!$using:BasicWebSiteName" -Thumbprint $($using:BasicWebSiteSSLCert).Thumbprint -sslFlags 0
    #Require SSL
    #Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:BasicWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl"
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:BasicWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Basic authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/security/authentication/basicAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:BasicWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion
        
    #region : Kerberos website management
    #Enabling the Windows useAppPoolCredentials
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'useAppPoolCredentials' -value 'True'

    #Changing the application pool identity for an AD Account : mandatory for Kerberos authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'identityType' -value 3
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'userName' -value "$Using:NetBiosDomainName\$Using:IISAppPoolUser"
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='$using:KerberosWebSiteName']/processModel" -name 'password' -value "$Using:ClearTextPassword"

    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:KerberosWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : NTLM website management
    #Enabling the Windows useAppPoolCredentials
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Windows authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:NTLMWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

     #Clearing the Windows authentication providers:
    Remove-WebConfigurationProperty -location "$using:NTLMWebSiteName" -filter system.webServer/security/authentication/windowsAuthentication/providers -name "."
    #Adding the NTLM provider:
    Add-WebConfiguration -Filter system.webServer/security/authentication/windowsAuthentication/providers -location "$using:NTLMWebSiteName" -Value NTLM

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
   #endregion

    #region : Digest website management
    #Enabling the Windows useAppPoolCredentials
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Digest authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/security/authentication/digestAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:DigestWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

     #Clearing the Windows authentication providers:
    Remove-WebConfigurationProperty -location "$using:DigestWebSiteName" -filter system.webServer/security/authentication/windowsAuthentication/providers -name "."
    #Adding the NTLM provider:
    Add-WebConfiguration -Filter "system.webServer/security/authentication/windowsAuthentication/providers" -location "$using:DigestWebSiteName" -Value NTLM

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
   #endregion

    #region : AD Client Certificate website management
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:ADClientCertIPv4Address!443!$using:ADClientCertWebSiteName" -Thumbprint $($using:ADClientCertWebSiteSSLCert).Thumbprint -sslFlags 0
    #Enabling the 'Active Directory Client Certificate Authentication' at the server level 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/clientCertificateMappingAuthentication" -name "enabled" -value "True"
    #Enabling DsMapper for the website (mandatory) for AD Client Certificate
    (Get-WebBinding -Name "$using:ADClientCertWebSiteName").EnableDsMapper()

    #SSL + Negotiate Client Certificate 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert"
    
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:ADClientCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the One to One IIS Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/security/authentication/clientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:ADClientCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : IIS Client Certificate website management
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:IISClientOneToOneCertIPv4Address!443!$using:IISClientOneToOneCertWebSiteName" -Thumbprint $($using:IISClientOneToOneCertWebSiteSSLCert).Thumbprint -sslFlags 0
    #SSL + Negotiate Client Certificate 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert"
    
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:IISClientOneToOneCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the One to One IIS Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "oneToOneCertificateMappingsEnabled" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "manyToOneCertificateMappingsEnabled" -value "False"
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/oneToOneMappings" -name "." -value @{userName="$Using:NetBiosDomainName\$Using:Logon";password="$Using:ClearTextPassword";certificate=$using:IISClientOneToOneCertContent}

    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:IISClientOneToOneCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : IIS Client Certificate website management
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:IISClientManyToOneCertIPv4Address!443!$using:IISClientManyToOneCertWebSiteName" -Thumbprint $($using:IISClientManyToOneCertWebSiteSSLCert).Thumbprint -sslFlags 0

    #SSL + Negotiate Client Certificate 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert"
    
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:IISClientManyToOneCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the One to One IIS Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "oneToOneCertificateMappingsEnabled" -value "False"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "manyToOneCertificateMappingsEnabled" -value "True"
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings" -name "." -value @{name="$Using:Logon";description="$Using:NetBiosDomainName\$Using:Logon";userName="$Using:NetBiosDomainName\$Using:Logon";password="$Using:ClearTextPassword"}
    #Optional : Adding rules that will give you an option to add multiple patterns for matching based on certificate properties.
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings/add[@name='$Using:Logon']/rules" -name "." -value @{certificateField='Subject';certificateSubField='CN';matchCriteria="$Using:Logon"}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings/add[@name='$Using:Logon']/rules" -name "." -value @{certificateField='Issuer';certificateSubField='CN';matchCriteria="$($using:CertificationAuthority.CaName)"}
    
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:IISClientManyToOneCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
    #endregion

    #region : Forms website management
    #Enabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:FormsWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #Enabling the Forms authentication
	Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication" -name "mode" -value "Forms"

    #Setting up the Forms authentication
    #Adding to authorized users
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "system.web/authentication/forms/credentials" -name "." -value @{name="$using:Logon";password="$using:ClearTextPassword"}
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "system.web/authentication/forms/credentials" -name "." -value @{name="$using:ADUser";password="$using:ClearTextPassword"}
    #Setting up clear text password
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms/credentials" -name "passwordFormat" -value "Clear"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms" -name "defaultUrl" -value "default.aspx"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms" -name "loginUrl" -value "login.aspx"
    #Denying access to anonymous users
    #Local (web.config)
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "/system.web/authorization" -Name "." -value @{users='?'} -Type "deny"
    #Setting up the client validation mode for the application. 
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "/appSettings" -name "." -value @{key='ValidationSettings:UnobtrusiveValidationMode';value='None'}

    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False' -verbose
   #endregion
}


Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose

$VerbosePreference = $PreviousVerbosePreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript