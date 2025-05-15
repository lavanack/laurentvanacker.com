﻿<#
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
$ErrorActionPreference = 'Continue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
# This is a lab so we assume to use clear-text password (and the same for all accounts for an easier management :))  
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$IISAppPoolUser = 'IISAppPoolUser'
$TestUser = 'JohnDoe'
$TestUserCredential = New-Object System.Management.Automation.PSCredential ("$NetBiosDomainName\$TestUser", $SecurePassword)

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$CA01IPv4Address = '10.0.0.2'
$IIS01IPv4Address = '10.0.0.21'
$CLIENT01IPv4Address = '10.0.0.22'
$CLIENT02IPv4Address = '10.0.0.23'

$AnonymousNetBiosName = 'anonymous'
$AnonymousWebSiteName = "$AnonymousNetBiosName.$FQDNDomainName"
$AnonymousIPv4Address = '10.0.0.101'

$BasicNetBiosName = 'basic'
$BasicWebSiteName = "$BasicNetBiosName.$FQDNDomainName"
$BasicIPv4Address = '10.0.0.102'

$KerberosNetBiosName = 'kerberos'
$KerberosWebSiteName = "$KerberosNetBiosName.$FQDNDomainName"
$KerberosIPv4Address = '10.0.0.103'

$NTLMNetBiosName = 'ntlm'
$NTLMWebSiteName = "$NTLMNetBiosName.$FQDNDomainName"
$NTLMIPv4Address = '10.0.0.104'

$DigestNetBiosName = 'digest'
$DigestWebSiteName = "$DigestNetBiosName.$FQDNDomainName"
$DigestIPv4Address = '10.0.0.105'

$ADClientCertNetBiosName = 'adclientcert'
$ADClientCertWebSiteName = "$ADClientCertNetBiosName.$FQDNDomainName"
$ADClientCertIPv4Address = '10.0.0.106'

$IISClientOneToOneCertNetBiosName = 'iisclientcert-onetoone'
$IISClientOneToOneCertWebSiteName = "$IISClientOneToOneCertNetBiosName.$FQDNDomainName"
$IISClientOneToOneCertIPv4Address = '10.0.0.107'

$IISClientManyToOneCertNetBiosName = 'iisclientcert-manytoone'
$IISClientManyToOneCertWebSiteName = "$IISClientManyToOneCertNetBiosName.$FQDNDomainName"
$IISClientManyToOneCertIPv4Address = '10.0.0.108'
$IISClientManyToOneCertUser = 'ManyToOne'

$FormsNetBiosName = 'forms'
$FormsWebSiteName = "$FormsNetBiosName.$FQDNDomainName"
$FormsIPv4Address = '10.0.0.109'

$ClientAuthCertTemplateName = 'ClientAuthentication'
$LabName = 'IISAuthLab'

$LocalTempFolder = 'C:\Temp'

#region Tools to download and install
#Microsoft Edge : Latest version
$MSEdgeEntUri = "http://go.microsoft.com/fwlink/?LinkID=2093437"

#Wireshark Download URI
$WireSharkDownloadHome = "https://www.wireshark.org/download/win64/"
$WiresharkLatestX64 = (Invoke-WebRequest -Uri $WireSharkDownloadHome).Links | Where-Object -FilterScript { $_.innerText -match "-latest-x64.exe" } | Sort-Object -Descending
$WiresharkWin64LatestExeUri = "{0}{1}" -f $WireSharkDownloadHome, $WiresharkLatestX64.href

#IIS Crypto Cli Download URI
$IISCryptoCliExeUri = 'https://www.nartac.com/Downloads/IISCrypto/IISCryptoCli.exe'
$IISCryptoExeUri = 'https://www.nartac.com/Downloads/IISCrypto/IISCrypto.exe'

#NPCap Download URI
#$NPCapExeUri = 'https://nmap.org/npcap/dist/npcap-1.31.exe'
#NMAP Download URI
$NMAPExeUri = 'https://nmap.org/dist/nmap-7.12-setup.exe'
# Code from: https://perplexity.nl/windows-powershell/installing-or-updating-7-zip-using-powershell/
$7zipExeUri = 'https://7-zip.org/' + (Invoke-WebRequest -Uri 'https://7-zip.org/' -UseBasicParsing | Select-Object -ExpandProperty Links | Where-Object { ($_.outerHTML -match 'Download') -and ($_.href -like "a/*") -and ($_.href -like "*-x64.exe") } | Select-Object -First 1 | Select-Object -ExpandProperty href)
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
    'Add-LabMachineDefinition:Processors'      = 4
}

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress $CA01IPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -IpAddress $IIS01IPv4Address
#Client
Add-LabMachineDefinition -Name CLIENT01 -IpAddress $CLIENT01IPv4Address -OperatingSystem 'Windows Server 2019 Datacenter (Desktop Experience)'
Add-LabMachineDefinition -Name CLIENT02 -IpAddress $CLIENT02IPv4Address
#endregion

#Installing servers
Install-Lab
Checkpoint-LabVM -SnapshotName FreshInstall -All 
#Restore-LabVMSnapshot -SnapshotName FreshInstall -All -Verbose
#Start-LabVM -All -Wait

$machines = Get-LabVM
$ClientMachines = Get-LabVM -Filter {$_.Name -match "^CLIENT"}

$Job = @()
#region Installing Microsoft Edge
#Updating MS Edge on all machines (because even the latest OS build ISO doesn't necessary contain the latest MSEdge version)
#-Force is used to be sure to download the latest MS Edge version 
$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $machines -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru
#endregion

#region SCHANNEL Hardening
#Copying IISCrypto and IISCryptoCli on all machines
$IISCryptoExe = Get-LabInternetFile -Uri $IISCryptoExeUri -Path $labSources\SoftwarePackages -PassThru -Force
$null = Copy-LabFileItem -Path $IISCryptoExe.FullName -DestinationFolderPath $LocalTempFolder -ComputerName $machines -PassThru
$IISCryptoCliExe = Get-LabInternetFile -Uri $IISCryptoCliExeUri -Path $labSources\SoftwarePackages -PassThru -Force
$LocalIISCryptoCliExe = Copy-LabFileItem -Path $IISCryptoCliExe.FullName -DestinationFolderPath $LocalTempFolder -ComputerName $machines -PassThru
$LocalIISCryptoCliExe = $LocalIISCryptoCliExe | Select-Object -First 1


Invoke-LabCommand -ActivityName 'SCHANNEL Hardening to support only TLS 1.2 and strongest Cipher Suites' -ComputerName $machines -ScriptBlock {
    #Following Strict Template from IISCrypto https://www.nartac.com/Products/IISCrypto
    Start-Process -FilePath "$using:LocalIISCryptoCliExe" -ArgumentList "/template strict" -Wait
}

#Waiting for background jobs
$Job | Wait-Job | Out-Null

#Restarting the IIS Server to take the SCHANNEL hardening into consideration
Restart-LabVM -ComputerName $machines -Wait
#endregion


#region Installing Required Windows Features
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -AsJob -PassThru
$Job += Install-LabWindowsFeature -FeatureName Web-Server, Web-Asp-Net45, Web-Request-Monitor, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Cert-Auth, Web-Windows-Auth -ComputerName IIS01 -IncludeManagementTools
#endregion

#Installing and setting up DNS, DFS-R Setup & GPO Settings on DC for replicated folder on IIS Servers for shared configuration
Invoke-LabCommand -ActivityName 'DNS, DFS-R Setup & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {
    #Creating AD Users
    #User for testing authentications
    #Selecting the option to store the password using reversible encryption. : https://techexpert.tips/iis/iis-digest-authentication/
    New-ADUser -Name $Using:TestUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -AllowReversiblePasswordEncryption $True
    #Application Pool Identity
    New-ADUser -Name $Using:IISAppPoolUser -AccountPassword $Using:SecurePassword -PasswordNeverExpires $True -CannotChangePassword $True -Enabled $True
    #User for Many to One IIS Certificate Mapping
    New-ADUser -Name $using:IISClientManyToOneCertUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entries for the websites 
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
    Set-ADUser -Identity "$Using:IISAppPoolUser" -ServicePrincipalNames @{Add = "HTTP/$using:KerberosWebSiteName", "HTTP/$using:KerberosNetBiosName", "HTTP/IIS01.$using:FQDNDomainName", "HTTP/IIS01" }
    #endregion

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    #region User Enrollment Policy
    #Creating a GPO at the domain level for certificate autoenrollment
    $GPO = New-GPO -Name "Autoenrollment Policy" | New-GPLink -Target $DefaultNamingContext
    #https://www.sysadmins.lv/retired-msft-blogs/xdot509/troubleshooting-autoenrollment.aspx : 0x00000007 = Enabled, Update Certificates that user certificates templates configured, Renew expired certificates, update pending certificates, and remove revoked certificates configured
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0x00000007 
    #endregion

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0

    #Setting kerberos.contoso.com, IIS01.contoso.com and IIS02.contoso.com in the Local Intranet Zone for all servers : mandatory for Kerberos authentication       
    #1 for Intranet Zone, 2 for Trusted Sites, 3 for Internet Zone and 4 for Restricted Sites Zone.
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:KerberosWebSiteName" -ValueName http -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$using:NTLMWebSiteName" -ValueName http -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 1
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\IIS01.$using:FQDNDomainName" -ValueName http -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 1

    #Changing the start page for IE
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Internet Explorer\Main' -ValueName "Start Page" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "http://$using:AnonymousWebSiteName"

    #Bonus : To open all the available websites accross all nodes
    $SecondaryStartPages = "https://$using:BasicWebSiteName", "http://$using:KerberosWebSiteName", "http://$using:NTLMWebSiteName", "http://$using:DigestWebSiteName", "https://$using:ADClientCertWebSiteName", "https://$using:IISClientOneToOneCertWebSiteName", "https://$using:IISClientManyToOneCertWebSiteName", "https://$using:FormsWebSiteName"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Internet Explorer\Main' -ValueName "Secondary Start Pages" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value $SecondaryStartPages
    #endregion

    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #Bonus : To open all the available websites accross all nodes
    $StartPages = "http://$using:AnonymousWebSiteName", "https://$using:BasicWebSiteName", "http://$using:KerberosWebSiteName", "http://$using:NTLMWebSiteName", "http://$using:DigestWebSiteName", "https://$using:ADClientCertWebSiteName", "https://$using:IISClientOneToOneCertWebSiteName", "https://$using:IISClientManyToOneCertWebSiteName", "https://$using:FormsWebSiteName"
    $i=0
    $StartPages | ForEach-Object -Process {
        Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName ($i++) -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "$_"
    }
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
New-LabCATemplate -TemplateName $ClientAuthCertTemplateName -DisplayName 'Client Authentication' -SourceTemplateName ClientAuth -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers', 'Domain Users' -ComputerName $CertificationAuthority -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the anonymous website
#$AnonymousWebSiteSSLCert = Request-LabCertificate -Subject "CN=$AnonymousWebSiteName" -SAN $AnonymousNetBiosName, "$AnonymousWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate one to one website
$BasicWebSiteSSLCert = Request-LabCertificate -Subject "CN=$BasicWebSiteName" -SAN $BasicNetBiosName, "$BasicWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate one to one website
$IISClientOneToOneCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$IISClientOneToOneCertWebSiteName" -SAN $IISClientOneToOneCertNetBiosName, "$IISClientOneToOneCertWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate many to one website
$IISClientManyToOneCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$IISClientManyToOneCertWebSiteName" -SAN $IISClientManyToOneCertNetBiosName, "$IISClientManyToOneCertWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the IIS client certificate many to one website
$ADClientCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$ADClientCertWebSiteName" -SAN $ADClientCertNetBiosName, "$ADClientCertWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#Getting a New SSL Web Server Certificate for the forms website
$FormsWebSiteSSLCert = Request-LabCertificate -Subject "CN=$FormsWebSiteName" -SAN $FormsNetBiosName, "$FormsWebSiteName", "IIS01", "IIS01.$FQDNDomainName" -TemplateName WebServerSSL -ComputerName IIS01 -PassThru -ErrorAction Stop
#region

#Copying Web site content on all IIS servers
Copy-LabFileItem -Path $CurrentDir\contoso.com.zip -DestinationFolderPath $LocalTempFolder -ComputerName IIS01

$AdmIISClientCertContent = Invoke-LabCommand -ActivityName '1:1 IIS and AD Client Certificate Management for Administrator' -ComputerName $ClientMachines -PassThru -ScriptBlock {
    #Adding users to the Administrators group for remote connection via PowerShell for getting a certificate (next step). Will be removed later
    $null = Add-LocalGroupMember -Group "Administrators" -Member "$using:NetBiosDomainName\$Using:TestUser"
    #Adding users to the Remote Desktop Users group for RDP 
    $null = Add-LocalGroupMember -Group "Remote Desktop Users" -Member "$using:NetBiosDomainName\$Using:TestUser"
    #Invoking GPUpdate to generate the Client certificate for the User
    Start-Process -FilePath "gpupdate" -ArgumentList "/wait:-1", "/force" -Wait
    $IISClientCert = (Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {($_.Subject -match $env:USERNAME) -and ($_.EnhancedKeyUsageList.FriendlyName -eq 'Client Authentication') })
    if($IISClientCert)
    {
        [PSCustomObject] @{PSComputerName = $env:COMPUTERNAME; CertRawData = [System.Convert]::ToBase64String($IISClientCert.RawData, [System.Base64FormattingOptions]::None)}
    }
    else
    {
        $IISClientCert = Get-Certificate -Template $using:ClientAuthCertTemplateName -Url ldap: -CertStoreLocation Cert:\CurrentUser\My
        if ($IISClientCert) {
            #Getting the content of the IIS client Certificate for the IIS client certificate website (needed later in the IIS Configuration)
            [PSCustomObject] @{PSComputerName = $env:COMPUTERNAME; CertRawData = [System.Convert]::ToBase64String($IISClientCert.Certificate.RawData, [System.Base64FormattingOptions]::None)}
        }
        else
        {
            Write-Error -Message "Unable to get a Client Certificate for $(whoami) on $($env:COMPUTERNAME)"
        }
    }
}

#Prerequisites : Test User need to be promoted as local admin on client machines 
$TestUserIISClientCertContent = Invoke-LabCommand -ActivityName '1:1 IIS and AD Client Certificate Management for Test User' -ComputerName $ClientMachines -Credential $TestUserCredential -PassThru -ScriptBlock {
    #Invoking GPUpdate to generate the Client certificate for the User
    Start-Process -FilePath "gpupdate" -ArgumentList "/wait:-1", "/force" -Wait
    $IISClientCert = (Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {($_.Subject -match $env:USERNAME) -and ($_.EnhancedKeyUsageList.FriendlyName -eq 'Client Authentication') })
    if($IISClientCert)
    {
        [PSCustomObject] @{PSComputerName = $env:COMPUTERNAME; CertRawData = [System.Convert]::ToBase64String($IISClientCert.RawData, [System.Base64FormattingOptions]::None)}
    }
    else
    {
        $IISClientCert = Get-Certificate -Template $using:ClientAuthCertTemplateName -Url ldap: -CertStoreLocation Cert:\CurrentUser\My
        if ($IISClientCert) {
            #Getting the content of the IIS client Certificate for the IIS client certificate website (needed later in the IIS Configuration)
            [PSCustomObject] @{PSComputerName = $env:COMPUTERNAME; CertRawData = [System.Convert]::ToBase64String($IISClientCert.Certificate.RawData, [System.Base64FormattingOptions]::None)}
        }
        else
        {
            Write-Error -Message "Unable to get a Client Certificate for $(whoami) on $($env:COMPUTERNAME)"
        }
    }
}

#region Wireshark silent install on client machines
#Copying WireShark on client machines. Silent install is not available due to npcap. cf. https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html
$WiresharkWin64LatestExe = Get-LabInternetFile -Uri $WiresharkWin64LatestExeUri -Path $labSources\SoftwarePackages -PassThru -Force
#$Job = Install-LabSoftwarePackage -ComputerName CLIENT01 -Path $WiresharkWin64LatestExe.FullName -CommandLine "/S" -AsJob -PassThru
$LocalWiresharkWin64LatestExe = Copy-LabFileItem -Path $WiresharkWin64LatestExe.FullName -DestinationFolderPath $LocalTempFolder -ComputerName $ClientMachines -PassThru
$LocalWiresharkWin64LatestExe = $LocalWiresharkWin64LatestExe | Select-Object -First 1

#Copying NMAP on client machines. Silent install is not available due to npcap. cf. https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html
$NMAPExe = Get-LabInternetFile -Uri $NMAPExeUri -Path $labSources\SoftwarePackages -PassThru -Force
$LocalNMAPExe = Copy-LabFileItem -Path $NMAPExe.FullName -DestinationFolderPath $LocalTempFolder -ComputerName $ClientMachines -PassThru
$LocalNMAPExe = $LocalNMAPExe | Select-Object -First 1

$7zipExe = Get-LabInternetFile -Uri $7zipExeUri -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName $ClientMachines -Path $7zipExe.FullName -CommandLine "/S"

#cf. https://silentinstallhq.com/wireshark-silent-install-how-to-guide/
Invoke-LabCommand -ActivityName 'Wireshark Silent Install' -ComputerName $ClientMachines -ScriptBlock {
    #$LocalTempFolder = $(Split-Path -Path $using:LocalNMAPExe -Parent)
    #WireShark Silent install
    Start-Process -FilePath $(Join-Path -Path $Env:ProgramFiles -ChildPath '7-Zip\7z.exe') -ArgumentList "x", "$using:LocalNMAPExe", "-o$using:LocalTempFolder", "-y" -Wait
    Start-Process -FilePath $(Join-Path -Path $using:LocalTempFolder -ChildPath "winpcap-nmap-4.13.exe")  -ArgumentList "/S" -Wait
    Start-Process -FilePath $using:LocalWiresharkWin64LatestExe -ArgumentList "/S" -Wait
}

#Prerequisites : Test User need to be promoted as local admin on client machines 
Invoke-LabCommand -ActivityName 'Configuration for TLS Key log file' -ComputerName $ClientMachines -Credential $TestUserCredential -ScriptBlock {
    #WireShark TLS Key Log file Configuration
    $WireSharkPreferencesFile = Join-Path -Path $env:APPDATA -ChildPath 'Wireshark\preferences'
    $TLSKeyLogFile = Join-Path -Path $env:USERPROFILE -ChildPath 'AppData\Local\WireShark\ssl-keys.log'
    $null = New-Item -Path $TLSKeyLogFile -ItemType File -Force

    if (Test-Path $WireSharkPreferencesFile) {
        $Content = Get-Content -Path $WireSharkPreferencesFile
        $NewContent = $Content -replace '#?tls.keylog_file:\s*(.*)$', "tls.keylog_file: $TLSKeyLogFile"
        $NewContent | Set-Content -Path $WireSharkPreferencesFile
    }
    else {
        $null = New-Item -Path $WireSharkPreferencesFile -ItemType File -Force
        $Content = "tls.keylog_file: $TLSKeyLogFile"
        $Content | Set-Content -Path $WireSharkPreferencesFile -Force
    }
}
#endregion

#Waiting for background jobs
$Job | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName BeforeIISSetup -All 
#Restore-LabVMSnapshot -SnapshotName BeforeIISSetup -All -Verbose
#Start-LabVM -All -Wait

Invoke-LabCommand -ActivityName 'Unzipping Web Site Content and Setting up the IIS websites' -ComputerName IIS01 -ScriptBlock {    
    #Renaming the NIC 
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Ethernet' -PassThru
    #Creating directory tree for hosting web sites
    $null = New-Item -Path C:\WebSites -ItemType Directory -Force
    #applying the required ACL (via PowerShell Copy and Paste)
    Get-Acl C:\inetpub\wwwroot | Set-Acl C:\WebSites
    
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
    Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/defaultDocument/files" -name "." -AtElement @{value = 'default.aspx' } -Force
    Add-WebConfiguration -Filter 'system.webserver/defaultdocument/files' -atIndex 0 -Value @{ value = 'default.aspx' } -Force
    #endregion 

    #region : Anonymous website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:AnonymousIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:AnonymousWebSiteName" -Force
    #Creating a dedicated web site
    New-WebAppPool -Name "$using:AnonymousWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebSite -Name "$using:AnonymousWebSiteName" -Port 80 -IPAddress $using:AnonymousIPv4Address -PhysicalPath "C:\WebSites\$using:AnonymousWebSiteName" -ApplicationPool "$using:AnonymousWebSiteName" -Force

    #Enabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:AnonymousWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #endregion

    #region : Basic website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:BasicIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:BasicWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:BasicWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:BasicWebSiteName" -Port 443 -IPAddress $using:BasicIPv4Address -PhysicalPath "C:\WebSites\$using:BasicWebSiteName" -ApplicationPool "$using:BasicWebSiteName" -Ssl -SslFlags 0 -Force
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
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:BasicWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'

    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    #Custom Log Fields for TLS & Certificates
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:BasicWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:BasicWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:BasicWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:BasicWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
    #endregion
        
    #region : Kerberos website management
    #Assigning dedicated IP address
    #Unzipping site content to dedicated folders
    #Creating a dedicated web site
    #Creating a dedicated application pool
    New-NetIPAddress –IPAddress $using:KerberosIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:KerberosWebSiteName" -Force
    New-WebAppPool -Name "$using:KerberosWebSiteName" -Force
    New-WebSite -Name "$using:KerberosWebSiteName" -Port 80 -IPAddress $using:KerberosIPv4Address -PhysicalPath "C:\WebSites\$using:KerberosWebSiteName" -ApplicationPool "$using:KerberosWebSiteName" -Force

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
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:KerberosWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #endregion

    #region : NTLM website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:NTLMIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:NTLMWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:NTLMWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:NTLMWebSiteName" -Port 80 -IPAddress $using:NTLMIPv4Address -PhysicalPath "C:\WebSites\$using:NTLMWebSiteName" -ApplicationPool "$using:NTLMWebSiteName" -Force

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
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:NTLMWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #endregion

    #region : Digest website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:DigestIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:DigestWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:DigestWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:DigestWebSiteName" -Port 80 -IPAddress $using:DigestIPv4Address -PhysicalPath "C:\WebSites\$using:DigestWebSiteName" -ApplicationPool "$using:DigestWebSiteName" -Force

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
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:DigestWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #endregion

    #region : AD Client Certificate website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:ADClientCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:ADClientCertWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:ADClientCertWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:ADClientCertWebSiteName" -Port 443 -IPAddress $using:ADClientCertIPv4Address -PhysicalPath "C:\WebSites\$using:ADClientCertWebSiteName" -ApplicationPool "$using:ADClientCertWebSiteName" -Ssl -SslFlags 0 -Force

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
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert,SslRequireCert"
    
    #Removing Default Binding
    Get-WebBinding -Port 80 -Name "$using:ADClientCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the AD Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/security/authentication/clientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:ADClientCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:ADClientCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    #Custom Log Fields for TLS & Certificates
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-subject';sourceName='CERT_SUBJECT';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:ADClientCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-serialnumber';sourceName='CERT_SERIALNUMBER';sourceType='ServerVariable'}
    #endregion

    #region : IIS Client Certificate website management 1:1
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:IISClientOneToOneCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:IISClientOneToOneCertWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:IISClientOneToOneCertWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:IISClientOneToOneCertWebSiteName" -Port 443 -IPAddress $using:IISClientOneToOneCertIPv4Address -PhysicalPath "C:\WebSites\$using:IISClientOneToOneCertWebSiteName" -ApplicationPool "$using:IISClientOneToOneCertWebSiteName" -Ssl -SslFlags 0 -Force

    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:IISClientOneToOneCertIPv4Address!443!$using:IISClientOneToOneCertWebSiteName" -Thumbprint $($using:IISClientOneToOneCertWebSiteSSLCert).Thumbprint -sslFlags 0
    #SSL + Negotiate Client Certificate 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert,SslRequireCert"
    
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:IISClientOneToOneCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the One to One IIS Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "oneToOneCertificateMappingsEnabled" -value "True"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "manyToOneCertificateMappingsEnabled" -value "False"
    
    #1 Certificate per user and per client computer for the Administrator
    $using:AdmIISClientCertContent | ForEach-Object -Process {
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/oneToOneMappings" -name "." -value @{userName = "$Using:NetBiosDomainName\$Using:Logon"; password = "$Using:ClearTextPassword"; certificate = $_.CertRawData }
    }

    #1 Certificate per user and per client computer for the test user
    $using:TestUserIISClientCertContent | ForEach-Object -Process {
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/oneToOneMappings" -name "." -value @{userName = "$Using:NetBiosDomainName\$Using:TestUser"; password = "$Using:ClearTextPassword"; certificate = $_.CertRawData }
    }

    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:IISClientOneToOneCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientOneToOneCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'

    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    #Custom Log Fields for TLS & Certificates
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-subject';sourceName='CERT_SUBJECT';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientOneToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-serialnumber';sourceName='CERT_SERIALNUMBER';sourceType='ServerVariable'}
    #endregion

    #region : IIS Client Certificate website management N:1
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:IISClientManyToOneCertIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:IISClientManyToOneCertWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:IISClientManyToOneCertWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:IISClientManyToOneCertWebSiteName" -Port 443 -IPAddress $using:IISClientManyToOneCertIPv4Address -PhysicalPath "C:\WebSites\$using:IISClientManyToOneCertWebSiteName" -ApplicationPool "$using:IISClientManyToOneCertWebSiteName" -Ssl -SslFlags 0 -Force

    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:IISClientManyToOneCertIPv4Address!443!$using:IISClientManyToOneCertWebSiteName" -Thumbprint $($using:IISClientManyToOneCertWebSiteSSLCert).Thumbprint -sslFlags 0

    #SSL + Negotiate Client Certificate 
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl,SslNegotiateCert,SslRequireCert"
    
    #Removing Default Binding
    #Get-WebBinding -Port 80 -Name "$using:IISClientManyToOneCertWebSiteName" | Remove-WebBinding
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'

    #Enabling the One to One IIS Client Certificate authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -name 'enabled' -value 'True'
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "oneToOneCertificateMappingsEnabled" -value "False"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name "manyToOneCertificateMappingsEnabled" -value "True"
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings" -name "." -value @{name = "$Using:IISClientManyToOneCertUser"; description = "$Using:NetBiosDomainName\$Using:IISClientManyToOneCertUser"; userName = "$Using:NetBiosDomainName\$Using:IISClientManyToOneCertUser"; password = "$Using:ClearTextPassword" }
    #Optional : Adding rules that will give you an option to add multiple patterns for matching based on certificate properties.
    #Only client certificates coming from the CA are authorized
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings/add[@name='$Using:IISClientManyToOneCertUser']/rules" -name "." -value @{certificateField = 'Issuer'; certificateSubField = 'CN'; matchCriteria = "$($using:CertificationAuthority.CaName)" }
    
    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:IISClientManyToOneCertWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:IISClientManyToOneCertWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    #Custom Log Fields for TLS & Certificates
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-subject';sourceName='CERT_SUBJECT';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:IISClientManyToOneCertWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='cert-serialnumber';sourceName='CERT_SERIALNUMBER';sourceType='ServerVariable'}
    #endregion

    #region : Forms website management
    #Assigning dedicated IP address
    New-NetIPAddress –IPAddress $using:FormsIPv4Address –PrefixLength 24 –InterfaceAlias "Ethernet"
    #Unzipping site content to dedicated folders
    Expand-Archive $(Join-Path -Path $using:LocalTempFolder -ChildPath "contoso.com.zip") -DestinationPath "C:\WebSites\$using:FormsWebSiteName" -Force
    #Creating a dedicated application pool
    New-WebAppPool -Name "$using:FormsWebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$using:FormsWebSiteName" -Port 443 -IPAddress $using:FormsIPv4Address -PhysicalPath "C:\WebSites\$using:FormsWebSiteName" -ApplicationPool "$using:FormsWebSiteName" -Ssl -SslFlags 0 -Force
    #Binding Management for SSL (Neither SNI nor CCS)
    #0: Regular certificate in Windows certificate storage.
    #1: SNI certificate.
    #2: Central certificate store.
    #3: SNI certificate in central certificate store.
    New-Item -Path "IIS:\SslBindings\$using:FormsIPv4Address!443!$using:FormsWebSiteName" -Thumbprint $($using:FormsWebSiteSSLCert).Thumbprint -sslFlags 0
    #Require SSL
    #Get-IISConfigSection -SectionPath 'system.webServer/security/access' -Location "$using:FormsWebSiteName" | Set-IISConfigAttributeValue -AttributeName sslFlags -AttributeValue Ssl
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$using:FormsWebSiteName" -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl"
    
    #Enabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$using:FormsWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'True'
    #Enabling the Forms authentication
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication" -name "mode" -value "Forms"

    #Setting up the Forms authentication
    #Adding to authorized users
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "system.web/authentication/forms/credentials" -name "." -value @{name = "$using:Logon"; password = "$using:ClearTextPassword" }
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "system.web/authentication/forms/credentials" -name "." -value @{name = "$Using:TestUser"; password = "$using:ClearTextPassword" }
    #Setting up clear text password
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms/credentials" -name "passwordFormat" -value "Clear"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms" -name "defaultUrl" -value "default.aspx"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms" -name "loginUrl" -value "login.aspx"
    Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName"  -filter "system.web/authentication/forms" -name "requireSSL" -value "True"
    
    #Denying access to anonymous users
    #Local (web.config)
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "/system.web/authorization" -Name "." -value @{users = '?' } -Type "deny"
    #Setting up the client validation mode for the application. 
    Add-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter "/appSettings" -name "." -value @{key = 'ValidationSettings:UnobtrusiveValidationMode'; value = 'None' }

    #Enabling ASP.Net Impersonation (local web.config)
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$using:FormsWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'

    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$using:FormsWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'

    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    #Custom Log Fields for TLS & Certificates
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:FormsWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:FormsWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:FormsWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='$using:FormsWebSiteName']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
    #endregion
}

$AdmIISClientCertContent = Invoke-LabCommand -ActivityName 'Removing Test User from Administrators group' -ComputerName $ClientMachines -PassThru -ScriptBlock {
    #removing test users from the Administrators group
    Remove-LocalGroupMember -Group "Administrators" -Member "$using:NetBiosDomainName\$Using:TestUser"
}

#Waiting for background jobs
$Job | Wait-Job | Out-Null

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All 

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript