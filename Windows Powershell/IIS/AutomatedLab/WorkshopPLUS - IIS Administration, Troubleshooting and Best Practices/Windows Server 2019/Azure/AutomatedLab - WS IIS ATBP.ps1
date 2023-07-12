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
#$ErrorActionPreference = 'Stop'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$10YearsFromNow = $Now.AddYears(10)
$WebServerCertValidityPeriod = New-TimeSpan -Start $Now -End $10YearsFromNow
$Logon = 'IISAdmin'
$ClearTextPassword = 'Im@JediLikeMyFatherBe4Me'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$LabFilesZipPath = Join-Path -Path $CurrentDir -ChildPath "LabFiles.zip"
$DemoFilesZipPath = Join-Path -Path $CurrentDir -ChildPath "Demos.zip"
$MusicStoreAppPoolUsr = 'MusicStoreAppPoolUsr'
$WDeployConfigWriter = 'WDeployConfigWriter'
$WebDeploySqlUsr = 'WebDeploySqlUsr'
$CentralSSLUser = 'CentralSSLUser'

$NetworkID = '192.168.0.0/16' 
$DC01IPv4Address = '192.168.0.101'
$SQL01IPv4Address = '192.168.0.111'
$IIS01IPv4Address = '192.168.0.201'
$IIS02IPv4Address = '192.168.0.202'

$SecurityCCSSNINetBiosName = 'SecurityCCSSNI'
$SecurityCCSSNIWebSiteName = "$SecurityCCSSNINetBiosName.$FQDNDomainName"
$SecurityCCSSNIIPv4Address = '192.168.0.103'

$SecurityCCSNoSNINetBiosName = 'SecurityCCSNoSNI'
$SecurityCCSNoSNIWebSiteName = "$SecurityCCSNoSNINetBiosName.$FQDNDomainName"
$SecurityCCSNoSNIIPv4Address = '192.168.0.104'

$SecurityCCSWildcartCertNetBiosName = 'securityCCSWildcardCert'
$SecurityCCSWildcartCertWebSiteName = "$SecurityCCSWildcartCertNetBiosName.$FQDNDomainName"
$SecurityCCSWildcartCertIPv4Address = '192.168.0.105'

$SecurityCCSSANCert0NetBiosName = 'SecurityCCSSANCert0'
$SecurityCCSSANCert0WebSiteName = "$SecurityCCSSANCert0NetBiosName.$FQDNDomainName"
$SecurityCCSSANCert0IPv4Address = '192.168.0.106'

$SecurityCCSSANCert1NetBiosName = 'SecurityCCSSANCert1'
$SecurityCCSSANCert1WebSiteName = "$SecurityCCSSANCert1NetBiosName.$FQDNDomainName"
$SecurityCCSSANCert1IPv4Address = '192.168.0.107'

$SecurityCCSSANCert2NetBiosName = 'SecurityCCSSANCert2'
$SecurityCCSSANCert2WebSiteName = "$SecurityCCSSANCert2NetBiosName.$FQDNDomainName"
$SecurityCCSSANCert2IPv4Address = '192.168.0.108'

$MSEdgeEntUri                   = "http://go.microsoft.com/fwlink/?LinkID=2093437"

$LabName = 'AzureIISWSPlus2019'

$azureDefaultLocation = 'France Central' 
#endregion

#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

Add-LabAzureSubscription -DefaultLocationName $azureDefaultLocation

#create an empty lab template and define where the lab XML files and the VMs will be stored
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine Azure

#make the network definition
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace $NetworkID

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
    #'Add-LabMachineDefinition:Processors'      = 4
}

$IIS01NetAdapter = @()
$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $IIS01IPv4Address
#$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

$SQL01NetAdapter = @()
$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQL01IPv4Address
#Adding an Internet Connection on the DC (Required for the SQL Setup via AutomatedLab)
#$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

#SQL Server
$SQLServer2019Role = Get-LabMachineRoleDefinition -Role SQLServer2019 -Properties @{ Features = 'SQL,Tools' }
Add-LabIsoImageDefinition -Name SQLServer2019 -Path $labSources\ISOs\en_sql_server_2019_standard_x64_dvd_cdcd4b9f.iso

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot -IpAddress $DC01IPv4Address
#SQL Server
Add-LabMachineDefinition -Name SQL01 -Roles $SQLServer2019Role -NetworkAdapter $SQL01NetAdapter #-Memory 2GB -Processors 2
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -NetworkAdapter $IIS01NetAdapter
#IIS front-end server
Add-LabMachineDefinition -Name IIS02 -IpAddress $IIS02IPv4Address
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
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled' -Value 0 -Force
    Rundll32 iesetup.dll, IEHardenLMSettings
    Rundll32 iesetup.dll, IEHardenUser
    Rundll32 iesetup.dll, IEHardenAdmin
    Remove-Item -Path $AdminKey -Force
    Remove-Item -Path $UserKey -Force
    #Setting the Keyboard to French
    #Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp (used in the Security lab)
    Get-NetAdapter | Rename-NetAdapter -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS & AD Setup on DC' -ComputerName DC01 -ScriptBlock {

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #DNS Host entries for the websites 
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSSNINetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSSNIIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSNoSNINetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSNoSNIIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSWildcartCertNetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSWildcartCertIPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSSANCert0NetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSSANCert0IPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSSANCert1NetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSSANCert1IPv4Address" -CreatePtr
    Add-DnsServerResourceRecordA -Name "$using:SecurityCCSSANCert2NetBiosName" -ZoneName "$using:FQDNDomainName" -IPv4Address "$using:SecurityCCSSANCert2IPv4Address" -CreatePtr

    #Creating AD Users
    New-ADUser -Name $Using:MusicStoreAppPoolUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    New-ADUser -Name $Using:WDeployConfigWriter -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    New-ADUser -Name $Using:WebDeploySqlUsr -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    New-ADUser -Name $Using:CentralSSLUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
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


#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 10-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer10Years -DisplayName 'WebServer10Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers'-ComputerName $CertificationAuthority -ErrorAction Stop

<#
#Getting a New SSL Web Server Certificate for the basic website
$SecurityCCSSNIWebSiteSSLCert = Request-LabCertificate -Subject "CN=$SecurityCCSSNIWebSiteName" -SAN $SecurityCCSSNINetBiosName, "$SecurityCCSSNIWebSiteName" -TemplateName WebServer10Years -ComputerName IIS01 -PassThru -ErrorAction Stop
$SecurityCCSNoSNIWebSiteSSLCert = Request-LabCertificate -Subject "CN=$SecurityCCSNoSNIWebSiteName" -SAN $SecurityCCSNoSNINetBiosName, "$SecurityCCSNoSNIWebSiteName" -TemplateName WebServer10Years -ComputerName IIS01 -PassThru -ErrorAction Stop
$SecurityCCSWildcartCertWebSiteSSLCert = Request-LabCertificate -Subject "CN=$SecurityCCSWildcartCertWebSiteName" -SAN $SecurityCCSWildcartCertNetBiosName, "$SecurityCCSWildcartCertWebSiteName" -TemplateName WebServer10Years -ComputerName IIS01 -PassThru -ErrorAction Stop
$SecurityCCSSANCert0WebSiteSSLCert = Request-LabCertificate -Subject "CN=$SecurityCCSSANCert0WebSiteName" -SAN $SecurityCCSSANCert0NetBiosName, "$SecurityCCSSANCert0WebSiteName", "$SecurityCCSSANCert1WebSiteName", "$SecurityCCSSANCert2WebSiteName" -TemplateName WebServer10Years -ComputerName IIS01 -PassThru -ErrorAction Stop

Invoke-LabCommand -ActivityName 'Exporting the Web Server Certificate for the future "Central Certificate Store" directory' -ComputerName IIS01 -ScriptBlock {

    #Creating replicated folder for Central Certificate Store
    New-Item -Path C:\CentralCertificateStore -ItemType Directory -Force

    $WebServer10YearsCert = Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "*.$($using:FQDNDomainName)" -SSLServerAuthentication | Where-Object -FilterScript {
        $_.hasPrivateKey 
    }
    foreach ($CurrentWebServer10YearsCert in $WebServer10YearsCert)
    {
        $Subject = $CurrentWebServer10YearsCert.Subject -replace "^CN=" -replace "\*", "_"
        $WebServer10YearsCert | Export-PfxCertificate -FilePath "C:\CentralCertificateStore\$Subject.pfx" -Password $Using:SecurePassword
        #$WebServer10YearsCert | Remove-Item -Force
    }
}
#>

# Hastable for getting the ISO Path for every IIS Server (needed for .Net 2.0 setup)
$IISServers = Get-LabVM | Where-Object -FilterScript { $_.Name -like "*IIS*" }
#$IsoPathHashTable = $IISServers | Select-Object -Property Name, @{Name = "IsoPath"; Expression = { $_.OperatingSystem.IsoPath } } | Group-Object -Property Name -AsHashTable -AsString

Copy-LabFileItem -Path $DemoFilesZipPath -ComputerName $IISServers
Copy-LabFileItem -Path $LabFilesZipPath -ComputerName $IISServers
foreach ($CurrentIISServerName in $IISServers.Name) {
    Invoke-LabCommand -ActivityName 'Copying lab and demo files locally' -ComputerName $CurrentIISServerName -ScriptBlock {
        $Sxs = New-Item -Path "C:\Sources\Sxs" -ItemType Directory -Force

        $null = New-Item -Path "C:\Temp" -ItemType Directory -Force
        #Lab files
        $LocalLabFilesZipPath = $(Join-Path -Path $env:SystemDrive -ChildPath $(Split-Path -Path $using:LabFilesZipPath -Leaf ))
        Expand-Archive $LocalLabFilesZipPath  -DestinationPath "$env:SystemDrive\" -Force
        Remove-Item $LocalLabFilesZipPath -Force

        #Demo files
        $LocalDemoFilesZipPath = $(Join-Path -Path $env:SystemDrive -ChildPath $(Split-Path -Path $using:DemoFilesZipPath -Leaf ))
        Expand-Archive $LocalDemoFilesZipPath  -DestinationPath "$env:SystemDrive\" -Force
        Remove-Item $LocalDemoFilesZipPath -Force
    }
}

$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName $machines -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob

Invoke-LabCommand -ActivityName 'Cleanup on SQL Server' -ComputerName SQL01 -ScriptBlock {
    Remove-Item -Path "C:\vcredist_x*.*" -Force
    Remove-Item -Path "C:\SSMS-Setup-ENU.exe" -Force
}


Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName IIS01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName 'FullInstall' -All

<#
Invoke-LabCommand -ActivityName 'Demos Setup' -ComputerName IIS01 -ScriptBlock {
    Start-Process -FilePath "$env:ComSpec" -ArgumentList "/c C:\Demos\Source\setup_script.bat > C:\Demos\Source\setup_script.log" -Wait
} 
Checkpoint-LabVM -SnapshotName 'Demos' -All
#>

Show-LabDeploymentSummary -Detailed

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript