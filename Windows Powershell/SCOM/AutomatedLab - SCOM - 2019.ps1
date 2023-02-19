<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment. THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free
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
<#
Based on 
- https://rlevchenko.com/2018/01/16/automate-scom-2016-installation-with-powershell/
- https://thesystemcenterblog.com/2019/07/08/installing-scom-2019-from-the-command-line/
- https://docs.microsoft.com/en-us/system-center/scom/deploy-install-reporting-server?view=sc-om-2019
- https://redmondmag.com/articles/2020/10/26/sql-server-reporting-for-scom.aspx
- https://blog.aelterman.com/2018/01/01/silent-installation-and-configuration-for-sql-server-2017-reporting-services/
- https://blog.aelterman.com/2018/01/03/complete-automated-configuration-of-sql-server-2017-reporting-services/
- https://www.prajwaldesai.com/install-scom-agent-using-command-line/
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
Import-Module -Name AutomatedLab
try {while (Stop-Transcript) {}} catch {}
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
#$VerbosePreference = 'Continue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

# OU name for placing accounts and groups (Service Accounts,for example)
$OUName = 'Service Accounts'
#Optional : Without a valid license key you will get a 180-day trial period.
$SCOMLicense = '... Put your licence Key here ...'
$SCOMAccessAccount = 'SCOM-Access-Account'
$SCOMDataWareHouseWriter = 'SCOM-DWH-Writer'
$SCOMDataWareHouseReader = 'SCOM-DWH-Reader'
$SCOMServerAction = 'SCOM-Server-Action'
$SCOMAdmins = 'SCOM-Admins'
# SCOM management group name (AutomatedLab, for example)
$SCOMMgmtGroup = 'AutomatedLab'


$SQLSVC = 'SQLSVC'
$SQLSSRS = 'SQLSSRS'
# User Name with admin rights on SQL Server (SQLUser,for example)
$SQLUser = 'SQLUser'
$SCOMSetupLocalFolder = "C:\System Center Operations Manager 2019"       

#For Microsoft.Windows.Server.2016.Discovery and Microsoft.Windows.Server.Library
#$SCOMWSManagementPackURI = 'https://download.microsoft.com/download/f/7/b/f7b960c9-7392-4c5a-bab4-efbb8a66ec2a/SC%20Management%20Pack%20for%20Windows%20Server%20Operating%20System.msi'
$SCOMWS2016andWS2019ManagementPackURI = 'https://download.microsoft.com/download/D/8/E/D8EB49E9-744E-4F83-B62C-CBBA2B72927C/Microsoft%20System%20Center%20MP%20for%20WS%202016%20and%20above.msi'
#More details on http://mpwiki.viacode.com/default.aspx?g=posts&t=218560
$SCOMIISManagementPackURI = 'https://download.microsoft.com/download/4/9/A/49A9DD6B-3ECC-46DD-9115-9DB60C052DA7/Microsoft%20System%20Center%20MP%20for%20IIS%202016%20and%201709%20Plus.msi'
$ReportViewer2015RuntimeURI = 'https://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi'
$SystemCLRTypesForSQLServer2014x64URI = 'https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi'
$SQLServer2019ReportingServicesURI = 'https://download.microsoft.com/download/1/a/a/1aaa9177-3578-4931-b8f3-373b24f63342/SQLServerReportingServices.exe'
$SCOMNETAPMManagementPackURI = 'https://download.microsoft.com/download/C/C/2/CC264378-4ADE-4FC3-A6BB-7257CF7D6640/Package/Microsoft.SystemCenter.ApplicationInsights.msi'

#Latest SQL CU : CU18 when this script was released in January 2023
#$SQLServer2019LatestCUURI = 'https://download.microsoft.com/download/6/e/7/6e72dddf-dfa4-4889-bc3d-e5d3a0fd11ce/SQLServer2019-KB5004524-x64.exe'
#To find dynamically the Latest SQL CU
$SQLServer2019LatestCUURI = ($(Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/confirmation.aspx?id=100809 -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "click here to download manually"}).href

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$SQL01IPv4Address = '10.0.0.11'
$IIS01IPv4Address = '10.0.0.21'
$SCOM01IPv4Address = '10.0.0.31'

$LabName = 'SCOM2019'
#endregion

Start-Service -Name ShellHWDetection
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
     'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2019 Datacenter (Desktop Experience)'
     #'Add-LabMachineDefinition:Processors'     = 4
}

$IIS01NetAdapter = @()
$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $IIS01IPv4Address -InterfaceName Corp
$IIS01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQL01NetAdapter = @()
$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SQL01IPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for the SQL Setup via AutomatedLab)
$SQL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SCOM01NetAdapter = @()
$SCOM01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $SCOM01IPv4Address -InterfaceName Corp
#Adding an Internet Connection on the DC (Required for the SQL Setup via AutomatedLab)
$SCOM01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$SQLServer2019Role = Get-LabMachineRoleDefinition -Role SQLServer2019 -Properties @{ Features = 'SQL,Tools' }
Add-LabIsoImageDefinition -Name SQLServer2019 -Path $labSources\ISOs\en_sql_server_2019_enterprise_x64_dvd_5e1ecc6b.iso

#region server definitions
#Root Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#SCOM server
Add-LabMachineDefinition -Name SCOM01 -NetworkAdapter $SCOM01NetAdapter -Memory 8GB -MinMemory 4GB -MaxMemory 8GB -Processors 4
#SQL Server
Add-LabMachineDefinition -Name SQL01 -Roles $SQLServer2019Role -NetworkAdapter $SQL01NetAdapter -Memory 4GB -MinMemory 2GB -MaxMemory 4GB -Processors 2
#IIS front-end server
Add-LabMachineDefinition -Name IIS01 -NetworkAdapter $IIS01NetAdapter
#endregion

#Installing servers
Install-Lab
Restart-LabVM -ComputerName SQL01 -Wait -ProgressIndicator 10
Checkpoint-LabVM -SnapshotName FreshInstall -All

#Downloading SQL Server 2019 CU8 (or later)
$SQLServer2019LatestCU = Get-LabInternetFile -Uri $SQLServer2019LatestCUURI -Path $labSources\SoftwarePackages -PassThru -Force
#Installing SQL Server 2019 CU8 (or later)
Install-LabSoftwarePackage -ComputerName SQL01 -Path $SQLServer2019LatestCU.FullName -CommandLine " /QUIET /IACCEPTSQLSERVERLICENSETERMS /ACTION=PATCH /ALLINSTANCES" #-AsJob
#Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

#region Installing Required Windows Features
$AllLabVMs = Get-LabVM
$Job = @()
$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $AllLabVMs -IncludeManagementTools -AsJob -PassThru
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $AllLabVMs -ScriptBlock {
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

     #Renaming the main NIC adapter to Corp
     Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
     Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
     Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS & AD Setup on DC' -ComputerName DC01 -ScriptBlock {

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

    $ADDistinguishedName=(Get-ADDomain).DistinguishedName

    #Creating AD OU
    $ADOrganizationalUnit = New-ADOrganizationalUnit -Name $using:OUName -Path $ADDistinguishedName -Passthru

    #Creating AD Users
    New-ADUser -Name $using:SQLUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true
    New-ADUser -Name $using:SCOMAccessAccount -SamAccountName $using:SCOMAccessAccount -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    New-ADUser -Name $using:SCOMDataWareHouseReader -SamAccountName $using:SCOMDataWareHouseReader -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    New-ADUser -Name $using:SCOMDataWareHouseWriter -SamAccountName $using:SCOMDataWareHouseWriter -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    New-ADUser -Name $using:SCOMServerAction -SamAccountName $using:SCOMServerAction -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    New-ADGroup -Name $using:SCOMAdmins -GroupScope Global -GroupCategory Security -Path $ADOrganizationalUnit.DistinguishedName
    Add-ADGroupMember $using:SCOMAdmins $using:SCOMAccessAccount,$using:SCOMDataWareHouseReader,$using:SCOMDataWareHouseWriter,$using:SCOMServerAction
    #SQL Server service accounts (SQLSSRS is a service reporting services account)
    New-ADUser -Name $using:SQLSVC -SamAccountName $using:SQLSVC -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    New-ADUser -Name $using:SQLSSRS -SamAccountName $using:SQLSSRS -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -Enabled $true -Path $ADOrganizationalUnit.DistinguishedName
    Write-Verbose "The service Accounts and SCOM-Admins group have been added to OU=$using:OUName,$DistinguishedName"
}


Invoke-LabCommand -ActivityName 'Adding the SCOM Admins AD Group to the local Administrators Group' -ComputerName SCOM01, SQL01, IIS01 -ScriptBlock {
    Add-LocalGroupMember -Member $using:NetBiosDomainName\$using:SCOMAdmins -Group Administrators
}

Invoke-LabCommand -ActivityName 'Installing IIS, ASP and ASP.NET 4.5+' -ComputerName IIS01 -ScriptBlock {
    Install-WindowsFeature Web-Server, Web-Asp, Web-Asp-Net45 -IncludeManagementTools
    Import-Module -Name WebAdministration
    $WebSiteName = 'www.contoso.com'
    #Creating a dedicated application pool
    New-WebAppPool -Name "$WebSiteName" -Force
    #Creating a dedicated web site
    New-WebSite -Name "$WebSiteName" -Port 81 -PhysicalPath "$env:SystemDrive\inetpub\wwwroot" -ApplicationPool "$WebSiteName" -Force
}

Invoke-LabCommand -ActivityName 'Adding some users to the SQL sysadmin group' -ComputerName SQL01 -ScriptBlock {

    #SQL Server Management Studio (SSMS), beginning with version 17.0, doesn't install either PowerShell module. To use PowerShell with SSMS, install the SqlServer module from the PowerShell Gallery.
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name SqlServer -Force -AllowClobber
    Import-Module -Name SQLServer

    $SQLLogin = Add-SqlLogin -ServerInstance $Env:COMPUTERNAME -LoginName "$using:NetBiosDomainName\$using:SQLUser" -LoginType "WindowsUser" -Enable
    $SQLLogin.AddToRole("sysadmin")
    
    #Setting up some firewall rules
    Set-NetFirewallRule -Name WMI-WINMGMT-In-TCP -Enabled True
    New-NetFirewallRule -Name "SQL DB" -DisplayName "SQL Database" -Profile Domain -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow
    New-NetFirewallRule -Name "SQL Server Admin Connection" -DisplayName "SQL Server Admin Connection" -Profile Domain -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow
    New-NetFirewallRule -Name "SQL Browser" -DisplayName "SQL Browser" -Profile Domain -Direction Inbound -LocalPort 1434 -Protocol UDP -Action Allow
    New-NetFirewallRule -Name "SQL SRRS (HTTP)" -DisplayName "SQL SRRS (HTTP)" -Profile Domain -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
    New-NetFirewallRule -Name "SQL SRRS (SSL)" -DisplayName "SQL SRRS (SSL)" -Profile Domain -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
    New-NetFirewallRule -Name "SQL Server 445" -DisplayName "SQL Server 445" -Profile Domain -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
    New-NetFirewallRule -Name "SQL Server 135" -DisplayName "SQL Server 135" -Profile Domain -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
    Write-Verbose "The SQL Server $env:COMPUTERNAME has been configured"

    #Starting SQL Server Agent Service (Prerequisite)
    Set-Service -Name SQLSERVERAGENT -StartupType Automatic -PassThru  | Start-Service
}

# Hastable for getting the ISO Path for every VM (needed for .Net 2.0 setup)
$SCOMServers = Get-LabVM | Where-Object -FilterScript { $_.Name -like "*SCOM*" }
$IsoPathHashTable = $SCOMServers | Select-Object -Property Name, @{Name = "IsoPath"; Expression = { $_.OperatingSystem.IsoPath } } | Group-Object -Property Name -AsHashTable -AsString
foreach ($CurrentSCOMServer in $SCOMServers.Name) {
    $Drive = Mount-LabIsoImage -ComputerName $CurrentSCOMServer -IsoPath $IsoPathHashTable[$CurrentSCOMServer].IsoPath -PassThru
    Invoke-LabCommand -ActivityName 'Copying .Net 2.0 cab' -ComputerName $CurrentSCOMServer -ScriptBlock {
        $Sxs = New-Item -Path "C:\Sources\Sxs" -ItemType Directory -Force
        Copy-Item -Path "$($using:Drive.DriveLetter)\sources\sxs\*" -Destination $Sxs -Recurse -Force
    }
    Dismount-LabIsoImage -ComputerName $CurrentSCOMServer
}

#Region Prerequisites for SCOM
$SystemCLRTypesForSQLServer2014x64 = Get-LabInternetFile -Uri $SystemCLRTypesForSQLServer2014x64URI -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName SCOM01 -Path $SystemCLRTypesForSQLServer2014x64.FullName -CommandLine "/qn  /L* $(Join-Path -Path $env:SystemDrive -ChildPath $($SystemCLRTypesForSQLServer2014x64.FileName+".log")) /norestart ALLUSERS=2"

$ReportViewer2015Runtime = Get-LabInternetFile -Uri $ReportViewer2015RuntimeURI -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName SCOM01 -Path $ReportViewer2015Runtime.FullName -CommandLine "/qn /L* $(Join-Path -Path $env:SystemDrive -ChildPath $($ReportViewer2015Runtime.FileName+".log")) /norestart ALLUSERS=2"
#endregion

#Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

$ISOPath = Join-Path -Path $(Get-LabSourcesLocation) -ChildPath "ISOs"
$SCOMISOPath = Join-Path -Path $ISOPath -ChildPath "mu_system_center_operations_manager_2019_x64_dvd_b3488f5c.iso"
$Drive = Mount-LabIsoImage -ComputerName SCOM01 -IsoPath $SCOMISOPath -PassThru

Invoke-LabCommand -ActivityName 'Installing the Operations Manager Management server, Operations Console and Operations Manager Web Console on SCOM Server' -ComputerName SCOM01 -ScriptBlock {
    Install-WindowsFeature Web-Server, Web-Request-Monitor, Web-Asp-Net, Web-Asp-Net45, Web-Windows-Auth, Web-Metabase, NET-WCF-HTTP-Activation45 -IncludeManagementTools -Source "C:\Sources\Sxs"
    Write-Verbose "The Web Console prerequisites have been installed"

    #Extracting setup files
    $ArgumentList= @(
        '/dir="'+$using:SCOMSetupLocalFolder+'"',
        '/silent'
    )
    Start-Process -FilePath "$($using:Drive.DriveLetter)\SCOM_2019.exe" -ArgumentList $ArgumentList -Wait

    #Setting up SCOM
    $ArgumentList= @(
    "/install /components:OMServer,OMConsole,OMWebConsole /ManagementGroupName:$using:SCOMMgmtGroup /SqlServerInstance:SQL01 /SqlInstancePort:1433", 
    "/DatabaseName:OperationsManager /DWSqlServerInstance:SQL01 /DWDatabaseName:OperationsManagerDW /ActionAccountUser:$using:NetBiosDomainName\$using:SCOMServerAction",
    "/ActionAccountPassword:$using:ClearTextPassword /DASAccountUser:$using:NetBiosDomainName\$using:SCOMAccessAccount /DASAccountPassword:$using:ClearTextPassword /DataReaderUser:$using:NetBiosDomainName\$using:SCOMDataWareHouseReader", 
    "/DataReaderPassword:$using:ClearTextPassword /DataWriterUser:$using:NetBiosDomainName\$using:SCOMDataWareHouseWriter /DataWriterPassword:$using:ClearTextPassword /WebSiteName:""Default Web Site""", 
    '/WebConsoleAuthorizationMode:Mixed /EnableErrorReporting:Always /SendCEIPReports:1 /UseMicrosoftUpdate:1 /AcceptEndUserLicenseAgreement:1 /silent'
    )
    #Note: The installation status can also be checked in the SCOM installation log: OpsMgrSetupWizard.log which is found at: %LocalAppData%\SCOM\LOGS
    Start-Process -FilePath "$using:SCOMSetupLocalFolder\Setup.exe" -ArgumentList $ArgumentList -Wait
    "`"$using:SCOMSetupLocalFolder\Setup.exe`" $($ArgumentList -join ' ')" | Out-File "$ENV:SystemDrive\SCOMUnattendedSetup.cmd"
    
    Write-Verbose "The SCOM has been installed. Don't forget to license SCOM"

    if ($using:SCOMLicense -match "^\w{5}-\w{5}-\w{5}-\w{5}-\w{5}$")
    {
        #Importing the OperationsManager module by specifying the full folder path
        Import-Module "${env:ProgramFiles}\Microsoft System Center\Operations Manager\Powershell\OperationsManager"
        $Cred = New-Object System.Management.Automation.PSCredential ($(whoami), $using:SecurePassword)
        #To properly license SCOM, install the product key using the following cmdlet: 
        Set-SCOMLicense -ProductId $using:SCOMLicense -ManagementServer $((Get-SCOMManagementServer).DisplayName) -Credential $Cred -Confirm:$false
        #(Re)Starting the 'System Center Data Access Service'is mandatory to take effect
        Start-Service -DisplayName 'System Center Data Access Service' #-Force
        #Checking the SkuForLicense = Retail 
        Get-SCOMManagementGroup | Format-Table -Property SKUForLicense, Version, TimeOfExpiration -AutoSize
    }
}
Dismount-LabIsoImage -ComputerName SCOM01

#Installing SSRS on the SQL Server
$SQLServer2019ReportingServices = Get-LabInternetFile -Uri $SQLServer2019ReportingServicesURI -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName SQL01 -Path $SQLServer2019ReportingServices.FullName -CommandLine " /quiet /IAcceptLicenseTerms /Edition=Eval"
#Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Invoke-LabCommand -ActivityName 'Configuring Report Server on SQL Server' -ComputerName SQL01 -ScriptBlock {
    #From https://blog.aelterman.com/2018/01/01/silent-installation-and-configuration-for-sql-server-2017-reporting-services/
    #Start-Process -FilePath "$env:ProgramFiles\Microsoft SQL Server Reporting Services\Shared Tools\rsconfig.exe" -ArgumentList "-c -s localhost -d ReportServer -a Windows -i SSRS" -Wait
    # "$env:ProgramFiles\Microsoft SQL Server Reporting Services\Shared Tools\rsconfig.exe -c -s localhost -d ReportServer -a Windows -i SSRS" | Out-File "$ENV:SystemDrive\SCOMUnattendedSetup.cmd" -Append

    #From (with modifications) https://blog.aelterman.com/2018/01/03/complete-automated-configuration-of-sql-server-2017-reporting-services/
    #From https://gist.github.com/SvenAelterman/f2fd058bf3a8aa6f37ac69e5d5dd2511

    function Get-ConfigSet()
    {
	    return Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15\Admin" -class MSReportServer_ConfigurationSetting -ComputerName localhost
    }

    # Allow importing of sqlps module
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

    # Retrieve the current configuration
    $configset = Get-ConfigSet

    $configset

    If (! $configset.IsInitialized)
    {
	    # Get the ReportServer and ReportServerTempDB creation script
	    [string]$dbscript = $configset.GenerateDatabaseCreationScript("ReportServer", 1033, $false).Script

	    # Import the SQL Server PowerShell module
	    #Import-Module sqlps -DisableNameChecking | Out-Null

	    # Establish a connection to the database server (localhost)
	    $conn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection -ArgumentList $env:ComputerName
	    $conn.ApplicationName = "SSRS Configuration Script"
	    $conn.StatementTimeout = 0
	    $conn.Connect()
	    $smo = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList $conn

	    # Create the ReportServer and ReportServerTempDB databases
	    $db = $smo.Databases["master"]
	    $db.ExecuteNonQuery($dbscript)

	    # Set permissions for the databases
	    $dbscript = $configset.GenerateDatabaseRightsScript($configset.WindowsServiceIdentityConfigured, "ReportServer", $false, $true).Script
	    $db.ExecuteNonQuery($dbscript)

	    # Set the database connection info
	    $configset.SetDatabaseConnection("(local)", "ReportServer", 2, "", "")

	    $configset.SetVirtualDirectory("ReportServerWebService", "ReportServer", 1033)
	    $configset.ReserveURL("ReportServerWebService", "http://+:80", 1033)

	    # For SSRS 2016-2017 only, older versions have a different name
	    $configset.SetVirtualDirectory("ReportServerWebApp", "Reports", 1033)
	    $configset.ReserveURL("ReportServerWebApp", "http://+:80", 1033)
        try
        {
	        $configset.InitializeReportServer($configset.InstallationID)
        }
        catch
        {
            throw (New-Object System.Exception("Failed to Initialize Report Server $($_.Exception.Message)", $_.Exception))
        }

	    # Re-start services?
	    $configset.SetServiceState($false, $false, $false)
	    Restart-Service $configset.ServiceName
	    $configset.SetServiceState($true, $true, $true)

	    # Update the current configuration
	    $configset = Get-ConfigSet

	    # Output to screen
	    $configset.IsReportManagerEnabled
	    $configset.IsInitialized
	    $configset.IsWebServiceEnabled
	    $configset.IsWindowsServiceEnabled
	    $configset.ListReportServersInDatabase()
	    $configset.ListReservedUrls();

	    $inst = Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer\RS_SSRS\v15" -class MSReportServer_Instance -ComputerName localhost

	    $inst.GetReportServerUrls()
    }

}

$Drive = Mount-LabIsoImage -ComputerName SQL01 -IsoPath $SCOMISOPath -PassThru
Invoke-LabCommand -ActivityName 'Installing the Operations Manager Reporting on the SQL Server' -ComputerName SQL01 -ScriptBlock {
    #Extracting setup files
    $ArgumentList= @(
        '/dir="'+$using:SCOMSetupLocalFolder+'"',
        '/silent'
    )
    Start-Process -FilePath "$($using:Drive.DriveLetter)\SCOM_2019.exe" -ArgumentList $ArgumentList -Wait

    #Setting up SCOM
    $ArgumentList= @(
    "/install /components:OMReporting /ManagementServer:SCOM01 /SRSInstance:SQL01\SSRS", 
    "/DataReaderUser:$using:NetBiosDomainName\$using:SCOMDataWareHouseReader /DataReaderPassword:$using:ClearTextPassword" , 
    "/SendODRReports:1 /UseMicrosoftUpdate:1 /AcceptEndUserLicenseAgreement:1 /silent"
    )
    #Note: The installation status can also be checked in the SCOM installation log: OpsMgrSetupWizard.log which is found at: %LocalAppData%\SCOM\LOGS
    Start-Process -FilePath "$using:SCOMSetupLocalFolder\Setup.exe" -ArgumentList $ArgumentList -Wait
    "`"$using:SCOMSetupLocalFolder\Setup.exe`" $($ArgumentList -join ' ')" | Out-File "$ENV:SystemDrive\SCOMUnattendedSetup.cmd"
}
Dismount-LabIsoImage -ComputerName SQL01


Invoke-LabCommand -ActivityName 'Cleanup on SQL Server' -ComputerName SQL01 -ScriptBlock {
     Remove-Item -Path "C:\vcredist_x*.*" -Force
     Remove-Item -Path "C:\SSMS-Setup-ENU.exe" -Force
     #Disabling the Internet Connection on the DC (Required only for the SQL Setup via AutomatedLab)
     Get-NetAdapter -Name Internet | Disable-NetAdapter -Confirm:$false
}


#Downloading the SCOM IIS and dependent Management Packs
$SCOMIISManagementPack = Get-LabInternetFile -Uri $SCOMIISManagementPackURI -Path $labSources\SoftwarePackages -PassThru -Force
#$SCOMWSManagementPack = Get-LabInternetFile -Uri $SCOMWSManagementPackURI -Path $labSources\SoftwarePackages -PassThru -Force
$SCOMWS2016andWS2019ManagementPack = Get-LabInternetFile -Uri $SCOMWS2016andWS2019ManagementPackURI -Path $labSources\SoftwarePackages -PassThru -Force
$SCOMNETAPMManagementPack = Get-LabInternetFile -Uri $SCOMNETAPMManagementPackURI -Path $labSources\SoftwarePackages -PassThru -Force

#Installing the SCOM IIS and Dependent Management Packs
#Install-LabSoftwarePackage -ComputerName SCOM01 -Path $SCOMWSManagementPack.FullName -CommandLine "-quiet"
Install-LabSoftwarePackage -ComputerName SCOM01 -Path $SCOMWS2016andWS2019ManagementPack.FullName -CommandLine "-quiet"
Install-LabSoftwarePackage -ComputerName SCOM01 -Path $SCOMIISManagementPack.FullName -CommandLine "-quiet"
Install-LabSoftwarePackage -ComputerName SCOM01 -Path $SCOMNETAPMManagementPack.FullName -CommandLine "-quiet"
#Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Invoke-LabCommand -ActivityName 'Installing Management Packs' -ComputerName SCOM01 -ScriptBlock {
    # From GutHub : Script designed to enumerate and download currently available MPs from Microsoft Download servers.
    #Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/slavizh/Get-SCOMManagementPacks/master/Get-SCOMManagementPacks.ps1) } -Extract"
    #For some cleanup in case of a previous install
    #'Microsoft.SystemCenter.ApplicationInsights', 'Microsoft.Windows.InternetInformationServices.2016', 'Microsoft.Windows.InternetInformationServices.CommonLibrary','Microsoft.Windows.Server.2016.Discovery', 'Microsoft.Windows.Server.Library' | Get-SCOMManagementPack | Remove-SCOMManagementPack
    #Importing the OperationsManager module by specifying the full folder path
    Import-Module "${env:ProgramFiles}\Microsoft System Center\Operations Manager\Powershell\OperationsManager"
    & "$env:ProgramFiles\Microsoft System Center\Operations Manager\Powershell\OperationsManager\Functions.ps1"
    & "$env:ProgramFiles\Microsoft System Center\Operations Manager\Powershell\OperationsManager\Startup.ps1"
    #Getting Installed Management Packs
    $SystemCenterManagementPacks = Get-ChildItem -Path "${env:ProgramFiles(x86)}\System Center Management Packs\" -File -Filter *.mp? -Recurse
    #Installing Windows Server Management Packs prior IIS
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.Server.Library'} | Import-SCOMManagementPack
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.Server.2016.Discovery'} | Import-SCOMManagementPack
    #Installing the Reports and Monitoring Management Pack
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.Server.Reports'} | Import-SCOMManagementPack
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.Server.2016.Monitoring'} | Import-SCOMManagementPack
    #Installing IIS Management Pack.
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.InternetInformationServices.CommonLibrary'} | Import-SCOMManagementPack
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.Windows.InternetInformationServices.2016' } | Import-SCOMManagementPack
    #Installing ApplicationInsights ManagementPack.
    $SystemCenterManagementPacks | Where-Object -FilterScript {$_.BaseName -eq 'Microsoft.SystemCenter.ApplicationInsights'} | Import-SCOMManagementPack

    $SCOMAgent = Install-SCOMAgent -PrimaryManagementServer $(Get-SCOMManagementServer) -DNSHostName IIS01.contoso.com -PassThru
    Get-SCOMPendingManagement | Approve-SCOMPendingManagement
 }

#Removing the Internet Connection on the SQL Server (Required only for the SQL Setup via AutomatedLab)
Get-VM -Name 'SQL01' | Remove-VMNetworkAdapter -Name 'Default Switch' -ErrorAction SilentlyContinue

#Setting processor number to 1 for all VMs (The AL deployment fails with 1 CPU)
Get-LabVM -All | Stop-VM -Passthru -Force | Set-VMProcessor -Count 1
Start-LabVm -All -ProgressIndicator 1 -Wait

$Job | Wait-Job | Out-Null
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

Invoke-LabCommand -ActivityName 'Windows Udpate via the PSWindowsUpdate PowerShell Module' -ComputerName SCOM01 -ScriptBlock {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PSWindowsUpdate -Force -AllowClobber
    Import-Module -Name PSWindowsUpdate 
    #From https://windows-hexerror.linestarve.com/q/so58570077-how-to-install-windows-updates-on-remote-computer-with-powershell: You can't Download or Install Updates on a machine from another remote machine. 
    #Get-WindowsUpdate -Install -AcceptAll -AutoReboot
    Invoke-WUJob -ComputerName localhost -Script { Import-Module PSWindowsUpdate ; Get-WindowsUpdate -Install -AcceptAll -AutoReboot -Verbose | Out-File "C:\PSWindowsUpdate_$('{0:yyyyMMddHHmmss}' -f (Get-Date)).log" -Append } -Confirm:$false -Verbose -RunNow
    #Start-ScheduledTask -TaskName PSWindowsUpdate -Verbose
    While ((Get-ScheduledTask -TaskName PSWindowsUpdate).State -eq 'Running') { Start-Sleep -Seconds 60}
}

Checkpoint-LabVM -SnapshotName 'Windows Update' -All

Show-LabDeploymentSummary -Detailed

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All

Stop-Transcript