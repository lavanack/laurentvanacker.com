<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THISnew
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks tog4 market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#Pre-requisites: We need a trial subscription for Ansible Automation Platform: https://www.redhat.com/en/technologies/management/ansible/trial

#requires -Version 5 -Modules AutomatedLab -RunAsAdministrator 
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$true)]
	[PSCredential]$RedHatCredential
)

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

#region Helper functions
# Adding certificate exception and TLS 1.2 
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-Process {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$true)]
	    [string]$CommandLine,
	    [Parameter(Mandatory=$false)]
	    [string]$LogDir,
	    [switch]$Stdout
    )
    
    Write-Verbose "Running: $CommandLine"
    if ($LogDir)
    {
        $TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
        $StdErrFile =  $(Join-Path -Path $LogDir -ChildPath $("{0}_stderr.txt" -f $TimeStamp))
        $StdOutFile =  $(Join-Path -Path $LogDir -ChildPath $("{0}_stdout.txt" -f $TimeStamp))
        Write-Verbose "`$StdErrFile: $StdErrFile"
        Write-Verbose "`$StdOutFile: $StdOutFile"
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $CommandLine -Wait -RedirectStandardOutput $StdOutFile -RedirectStandardError $StdErrFile
        if ($Stdout)
        {
            Write-Verbose -Message "`r`n$(Get-Content -Path $StdOutFile -Raw)"
        }
        if ((Test-Path -Path $StdErrFile -PathType Leaf) -and ((Get-Item -Path $StdErrFile).Length -gt 0))
        {
            Write-Warning -Message "$StdErrFile is not empty. The command line was : $CommandLine"
            Write-Warning -Message "`r`n$(Get-Content -Path $StdErrFile -Raw)"
        }
    }
    else
    {
        #You'll have to close the prompt Windows by yourself by using [X] at the top right.
        Start-Process -FilePath $env:ComSpec -ArgumentList "/k", $CommandLine -Wait
    }
}
#endregion

$PreviousVerbosePreference = $VerbosePreference
#$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$10YearsFromNow = $Now.AddYears(10)
$WebServerCertValidityPeriod = New-TimeSpan -Start $Now -End $10YearsFromNow
$Logon = 'administrator'
$ClearTextPassword = 'P@ssw0rd'
$AnsibleLogon = 'admin'
$AnsibleClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$GITNetBiosName = 'git'
$GITWebSiteName = "$GITNetBiosName.$FQDNDomainName"

$GITUserName = 'git'
$GITClearTextPassword = 'Password1234!'
$GITSecurePassword = ConvertTo-SecureString -String $GITClearTextPassword -AsPlainText -Force

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$WS01IPv4Address = '10.0.0.11'
$RHEL01IPv4Address = '10.0.0.21'
$GIT01IPv4Address = '10.0.0.31'
$IIS01IPv4Address = '10.0.0.41'

$SourceControlGitFolder = "C:\SourceControl\Git"
$IISGitFolder = Join-Path -Path $SourceControlGitFolder -ChildPath "IIS"
$GITExe = "$env:ProgramFiles\Git\cmd\git"
$GITCmdExe = "$env:ProgramFiles\Git\git-cmd.exe"
$GITBashExe = "$env:ProgramFiles\Git\git-bash.exe"

$MSEdgeEntUri = 'http://go.microsoft.com/fwlink/?LinkID=2093437'
$GITURI = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.OuterHTML -match "64-bit Git For Windows Setup"}).href

$UserHome = (Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH)
#Run ssh-keygen to generate keys if needed
$SSHPublicKeyPath = Join-Path -Path $UserHome -Child "\.ssh\id_rsa.pub"
$SSHPrivateKeyPath = Join-Path -Path $UserHome -Child "\.ssh\id_rsa"

If (-Not(Test-Path -Path $SSHPublicKeyPath -PathType Leaf))
{
    Write-Error -Exception "The $SSHPublicKeyPath (Public key file) doesn't exist" -ErrorAction Stop
}

If (-Not(Test-Path -Path $SSHPrivateKeyPath -PathType Leaf))
{
    Write-Error -Exception "The $SSHPrivateKeyPath (Private key file) doesn't exist" -ErrorAction Stop
}

$LabName = 'LinuxAnsibleTower'

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
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#these credentials are used for connecting to the machines. As this s a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:DnsServer1'      = $DC01IPv4Address
    'Add-LabMachineDefinition:Gateway'         = $DC01IPv4Address
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 2
}

$DC01NetAdapter = @()
$DC01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DC01IPv4Address -InterfaceName Corp
$DC01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$RHEL01NetAdapter = @()
$RHEL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $RHEL01IPv4Address -InterfaceName Corp
#$RHEL01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

#region server definitions
#Domain controller + Certificate Authority
#Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot, Routing -IpAddress $DC01IPv4Address
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot, Routing -NetworkAdapter $DC01NetAdapter
Add-LabMachineDefinition -Name RHEL01 -OperatingSystem 'Red Hat Enterprise Linux 8.6' -DomainName contoso.com -RhelPackage gnome-desktop -NetworkAdapter $RHEL01NetAdapter -MinMemory 5GB -MaxMemory 5GB -Memory 5GB -SshPublicKeyPath $SSHPublicKeyPath -SshPrivateKeyPath $SSHPrivateKeyPaths
#Add-LabMachineDefinition -Name RHEL01 -OperatingSystem 'Red Hat Enterprise Linux 8.6' -DomainName contoso.com -RhelPackage gnome-desktop -NetworkAdapter $RHEL01NetAdapter
Add-LabMachineDefinition -Name WS01 -IpAddress $WS01IPv4Address #-OperatingSystem 'Windows Server 2019 Datacenter (Desktop Experience)'
Add-LabMachineDefinition -Name GIT01 -IpAddress $GIT01IPv4Address #-OperatingSystem 'Windows Server 2019 Datacenter (Desktop Experience)'
#IIS front-end server
Add-LabDiskDefinition -Name DataIIS -DiskSizeInGb 10 -Label "Data" -DriveLetter D
Add-LabDiskDefinition -Name LogsIIS -DiskSizeInGb 10 -Label "Logs" -DriveLetter E
Add-LabMachineDefinition -Name IIS01 -IpAddress $IIS01IPv4Address -Disk DataIIS, LogsIIS

#Installing servers
Install-Lab -Verbose
Do {
    Write-Verbose -Message "Sleeping for 1 minute (Waiting RHEL01 be available on SSH port (TCP/22)) ..." -Verbose
    Start-Sleep -Seconds 60
} While (-Not((Test-NetConnection -ComputerName RHEL01 -Port 22 -InformationLevel "Detailed").TcpTestSucceeded))

Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Installing Required Windows Features
$machines = Get-LabVM -IncludeLinux
$IISServers = $machines | Where-Object -FilterScript { $_.Name -like "*IIS*" }
$WindowsServers = $machines | Where-Object -FilterScript { $_.OperatingSystem -like "Windows*" }
$WindowsServerGroupMembers = $WindowsServers | Where-Object -FilterScript { $_.Name -notin "GIT01", "DC01" }
$LinuxServerGroupMembers = $machines | Where-Object -FilterScript { $_ -notin $WindowsServers}
$Job = @()

$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $WindowsServers -IncludeManagementTools -AsJob -PassThru
#endregion

$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $WindowsServers -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru

$GIT = Get-LabInternetFile -Uri $GITURI -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $WindowsServers -Path $GIT.FullName -CommandLine "/SILENT /CLOSEAPPLICATIONS" -AsJob -PassThru

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $WindowsServers -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0
    Stop-Process -Name Explorer
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp (used in the Security lab)
    Rename-NetAdapter -Name "$labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
    
    #Changing the default Edit action for .ps1 file to open in Powershell ISE
    #Set-ItemProperty -Path Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\Edit\Command -Name "(Default)" -Value "$env:windir\System32\WindowsPowerShell\v1.0\powershell_ise.exe"  -Force
} -Variable (Get-Variable -Name LabName)

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS & AD Setup on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $NetworkID -ReplicationScope 'Forest'
    Add-DnsServerResourceRecordCName -Name "git" -HostNameAlias "git01.$($FQDNDomainName)" -ZoneName $FQDNDomainName
} -Variable (Get-Variable -Name NetworkID, FQDNDomainName)

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 10-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer10Years -DisplayName 'WebServer10Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ValidityPeriod $WebServerCertValidityPeriod -ComputerName $CertificationAuthority -ErrorAction Stop
$GITWebSiteSSLCert = Request-LabCertificate -Subject "CN=$GITWebSiteName" -SAN $GITNetBiosName, "$GITWebSiteName", "GIT01", "GIT01.$FQDNDomainName" -TemplateName WebServer10Years -ComputerName GIT01 -PassThru -ErrorAction Stop


# Hastable for getting the ISO Path for every IIS Server (needed for .Net 2.0 setup)
$IsoPathHashTable = $IISServers | Select-Object -Property Name, @{Name = "IsoPath"; Expression = { $_.OperatingSystem.IsoPath } } | Group-Object -Property Name -AsHashTable -AsString

foreach ($CurrentIISServerName in $IISServers.Name) {
    $Drive = Mount-LabIsoImage -ComputerName $CurrentIISServerName -IsoPath $IsoPathHashTable[$CurrentIISServerName].IsoPath -PassThru
    Invoke-LabCommand -ActivityName 'Copying .Net 2.0 cab locally' -ComputerName $CurrentIISServerName -ScriptBlock {
        $Sxs = New-Item -Path "C:\Sources\Sxs" -ItemType Directory -Force
        Copy-Item -Path "$($Drive.DriveLetter)\sources\sxs\*" -Destination $Sxs -Recurse -Force
    } -Variable (Get-Variable -Name Drive)
    Dismount-LabIsoImage -ComputerName $CurrentIISServerName
}

$Job += Install-LabWindowsFeature -FeatureName NET-Framework-Features -ComputerName $IISServers -AsJob -PassThru

Invoke-LabCommand -ActivityName 'Setting up VS Code and IIS for Git' -ComputerName GIT01  -ScriptBlock {

    $VSCodeExtension = [ordered]@{
        #"PowerShell" = "ms-vscode.powershell"
        'Git Graph' = 'mhutchie.git-graph'
        'Git History' = 'donjayamanne.githistory'
        'GitLens - Git supercharged' = 'eamodio.gitlens'
        'Git File History' = 'pomber.git-file-history'
        'indent-rainbow' = 'oderwat.indent-rainbow'
    }

    #Installing VSCode with Powershell extension (and optional additional ones)
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose

    #FROM https://smalltech.com.au/blog/how-to-run-a-git-server-on-windows-with-iis

    #Step 2
    #Creating directory tree for hosting web sites
    $GITWebSitePath =  "C:\WebSites\$GITWebSiteName"
    $null = New-Item -Path $GITWebSitePath -ItemType Directory -Force

    #Step 3 + 4
    New-LocalGroup -Name  "Git Users" -Description "Git Users"
    New-LocalUser -Name $GITUserName -FullName "Git User" -Description "Git User" -Password $GITSecurePassword -AccountNeverExpires -PasswordNeverExpires #| Add-LocalGroupMember -Group "Administrators"
    Add-LocalGroupMember -Group "Git Users" -Member "git"
    #From https://medium.com/@piteryo7/how-to-set-up-git-server-on-local-network-windows-tutorial-7ec5cd2df3b1

    #Step 5
    <#
    Set-Location -Path $GITWebSitePath
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$using:GitExe"" init --bare IIS.git" -Wait
    #>
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$GitBashExe"" --cd=$GITWebSitePath -c 'git init IIS.git --bare'" -Wait

    
    #Steps 6 -> 9
    #Step 7 
    Add-windowsFeature Web-Server, Web-CGI, Web-Basic-Auth -includeManagementTools
    
    #applying the required ACL (via PowerShell Copy and Paste)
    Get-Acl C:\inetpub\wwwroot | Set-Acl $GITWebSitePath
    #TODO : Customeize ACL for "Git Users" group with full control
    $existingAcl = Get-Acl $GITWebSitePath

    #region Add Full control access for "Git Users" Group for "This folder, subfolders and files"
    $identity = "Git Users"
    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    # Create a new FileSystemAccessRule object
    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity,$colRights,$InheritanceFlag,$PropagationFlag, $objType)
    # Modify the existing ACL to include the new rule
    $existingAcl.SetAccessRule($AccessRule)
    #endregion 

    # Apply the modified access rule to the folder
    $existingAcl | Set-Acl -Path $GITWebSitePath
    
    #PowerShell module for IIS Management
    Import-Module -Name WebAdministration

    #region : Default Settings
    #Removing "Default Web Site"
    Remove-WebSite -Name 'Default Web Site' -ErrorAction Ignore
    Remove-WebSite -Name "$GITWebSiteName" -ErrorAction Ignore
    Remove-WebAppPool -Name "$GITWebSiteName" -ErrorAction Ignore
    #Configuring The Anonymous Authentication to use the AppPoolId
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "userName" -value ""
    #Disabling the Anonymous authentication for all websites
    #Step 9 
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "enabled" -value "False"
    #endregion 

    #region : GIT website management
    #Step 6 
    #Creating a dedicated application pool
    New-WebAppPool -Name "$GITWebSiteName" -Force

    #Creating a dedicated web site
    New-WebSite -Name "$GITWebSiteName" -Port 80 -IPAddress * -PhysicalPath $GITWebSitePath -ApplicationPool "$GITWebSiteName" -Force
    
    #Setting up the dedicated application pool to "No Managed Code"
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$GITWebSiteName']" -name "managedRuntimeVersion" -value ""


    #Step 9 
    #Disabling the Anonymous authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$GITWebSiteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'
    #Enabling the Basic authentication
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$GITWebSiteName" -filter 'system.webServer/security/authentication/basicAuthentication' -name 'enabled' -value 'True'
    #Enabling ASP.Net Impersonation (local web.config)
    #Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$GITWebSiteName" -filter 'system.web/identity' -name 'impersonate' -value 'True'
    #Disabling validation for application pool in integrated mode due to ASP.Net impersonation incompatibility
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$GITWebSiteName" -filter 'system.webServer/validation' -name 'validateIntegratedModeConfiguration' -value 'False'
    #endregion

    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$GITWebSiteName']/environmentVariables" -name "." -value @{name='GIT_PROJECT_ROOT';value="$GITWebSitePath"}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$GITWebSiteName']/environmentVariables" -name "." -value @{name='GIT_HTTP_EXPORT_ALL';value='1'}

    #Step 8
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/handlers" -name "." -value @{name='Git Smart HTTP';path='*';verb='*';modules='CgiModule';scriptProcessor='C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/isapiCgiRestriction" -name "." -value @{path='C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe';allowed='True';description='Git HTTP Backend'}

    $null = New-Item -Path $SourceControlGitFolder -ItemType Directory -Force
    <#
    Set-Location -Path $SourceControlGitFolder
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$using:GitExe"" clone http://$($GITUserName):$($GITClearTextPassword)@$($GITWebSiteName)/IIS.git" -Wait
    #>
    #From https://superuser.com/questions/1104567/how-can-i-find-out-the-command-line-options-for-git-bash-exe
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$GitBashExe"" --cd=$SourceControlGitFolder -c 'git clone http://$($GITUserName):$($GITClearTextPassword)@$($GITWebSiteName)/IIS.git'" -Wait
} -Variable (Get-Variable -Name GITWebSiteName, GITUserName, GITSecurePassword, GitBashExe, GITWebSiteName, GITClearTextPassword, SourceControlGitFolder)

$IISSetupDirectory = $(Join-Path -Path $CurrentDir -ChildPath 'IISSetup')
if (Test-Path -Path $IISSetupDirectory -PathType Container) {
    #Waiting for background jobs
    $LocalIISSetupDirectory = Copy-LabFileItem -Path $IISSetupDirectory -ComputerName GIT01 -DestinationFolderPath $IISGitFolder -Recurse -PassThru #-Verbose
    #$LocalIISSetupDirectory = $LocalIISSetupDirectory | Select -Unique

    Invoke-LabCommand -ActivityName 'Adding IIS Setup to Git repository' -ComputerName GIT01  -ScriptBlock {
        <#
        Set-Location -Path $IISGitFolder
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$using:GitExe"" add ." -Wait
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$using:GitExe"" commit -am 'Adding all files & folders under the project'" -Wait
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$using:GitExe"" push" -Wait
        #>
        Set-WinUserLanguageList fr-fr -Force

        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$GitBashExe"" --cd=$IISGitFolder -c 'git add .'" -Wait
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$GitBashExe"" --cd=$IISGitFolder -c 'git commit -m 'Adding all files and folders under the project''" -Wait
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c", """$GitBashExe"" --cd=$IISGitFolder -c 'git push'" -Wait
    }  -Variable (Get-Variable -Name IISGitFolder, GitBashExe, IISGitFolder)
}

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName $WindowsServers  -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

$Job | Wait-Job | Out-Null
#Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

#Cleaning up previously generated stdout an stderr files
Get-ChildItem -Path $CurrentDir -Filter *_std*.txt | Remove-Item -Force

#Invoke-Process -CommandLine "ssh -l root RHEL01 -vvv"
#Switch to french keyboard
Invoke-Process -CommandLine "ssh root@RHEL01 sudo localectl set-keymap fr" -LogDir $CurrentDir -Stdout -Verbose
#From https://computingforgeeks.com/install-and-configure-ansible-tower-on-centos-rhel/

#region From https://computingforgeeks.com/install-and-configure-ansible-tower-on-centos-rhel/

#region Step 1: Update system and add EPEL repository
#From https://access.redhat.com/discussions/5983481?tour=8
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo subscription-manager remove --all' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo subscription-manager unregister' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo subscription-manager clean' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh root@RHEL01 subscription-manager register --username $($RedHatCredential.UserName) --password $($RedHatCredential.GetNetworkCredential().Password) --auto-attach" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo subscription-manager refresh' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh root@RHEL01 ""POOL_ID=`$(subscription-manager list --available | grep 'Pool ID:' | sed 's/^Pool ID:[[:space:]]*//g'); echo `$POOL_ID;sudo subscription-manager attach --pool=`$POOL_ID""" -LogDir $CurrentDir -Stdout -Verbose
#Verifying the subscription was successfully attached
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo subscription-manager list --consumed' -LogDir $CurrentDir -Stdout -Verbose

#region From https://computingforgeeks.com/how-to-install-epel-repository-on-rhel-8-centos-8/
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 ARCH=$( /bin/arch ); sudo subscription-manager repos --enable "codeready-builder-for-rhel-8-${ARCH}-rpms"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo dnf repolist epel' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo dnf --disablerepo="*" --enablerepo="epel" list available' -LogDir $CurrentDir -Stdout -Verbose
#endregion
#endregion

#Updates
#Invoke-Process -CommandLine 'ssh root@RHEL01 sudo yum -y update' -LogDir $CurrentDir -Stdout -Verbose
#endregion

#region Ansible Tower Setup From https://computingforgeeks.com/install-and-configure-ansible-tower-on-centos-rhel/
#Invoke-Process -CommandLine 'ssh root@RHEL01 "dnf groupinstall ""Development Tools"" -y"' -LogDir $CurrentDir -Stdout -Verbose -LogDir $CurrentDir -Stdout -Verbose
#Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo yum -y install python3-devel python38-devel python39-devel gcc krb5-devel krb5-libs krb5-workstation"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo yum -y install gcc krb5-devel krb5-libs krb5-workstation"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo pip3 install pywinrm[kerberos]  --user"' -LogDir $CurrentDir -Stdout -Verbose

<#
#FROM https://tecadmin.net/install-python-3-9-on-centos-8/
Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo dnf install wget yum-utils make gcc openssl-devel bzip2-devel libffi-devel zlib-devel -y"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 "cd /tmp && wget https://www.python.org/ftp/python/3.9.6/Python-3.9.6.tgz && tar xzf Python-3.9.6.tgz"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 "cd /tmp/Python-3.9.6 && sudo ./configure --with-system-ffi --with-computed-gotos --enable-loadable-sqlite-extensions && sudo make -j ${nproc} && sudo make altinstall"' -LogDir $CurrentDir -Stdout -Verbose 
Invoke-Process -CommandLine 'ssh root@RHEL01 "python3.9 -V' -LogDir $CurrentDir -Stdout -Verbose 
Invoke-Process -CommandLine 'ssh root@RHEL01 "pip3.9 -V' -LogDir $CurrentDir -Stdout -Verbose 
#>

Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo mkdir -p /tmp/tower && cd /tmp/tower && curl -k -O https://releases.ansible.com/ansible-tower/setup/ansible-tower-setup-latest.tar.gz && tar xvf ansible-tower-setup-latest.tar.gz"' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "ssh root@RHEL01 ""cd /tmp/tower/ansible-tower-setup*/ && sed -i 's/_password='\'\''/_password='\'$AnsibleClearTextPassword\''/g' inventory""" -LogDir $CurrentDir -Stdout -Verbose

#region Setup will break if we don't remove (or comment the task) : "Clean up any poorly-permissioned Tower configuration files on upgrade"
$TempLocalTasksYAMLFile = Join-Path -Path $CurrentDir -ChildPath "tasks.yml"
#Invoke-Process -CommandLine "scp root@RHEL01:/tmp/tower/ansible-tower-setup-3.8.6-2/roles/awx_install/tasks/tasks.yml ""$TempLocalTasksYAMLFile""" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "scp root@RHEL01:/tmp/tower/ansible-tower-setup*/roles/awx_install/tasks/tasks.yml ""$TempLocalTasksYAMLFile""" -LogDir $CurrentDir -Stdout -Verbose
<#
#Removing task
$Tokens = (Get-Content -Path $TempLocalTasksYAMLFile -raw) -split '- name: '
$FilteredTokens= $Tokens | Where-Object -FilterScript {$_ -notmatch "Clean up any poorly-permissioned Tower configuration files on upgrade"}
$FilteredTokens -join '- name: ' | Set-Content $TempLocalTasksYAMLFile
#>
#Commenting task
$Tokens = (Get-Content -Path $TempLocalTasksYAMLFile -raw) -split "`n`n"
$FilteredTokens = $Tokens | ForEach-Object -Process { if ($_ -match "- name: Clean up any poorly-permissioned Tower configuration files on upgrade") {"#"+$_.replace("`n", "`n#")} else { $_ }}
$FilteredTokens -join "`n`n" | Set-Content $TempLocalTasksYAMLFile

#Invoke-Process -CommandLine "scp ""$TempLocalTasksYAMLFile"" root@RHEL01:/tmp/tower/ansible-tower-setup-3.8.6-2/roles/awx_install/tasks/tasks.yml" -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine "scp ""$TempLocalTasksYAMLFile"" root@RHEL01:/tmp/tower/ansible-tower-setup*/roles/awx_install/tasks/tasks.yml" -LogDir $CurrentDir -Stdout -Verbose
Remove-Item -Path $TempLocalTasksYAMLFile -Force
#endregion 

Invoke-Process -CommandLine 'ssh root@RHEL01 "cd /tmp/tower/ansible-tower-setup*/ && sudo ./setup.sh' -LogDir $CurrentDir -Stdout -Verbose
Invoke-Process -CommandLine 'ssh root@RHEL01 sudo yum -y downgrade --allowerasing --enablerepo=ansible-tower --enablerepo=ansible-tower-dependencies ansible' -LogDir $CurrentDir -Stdout -Verbose

#FROM https://docs.ansible.com/ansible-tower/latest/html/administration/kerberos_auth.html and https://docs.ansible.com/ansible/2.3/intro_windows.html#installing-python-kerberos-dependencies

#Setting up Kerberos on the RHEL server
Invoke-Process -CommandLine "ssh root@RHEL01 ""sed -i 's/#//g' /etc/krb5.conf && sed -i 's/example.com/$FQDNDomainName/g' /etc/krb5.conf && sed -i 's/EXAMPLE.COM/$($FQDNDomainName.Toupper())/g' /etc/krb5.conf &&sed -i 's/kerberos/$((Get-LabVM -Role RootDC).Name)/g' /etc/krb5.conf """ -LogDir $CurrentDir -Stdout -Verbose
#endregion

Invoke-LabCommand -ActivityName 'Configuring Remoting For Ansible' -ComputerName $WindowsServers  -ScriptBlock {
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1) }" -Verbose
    #Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1) }  -EnableCredSSP -DisableBasicAuth" -Verbose
    #EnableCredSSP = $true
    #DisableBasicAuth = true
    #GlobalHttpFirewallAccess = false
} 

Checkpoint-LabVM -SnapshotName AnsibleInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'AnsibleInstall' -All -Verbose

Start-Sleep -Seconds 30

#region Tower API for Automation from https://docs.ansible.com/ansible-tower/latest/html/towerapi/api_ref.html
#region Authentication
$Headers = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($AnsibleLogon):$($AnsibleClearTextPassword)"))}
$Response = Invoke-RestMethod -Method POST -Header $Headers -ContentType "application/json" -uri https://RHEL01/api/v2/tokens/
Write-Host "Response Token: $($Response.token)"
#endregion

Start-Sleep -Seconds 30

#region Getting Subscriptions
$Body = @{ 
    subscriptions_username = $RedHatCredential.UserName
    subscriptions_password = $RedHatCredential.GetNetworkCredential().Password
}
$Subscriptions = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/config/subscriptions/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#Getting the Trial Subscription
$TrialSubscription = $Subscriptions | Where-Object -FilterScript {$_.license_type -eq 'trial'}
#endregion

Start-Sleep -Seconds 30

#region Attaching the Trial Subscription
$Body = @{ 
    pool_id = $TrialSubscription.pool_id
}
$AttachSubscription = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/config/attach/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Checking license
$Configuration = Invoke-RestMethod -Method Get -Headers $Headers -Uri "https://RHEL01/api/v2/config/" -ContentType "application/json" 
if (-not($Configuration.license_info.license_type))
{
    Write-Error -Message "No valid license found" -ErrorAction Stop
}
#endregion

Start-Sleep -Seconds 30

#region Credential Management
#region Adding Windows Administrator Credential
$inputs = @{
    password = $ClearTextPassword
    username = $Logon
}

$Body = @{ 
    name = "Windows Administrator - Credential"
    description = "Windows Administrator - Credential"
    organization = 1
    credential_type = 1
    inputs = $inputs
}

$WindowsAdminCredential = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/credentials/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Local Git Credential
$inputs = @{
    password = $GITClearTextPassword
    username = $GITUserName
}

$Body = @{ 
    name = "Local Git - Credential"
    description = "Local Git - Credential"
    organization = 1
    credential_type = 2
    inputs = $inputs
}

$LocalGitCredential = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/credentials/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion
#endregion

Start-Sleep -Seconds 30

#region Adding "Linux Servers - Inventory"
$Body = @{ 
    name = "Linux Servers - Inventory"
    description = "Linux Servers - Inventory"
    #1 = Default
    organization = 1
    kind = ""
    host_filter = $null
    variables = $null
    insights_credential = $null
}

$LinuxServersInventory = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Group to "Linux Servers - Inventory"
$Body = @{ 
    name = "LinuxServerGroup"
    description = "Linux Servers - Group"
    variables = ""
}
$LinuxServerGroup = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/$($LinuxServersInventory.id)/groups/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Linux servers to "Linux Servers - Group" 
foreach ($CurrentLinuxServer in $LinuxServerGroupMembers)
{
    $LinuxServerName = "{0}.{1}" -f $CurrentLinuxServer.Name, $CurrentLinuxServer.DomainName
    Write-Verbose "Processing $LinuxServerName ..." -Verbose
    $Body = @{ 
        name = $LinuxServerName
        description = $LinuxServerName
        inventory = $LinuxServersInventory.id
        enabled = $true
        instance_id = ""
        variables = $null
    }

    $CurrentHost = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/groups/$($LinuxServerGroup.id)/hosts/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
}
#endregion

Start-Sleep -Seconds 30

#region Adding "Windows Servers - Inventory"
$Body = @{ 
    name = "Windows Servers - Inventory"
    description = "Windows Servers - Inventory"
    #1 = Default
    organization = 1
    kind = ""
    host_filter = $null
    variables = $null
    insights_credential = $null
}

$WindowsServersInventory = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Group to "Windows Servers - Inventory"
$WinRMSSLListenerVariables = @{
    ansible_ssh_port = 5986
    ansible_connection = "winrm"
    ansible_winrm_server_cert_validation = "ignore"
}

$Body = @{ 
    name = "WindowsServerGroup"
    description = "Windows Servers - Group"
    variables = $WinRMSSLListenerVariables | ConvertTo-Json
}
$WindowsServerGroup = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/$($WindowsServersInventory.id)/groups/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Windows servers to "Windows Servers - Group" 
foreach ($CurrentWindowsServer in $WindowsServerGroupMembers)
{
    $WindowsServerName = "{0}.{1}" -f $CurrentWindowsServer.Name, $CurrentWindowsServer.DomainName
    Write-Verbose "Processing $WindowsServerName ..." -Verbose
    $Body = @{ 
        name = $WindowsServerName
        description = $WindowsServerName
        inventory = $WindowsServersInventory.id
        enabled = $true
        instance_id = ""
        variables = $null
    }

    $CurrentHost = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/groups/$($WindowsServerGroup.id)/hosts/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
}
#endregion

Start-Sleep -Seconds 30

#region Adding "IIS Servers - Inventory"
$Body = @{ 
    name = "IIS Servers - Inventory"
    description = "IIS Servers - Inventory"
    #1 = Default
    organization = 1
    kind = ""
    host_filter = $null
    variables = $null
    insights_credential = $null
}

$IISServersInventory = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Group to "IIS Servers - Inventory"
<#
$WinRMSSLListenerVariables = @{
    ansible_ssh_port = 5986
    ansible_connection = "winrm"
    ansible_winrm_server_cert_validation = "ignore"
}
#>

$Body = @{ 
    name = "IISServerGroup"
    description = "IIS Servers - Group"
    variables = $WinRMSSLListenerVariables | ConvertTo-Json
}
$IISServerGroup = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/inventories/$($IISServersInventory.id)/groups/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding IIS servers to "IIS Servers - Group" 
foreach ($CurrentIISServer in $IISServers)
{
    $IISServerName = "{0}.{1}" -f $CurrentIISServer.Name, $CurrentIISServer.DomainName
    Write-Verbose "Processing $IISServerName ..." -Verbose
    $Body = @{ 
        name = $IISServerName
        description = $IISServerName
        inventory = $IISServersInventory.id
        enabled = $true
        instance_id = ""
        variables = $null
    }

    $CurrentHost = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/groups/$($IISServerGroup.id)/hosts/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
}
#endregion

Start-Sleep -Seconds 30


#region Creating LAN HTTP Git Project
$Body = @{ 
    name = "LAN HTTP Git - Project"
    description = "LAN HTTP Git - Project"
    organization = 1
    scm_type = "git"
    scm_url = "http://git.contoso.com/IIS.git"
    scm_update_on_launch = $true
    credential =  $LocalGitCredential.Id
}

$LANHTTPGitProject = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/projects/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Creating Laurent's Github Project
$Body = @{ 
    name = "Laurent's Github - Project"
    description = "Laurent's Github - Project"
    organization = 1
    scm_type = "git"
    scm_url = "https://github.com/lavanack/laurentvanacker.com"
    scm_update_on_launch = $true
}

$LaurentGitHubProject = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/projects/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Creating a Job Template for Windows #1
$Body = @{ 
    name = "From Laurent's Github: IIS Setup Sample - Template"
    description = "From Laurent's Github: IIS Setup Sample - Template"
    job_type = "run"
    inventory = $WindowsServersInventory.id
    project =  $LaurentGitHubProject.id
    playbook = "Ansible/Samples/Windows/enable-iis.yml"
    verbosity = 4
    organization = 1
}

$IISSetupJobTemplate = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Credential to Job Template for Windows #1
$Body = @{ 
    id = $WindowsAdminCredential.id
}

$JobTemplateCredential = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/$($IISSetupJobTemplate.id)/credentials/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Creating a Job Template for Windows #2
$Body = @{ 
    name = "From Laurent's Github: PowerShell Sample - Template"
    description = "From Laurent's Github: PowerShell Sample - Template"
    job_type = "run"
    inventory = $WindowsServersInventory.id
    project =  $LaurentGitHubProject.id
    playbook = "Ansible/Samples/Windows/run-powershell.yml"
    credentials = $WindowsAdminCredential.id
    verbosity = 4
    organization = 1
}

$PowershellJobTemplate = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Credential to Job Template for Windows #2
$Body = @{ 
    id = $WindowsAdminCredential.id
}
$JobTemplateCredential = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/$($PowershellJobTemplate.id)/credentials/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

<#
#region Manual Playbook #1
#From https://adamtheautomator.com/ansible-tower/#Creating_and_Running_a_Job
#region Creating a YML content
Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo mkdir -p /var/lib/awx/projects/playbooks"' -LogDir $CurrentDir -Stdout -Verbose
$YMLContent = @"
---
  - name: "Playing with Ansible"
    hosts: localhost
    connection: local
    tasks:

    - name: "just execute a ls -lrt command"
      shell: "ls -lrt"
      register: "output"

    - debug: var=output.stdout_lines
"@
$YMLFile = New-Item -Path $(Join-Path -Path $CurrentDir -ChildPath 'ata.yml') -ItemType File -Value $YMLContent -Force
Invoke-Process -CommandLine "scp ""$($YMLFile.FullName)"" root@RHEL01:/var/lib/awx/projects/playbooks/""" -LogDir $CurrentDir -Stdout -Verbose
#endregion

Start-Sleep -Seconds 30

#region Creating a Playbooks Project
$Body = @{ 
    name = "Playbooks - Project"
    description = "ATA Learning"
    organization = 1
    scm_type = ""
    scm_update_on_launch = $false
    local_path = "playbooks"
}

$MyProject = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/projects/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Creating a Job Template
$Body = @{ 
    name = "My Job - Template"
    description = "My Job - Template"
    job_type = "run"
    inventory = $LinuxServersInventory.id
    project =  $MyProject.id
    playbook = "ata.yml"
    verbosity = 4
    organization = 1
}

$MyJobTemplate = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30
#endregion
#>

#region Manual Playbook : IIS Setup
#From https://adamtheautomator.com/ansible-tower/#Creating_and_Running_a_Job
#region Creating a YML content
Invoke-Process -CommandLine 'ssh root@RHEL01 "sudo mkdir -p /var/lib/awx/projects/playbooks"' -LogDir $CurrentDir -Stdout -Verbose
$EscapedSourceControlGitFolder = $SourceControlGitFolder.Replace('\', '\\')
$IISSetupScript = "$SourceControlGitFolder\IIS\IISSetup\IISSetup.ps1".Replace('\', '\\')

$YMLContent = @"
---
 - hosts: all
   tasks:
   - name: Create Source directory structure
     win_file:
       path: "$EscapedSourceControlGitFolder" 
       state: directory

   - name: Clone the LAN HTTP Git Repository
     win_command: >
       "$GitBashExe" 
       --cd=$SourceControlGitFolder 
       -c 'git clone http://$($GITUserName):$($GITClearTextPassword)@$($GITWebSiteName)/IIS.git'

   - name: Run powershell - Install IIS
     win_shell: '& "$IISSetupScript"'
"@

$YMLFile = New-Item -Path $(Join-Path -Path $CurrentDir -ChildPath 'iissetup.yml') -ItemType File -Value $YMLContent -Force
Invoke-Process -CommandLine "scp ""$($YMLFile.FullName)"" root@RHEL01:/var/lib/awx/projects/playbooks/""" -LogDir $CurrentDir -Stdout -Verbose
#endregion

Start-Sleep -Seconds 30

#region Creating a Playbooks Project
$Body = @{ 
    name = "IIS Setup Playbook - Project"
    description = "IIS Setup Playbook - Project"
    organization = 1
    scm_type = ""
    scm_update_on_launch = $false
    local_path = "playbooks"
}

$IISSetupProject = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/projects/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Creating a Job Template for Windows #3
$Body = @{ 
    name = "From LAN HTTP Git: IIS Setup - Template"
    description = "From LAN HTTP Git: IIS Setup - Template"
    job_type = "run"
    inventory = $IISServersInventory.id
    project =  $IISSetupProject.id
    playbook = "iissetup.yml"
    verbosity = 4
    organization = 1
}

$IISSetupJobTemplate = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 
#endregion

Start-Sleep -Seconds 30

#region Adding Credential to Job Template for Windows #3
$Body = @{ 
    id = $WindowsAdminCredential.id
}
$JobTemplateCredential = Invoke-RestMethod -Method Post -Headers $Headers -Uri "https://RHEL01/api/v2/job_templates/$($IISSetupJobTemplate.id)/credentials/" -Body $($Body | ConvertTo-Json) -ContentType "application/json" 

Start-Sleep -Seconds 30

#endregion

#endregion

#From propagating the environment variables
Restart-LabVM -ComputerName $IISServers -Wait #-Verbose

#region Using browser to manage Ansible Tower
$AnsibleClearTextPassword | Set-Clipboard
Write-Host "[INFO] Use $AnsibleLogon/$AnsibleClearTextPassword as credential for connecting to https://RHEL01. ($AnsibleClearTextPassword bas been copied into the clipboard)" -ForegroundColor Green
Start-Process https://RHEL01 -WindowStyle Maximized
#endregion

Checkpoint-LabVM -SnapshotName 'FullInstall' -All
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose
Show-LabDeploymentSummary


#$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference

Stop-Transcript