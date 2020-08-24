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
$Now = Get-Date
$10Years = $Now.AddYears(10)
$WebServerCertValidityPeriod = New-TimeSpan -Start $Now -End $10Years
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID='10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$IIS01IPv4Address = '10.0.0.101'
$IIS02IPv4Address = '10.0.0.102'

$LabName = 'IISWSAOBP2019'
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

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot -IpAddress $DC01IPv4Address
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
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS Setup on DC' -ComputerName DC01 -ScriptBlock {

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 10-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer10Years -DisplayName 'WebServer10Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ValidityPeriod $WebServerCertValidityPeriod -ComputerName $CertificationAuthority -ErrorAction Stop

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

# Hastable for getting the ISO Path for every VM (needed for .Net 2.0 setup)
$IsoPathHashTable = Get-LabMachineDefinition | Where-Object { $_.Name -like "*IIS*"}  | Select-Object -Property Name, @{Name="IsoPath"; Expression={$_.OperatingSystem.IsoPath}} | Group-Object -Property Name -AsHashTable -AsString

$IISServers = (Get-LabVM | Where-Object -FilterScript { $_.Name -like "*IIS*"}).Name
foreach ($CurrentIISServer in $IISServers)
{
    $Drive = Mount-LabIsoImage -ComputerName $CurrentIISServer -IsoPath $IsoPathHashTable[$CurrentIISServer].IsoPath -PassThru
    Invoke-LabCommand -ActivityName 'Copying .Net 2.0 cab, lab and demo files locally' -ComputerName $CurrentIISServer -ScriptBlock {
        $Sxs=New-Item -Path "C:\Sources\Sxs" -ItemType Directory -Force
        Copy-Item -Path "$($using:Drive.DriveLetter)\sources\sxs\*" -Destination $Sxs -Recurse -Force
    }
    Dismount-LabIsoImage -ComputerName $CurrentIISServer
}

#Setting processor number to 1 for all VMs (The AL deployment fails with 1 CPU)
Get-LabVM -All | Stop-VM -Passthru | Set-VMProcessor -Count 1
Get-LabVM -All | Start-VM

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All
  
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript