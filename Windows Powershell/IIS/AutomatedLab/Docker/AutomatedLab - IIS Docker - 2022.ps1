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
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$10YearsFromNow = $Now.AddYears(10)
$WebServerCertValidityPeriod = New-TimeSpan -Start $Now -End $10YearsFromNow
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$DOCKER01IPv4Address = '10.0.0.11'

$IISDockerFileContent = @'
FROM mcr.microsoft.com/windows/servercore/iis
'@
$DockerFileName = 'DockerFile'

$LabName = 'IISDocker2022'
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
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = 4
}

$DOCKER01NetAdapter = @()
$DOCKER01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DOCKER01IPv4Address -InterfaceName 'Corp'
$DOCKER01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName 'Internet'

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CARoot -IpAddress $DC01IPv4Address
#IIS front-end server
Add-LabMachineDefinition -Name DOCKER01 -NetworkAdapter $DOCKER01NetAdapter -MinMemory 6GB -MaxMemory 6GB -Memory 6GB -Processors 2
#endregion

#Installing servers
Install-Lab
Checkpoint-LabVM -SnapshotName FreshInstall -All
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose


#region Installing Required Windows Features
$machines = Get-LabVM
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $machines -IncludeManagementTools -AsJob
#endregion

#region Enabling Nested Virtualization on DOCKER01
#Restarting all VMs
Stop-LabVM -All -Wait
Set-VMProcessor -VMName DOCKER01 -ExposeVirtualizationExtensions $true
Start-LabVM -All -Wait
#endregion

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS & AD Setup on DC' -ComputerName DC01 -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for 10-year SSL Web Server certificate
New-LabCATemplate -TemplateName WebServer10Years -DisplayName 'WebServer10Years' -SourceTemplateName WebServer -ApplicationPolicy 'Server Authentication' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ValidityPeriod $WebServerCertValidityPeriod -ComputerName $CertificationAuthority -ErrorAction Stop
#Request-LabCertificate -Subject "CN=DOCKER01.contoso.com" -TemplateName WebServer10Years -ComputerName DOCKER01 -PassThru 
#endregion

Install-LabWindowsFeature -FeatureName Containers,Hyper-V -ComputerName DOCKER01 -IncludeManagementTools

Invoke-LabCommand -ActivityName 'Docker Setup' -ComputerName DOCKER01 -ScriptBlock {
    #From https://docs.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=Windows-Server#prerequisites
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    #Open an elevated PowerShell session and install the Docker-Microsoft PackageManagement Provider from the PowerShell Gallery.
    Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
    #Use the PackageManagement PowerShell module to install the latest version of Docker.
    Install-Package -Name Docker -ProviderName DockerMsftProvider -Force
    #After the installation completes, restart the computer.
}
Restart-LabVM -ComputerName DOCKER01 -Wait
Checkpoint-LabVM -SnapshotName DockerSetup -All

Invoke-LabCommand -ActivityName 'Docker Configuration' -ComputerName DOCKER01 -Verbose -ScriptBlock {
    Start-Service Docker
    #Pulling IIS image
    #docker pull mcr.microsoft.com/windows/servercore/iis

    $null = New-Item -Path $env:SystemDrive\Docker\IIS\$using:DockerFileName -ItemType File -Value $using:IISDockerFileContent -Force
    Set-Location -Path $env:SystemDrive\Docker\IIS\
    docker build -t iis-website .
    docker run -d -p 80:80 --name my-running-site iis-website
    #docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" my-running-site

    #Pulling ASP.Net Sample image
    docker run -d -p 81:80 --name aspnet_sample --rm -it mcr.microsoft.com/dotnet/framework/samples:aspnetapp
}

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName DOCKER01 -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 

#Waiting for background jobs
Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript