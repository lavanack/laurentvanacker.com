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
$ErrorActionPreference = 'Cont'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
#$ClearTextPassword = 'Pa$$w0rd'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.local'

$PowerUser = 'power'
#$PowerUserCredential = New-Object System.Management.Automation.PSCredential ("$NetBiosDomainName\$PowerUser", $SecurePassword)

$NetworkID = '192.168.1.0/24' 
$DCIPv4Address = '192.168.1.1'
$MSIPv4Address = '192.168.1.2'
$WIN10IPv4Address = '192.168.1.3'

$VSCodeExtension = [ordered]@{
    #"PowerShell" = "ms-vscode.powershell"
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
}

$GitURI = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.InnerText -eq "64-bit Git For Windows Setup"}).href

$LabName = 'PSDSCWSv2'
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

#these credentials are used for connecting to the Machines. As this is a lab we use clear-text passwords
Set-LabInstallationCredential -Username $Logon -Password $ClearTextPassword

#defining default parameter values, as these ones are the same for all the Machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $LabName
    'Add-LabMachineDefinition:DomainName'      = $FQDNDomainName
    'Add-LabMachineDefinition:MinMemory'       = 1GB
    'Add-LabMachineDefinition:MaxMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 Datacenter (Desktop Experience)'
    #'Add-LabMachineDefinition:Processors'      = 4
}

$DCNetAdapter = @()
$DCNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DCIPv4Address
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$DCNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$WIN10NetAdapter = @()
$WIN10NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $WIN10IPv4Address
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$WIN10NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

$MSNetAdapter = @()
$MSNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $MSIPv4Address
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$MSNetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC -Roles RootDC -NetworkAdapter $DCNetAdapter
#PULL Server
Add-LabMachineDefinition -Name WIN10 -NetworkAdapter $WIN10NetAdapter -OperatingSystem 'Windows 10 Enterprise' -Memory 4GB -MinMemory 2GB -MaxMemory 4GB #-Processors 4
#Member server
Add-LabMachineDefinition -Name MS -NetworkAdapter $MSNetAdapter
#endregion

#Installing servers
Install-Lab
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Installing Required Windows Features
$Machines = Get-LabVM -All
$DesktopMachines = $Machines | Where-Object -FilterScript { $_.OperatingSystem -match "Desktop|GUI"}
Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $Machines -IncludeManagementTools -AsJob
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $DesktopMachines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer -Force
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD Setup on DC' -ComputerName DC -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

    #Creating AD Users
    $ADUser = New-ADUser -SamAccountName  $Using:PowerUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true -DisplayName 'Power Shell' -Name 'Power Shell' -PassThru
    Add-ADGroupMember -Identity 'Domain Admins' -Members $ADUser
}


#Installing Git
$Git = Get-LabInternetFile -Uri $GitUri -Path $labSources\SoftwarePackages -PassThru -Force
Install-LabSoftwarePackage -ComputerName WIN10 -Path $Git.FullName -CommandLine "/SILENT /CLOSEAPPLICATIONS"

Invoke-LabCommand -ActivityName "Installing Powershell7+, VSCode and extensions and some PowerShell modules" -ComputerName WIN10 -ScriptBlock {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    #Installing the NuGet Provider
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

    #Installing Powershell 7+ : Silent Install
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

    #Installing VSCode with Powershell extension (and optional additional ones)
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($($using:VSCodeExtension).Values -join ',')" -Verbose

    #Installing posh-git module
    Install-Module posh-git, Az.Automation -Force
    #Enable-GitColors
}

Copy-LabFileItem -Path C:\PoshDSCv2\Demos -DestinationFolder C:\PShell\ -ComputerName $Machines -Recurse
Copy-LabFileItem -Path C:\PoshDSCv2\Labs -DestinationFolder C:\PShell\ -ComputerName $Machines -Recurse

Get-Job -Name 'Installation of*' | Wait-Job | Out-Null

Show-LabDeploymentSummary -Detailed
Restart-LabVM -ComputerName $Machines -Wait -Verbose
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript