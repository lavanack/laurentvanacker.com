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
$ErrorActionPreference = 'Continue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Now = Get-Date
$5YearsFromNow = $Now.AddYears(5)
$CertValidityPeriod = New-TimeSpan -Start $Now -End $5YearsFromNow
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$ConfigurationID  = (New-Guid).Guid
$StandardUser = 'johndoe'

$NetworkID = '10.0.0.0/16' 
$DCIPv4Address = '10.0.0.1'
$PULLIPv4Address = '10.0.0.11'
$TARGETNODE01IPv4Address = '10.0.0.101'
$TARGETNODE02IPv4Address = '10.0.0.102'

$LabName = 'DSCv3IIS'
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
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2025 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 2
}

$TARGETNODE01NetAdapter = @()
$TARGETNODE01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $TARGETNODE01IPv4Address
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$TARGETNODE01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp


$TARGETNODE02NetAdapter = @()
$TARGETNODE02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $TARGETNODE02IPv4Address
#Adding an Internet Connection on the DC (Required for PowerShell Gallery)
$TARGETNODE02NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

#region server definitions
#Domain controller + Certificate Authority
Add-LabMachineDefinition -Name DC -Roles RootDC, CARoot -IpAddress $DCIPv4Address
#Member server
Add-LabMachineDefinition -Name TARGETNODE01 -NetworkAdapter $TARGETNODE01NetAdapter
#Member server
Add-LabMachineDefinition -Name TARGETNODE02 -NetworkAdapter $TARGETNODE02NetAdapter
#endregion

#Installing servers
Install-Lab
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Installing Required Windows Features
$AllLabVMs = Get-LabVM
$Job = @()
$DesktopMachines = $AllLabVMs | Where-Object -FilterScript { $_.OperatingSystem -match "Desktop"}
$TargetNodes = $AllLabVMs | Where-Object -FilterScript { $_.Name -match "^TARGETNODE"}

$Job += Install-LabWindowsFeature -FeatureName Telnet-Client -ComputerName $AllLabVMs -IncludeManagementTools -AsJob -PassThru
#endregion

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $DesktopMachines -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green

    #Setting the Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}

#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD Setup on DC' -ComputerName DC -ScriptBlock {
    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 

    #Creating AD Users
    New-ADUser -Name $Using:StandardUser -AccountPassword $using:SecurePassword -PasswordNeverExpires $true -CannotChangePassword $True -Enabled $true

    #Creating dedicated AD security group  for target nodes
    $ADGroup = New-ADGroup -Name "DSCTargetNodes" -SamAccountName DSCTargetNodes -GroupCategory Security -GroupScope Global -DisplayName "DSC Target Nodes" -Path "CN=Computers,DC=$($using:FQDNDomainName -split "\." -join ",DC=")" -Description "DSC Target Nodes" -PassThru
    $ADGroup | Add-ADGroupMember -Members $(Get-ADComputer -Filter 'Name -like "TARGETNODE*"' | ForEach-Object -Process { "$($_.Name)$"})
    #endregion

    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext

    #region Edge Settings
    $GPO = New-GPO -Name "Edge Settings" | New-GPLink -Target $DefaultNamingContext
    # https://devblogs.microsoft.com/powershell-community/how-to-change-the-start-page-for-the-edge-browser/
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName "RestoreOnStartup" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 4

    #Bonus : To open an edge tab for every default web site installed via DSC (SMB Pull Server) on all target nodes.
    $i=0
    $TargetNodes.Name | ForEach-Object -Process {
        Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' -ValueName ($i++) -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "http://$_"
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
#Generating a new template for 5-year document encryption certificate
New-LabCATemplate -TemplateName DocumentEncryption5Years -DisplayName 'DocumentEncryption5Years' -SourceTemplateName CEPEncryption -ApplicationPolicy 'Document Encryption' -KeyUsage KEY_ENCIPHERMENT, DATA_ENCIPHERMENT -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -SamAccountName 'Domain Computers' -ValidityPeriod $CertValidityPeriod -ComputerName $CertificationAuthority -ErrorAction Stop

$DCDocumentEncryptionCert = Request-LabCertificate -Subject "CN=dc.$FQDNDomainName" -SAN "dc", "dc.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName DC -PassThru -ErrorAction Stop
$TARGETNODE01DocumentEncryptionCert = Request-LabCertificate -Subject "CN=TARGETNODE01.$FQDNDomainName" -SAN "TARGETNODE01", "TARGETNODE01.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName TARGETNODE01 -PassThru -ErrorAction Stop
$TARGETNODE02DocumentEncryptionCert = Request-LabCertificate -Subject "CN=TARGETNODE02.$FQDNDomainName" -SAN "TARGETNODE02", "TARGETNODE02.$FQDNDomainName" -TemplateName DocumentEncryption5Years -ComputerName TARGETNODE02 -PassThru -ErrorAction Stop

Invoke-LabCommand -ActivityName 'Disabling Windows Update service' -ComputerName $AllLabVMs -ScriptBlock {
    Stop-Service WUAUSERV -PassThru | Set-Service -StartupType Disabled
} 


Invoke-LabCommand -ActivityName 'Installing DSCv3 required components' -ComputerName $TargetNodes -ScriptBlock {
    #region WinGet
    #Updating all installed components
    winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --force
    #Installing Powershell 7+ : Silent Install
    #Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

    #FROM https://techcommunity.microsoft.com/blog/itopstalkblog/using-desired-state-configuration-dsc-v3-on-windows-server-2025/4415382
    winget install Microsoft.DSC 
    winget install Microsoft.PowerShell
    #endregion
} 

$YAMLFiles = Copy-LabFileItem -Path $CurrentDir\*.yaml -DestinationFolderPath C:\DSC -ComputerName $TargetNodes -PassThru

Invoke-LabCommand -ActivityName 'Invoking DSCv3' -ComputerName $TargetNodes -ScriptBlock {
    foreach ($CurrentYAMLFile in $($($using:YAMLFiles).FullName | Select-Object -Unique) ) {
        dsc --trace-level info config set --file $CurrentYAMLFile
        #dsc --trace-level trace config get --file $CurrentYAMLFile
    }
}

$Job | Wait-Job | Out-Null

Checkpoint-LabVM -SnapshotName 'FullInstall' -All

Show-LabDeploymentSummary

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript