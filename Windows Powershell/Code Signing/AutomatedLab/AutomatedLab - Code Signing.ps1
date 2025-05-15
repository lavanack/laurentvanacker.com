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
    Write-Host "Stopping Transcript ..."; Stop-Transcript
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
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'
$DevUser = "DevUser"
$ClientUser = "ClientUser"
$DevUserCred = New-Object PSCredential -ArgumentList "$NetBiosDomainName\$DevUser", $SecurePassword   
$ClientUserCred = New-Object PSCredential -ArgumentList "$NetBiosDomainName\$ClientUser", $SecurePassword   
$PowerShellCodeSigningTemplateName = "PowerShellCodeSigning"


$NetworkID = '10.0.0.0/16' 
$DC01IPv4Address = '10.0.0.1'
$CAIPv4Address = '10.0.0.2'
$DEV01IPv4Address = '10.0.0.21'
$CLIENT01IPv4Address = '10.0.0.31'

#Using half of the logical processors to speed up the deployement
[int]$LabMachineDefinitionProcessors = [math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors)

$LabName = 'PSCodeSigning'
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
    'Add-LabMachineDefinition:Processors'      = $LabMachineDefinitionProcessors
}

#Network adapters for dev machine
$DEV01NetAdapter = @()
$DEV01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $DEV01IPv4Address
$DEV01NetAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

#region server definitions
#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
#Certificate Authority
Add-LabMachineDefinition -Name CA01 -Roles CARoot -IpAddress $CAIPv4Address
#Dev machine
Add-LabMachineDefinition -Name DEV01 -NetworkAdapter $DEV01NetAdapter -OperatingSystem 'Windows 11 Enterprise'
#Client Machine 
Add-LabMachineDefinition -Name CLIENT01 -IpAddress $CLIENT01IPv4Address -OperatingSystem 'Windows 11 Enterprise'
#endregion

#Installing servers
Install-Lab

$AllMachines = Get-LabVM
$WindowsServers = $AllMachines | Where-Object -FilterScript { $_.OperatingSystem -match "Server" }

Invoke-LabCommand -ActivityName "Disabling IE ESC" -ComputerName $WindowsServers -ScriptBlock {
    #Disabling IE ESC
    $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $UserKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    Set-ItemProperty -Path $AdminKey -Name 'IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0' -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name 'IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0' -Value 0 -Force
    Rundll32 iesetup.dll, IEHardenLMSettings
    Rundll32 iesetup.dll, IEHardenUser
    Rundll32 iesetup.dll, IEHardenAdmin
    Remove-Item -Path $AdminKey -Force
    Remove-Item -Path $UserKey -Force
}


Invoke-LabCommand -ActivityName "Renaming NICs" -ComputerName $AllMachines -ScriptBlock {
    #Setting the Keyboard to French
    #Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Renaming the main NIC adapter to Corp (used in the Security lab)
    Rename-NetAdapter -Name "$using:labName 0" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Ethernet" -NewName 'Corp' -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name "Default Switch 0" -NewName 'Internet' -PassThru -ErrorAction SilentlyContinue
}


#Installing and setting up DNS
Invoke-LabCommand -ActivityName 'DNS, AD & GPO Settings on DC' -ComputerName DC01 -ScriptBlock {

    #region DNS management
    #Reverse lookup zone creation
    Add-DnsServerPrimaryZone -NetworkID $using:NetworkID -ReplicationScope 'Forest' 
    #endregion

    #Creating a GPO at the domain level for certificate autoenrollment
    $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
    $GPO = New-GPO -Name "Autoenrollment Policy" | New-GPLink -Target $DefaultNamingContext
    #region User Enrollment Policy
    #https://www.sysadmins.lv/retired-msft-blogs/xdot509/troubleshooting-autoenrollment.aspx : 0x00000007 = Enabled, Update Certificates that user certificates templates configured, Renew expired certificates, update pending certificates, and remove revoked certificates configured
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type Dword -value 0x00000007 
    #endregion

    #region PowerShell Execution Policy
    $GPO = New-GPO -Name "PowerShell Execution Policy" | New-GPLink -Target $DefaultNamingContext
    #Setting PowerShell Execution Policy to "AllSigned"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell' -ValueName ExecutionPolicy -Type String -value "AllSigned"
    #Enabling PowerShell Script Execution
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell' -ValueName EnableScripts -Type Dword -value 1
    #endregion

    #region IE Settings
    $GPO = New-GPO -Name "IE Settings" | New-GPLink -Target $DefaultNamingContext
    #Disabling IE ESC
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0 -Type Dword -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -ValueName IsInstalled -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 0 -Type Dword -value 0
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap' -ValueName IEHarden -Type Dword -value 0
    #endregion

    #region WireShark : (Pre)-Master-Secret Log Filename
    $GPO = New-GPO -Name "(Pre)-Master-Secret Log Filename" | New-GPLink -Target $DefaultNamingContext
    #For decrypting SSL traffic via network tools : https://support.f5.com/csp/article/K50557518
    $SSLKeysFile = '%USERPROFILE%\AppData\Local\ssl-keys.log'
    Set-GPRegistryValue -Name $GPO.DisplayName -Key 'HKCU\Environment' -ValueName "SSLKEYLOGFILE" -Type ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value $SSLKeysFile
    #endregion

    New-ADGroup -Name "PSCodeSigners" -SamAccountName PSCodeSigners -GroupCategory Security -GroupScope Global -DisplayName "PSCodeSigners" -Description "Powershell Code Signers"
    New-ADUser -Name "$using:ClientUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True
    New-ADUser -Name "$using:DevUser" -PasswordNeverExpires $True -AccountPassword $Using:SecurePassword -CannotChangePassword $True -Enabled $True
    Add-ADGroupMember -Identity "PSCodeSigners" -Members "$using:DevUser"
}

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for Code Signing only for members of the PSCodeSigners AD group 
New-LabCATemplate -TemplateName $PowerShellCodeSigningTemplateName -DisplayName 'PowerShell Code Signing' -SourceTemplateName CodeSigning -ApplicationPolicy 'Code Signing' -EnrollmentFlags Autoenrollment -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'PSCodeSigners' -ComputerName $CertificationAuthority -ErrorAction Stop
#Enable-LabCertificateAutoenrollment -Computer -User -CodeSigningTemplateName $using:PowerShellCodeSigningTemplateName
#endregion

Invoke-LabCommand -ActivityName 'Group Policy Update' -ComputerName DC01 -ScriptBlock {
    Invoke-GPUpdate -Computer DEV01 -Force
    Invoke-GPUpdate -Computer CLIENT01 -Force
}


Invoke-LabCommand -ActivityName 'RDP Settings' -ComputerName DEV01 -ScriptBlock {
    #For RDP connection and PowerShell remoting (No administration privileges required here)
    Add-LocalGroupMember -Group "Remote Management Users" -Member "$using:DevUser"
    #Adding the DevUser account to the "Remote Desktop Users" group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member  "$using:DevUser"
}

Invoke-LabCommand -ActivityName 'RDP Settings' -ComputerName CLIENT01 -ScriptBlock {
    #For RDP connection and PowerShell remoting (No administration privileges required here)
    Add-LocalGroupMember -Group "Remote Management Users" -Member "$using:ClientUser"
    #Adding the ClientUser account to the "Remote Desktop Users" group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member  "$using:ClientUser"
}

Invoke-LabCommand -ActivityName 'RDP Settings & Signing PowerShell Script' -ComputerName DEV01 -Credential $DevUserCred -Verbose -ScriptBlock {
    $ScriptFilePath = "C:\Users\$using:DevUser\Desktop\SignedScript.ps1"
    "'This is my first signed script ...'" | Out-File $ScriptFilePath -Force
    #Normally this line is not required when connecting first via RDP because the autoenrollment feature will issue the required certificate
    $CodeSigningCert = Get-Certificate -Template $using:PowerShellCodeSigningTemplateName -Url ldap: -CertStoreLocation Cert:\CurrentUser\My
    #Signing the Powershell Script
    Set-AuthenticodeSignature -Certificate $CodeSigningCert.Certificate -FilePath $ScriptFilePath -TimestampServer $using:TimestampServer
}

Invoke-LabCommand -ActivityName 'Creating Profile' -ComputerName CLIENT01 -Credential $ClientUserCred -ScriptBlock {
    #Just to create the profile (and the desktop folder)
}

Invoke-LabCommand -ActivityName 'Copying the PowerShell script from the Dev to the Client machine' -ComputerName CLIENT01 -ScriptBlock {
    #Copying the signed script on the client machine
    Copy-Item -Path "\\DEV01\C$\Users\$using:DevUser\Desktop\SignedScript.ps1" -Destination "C:\Users\$using:ClientUser\Desktop\SignedScript.ps1"
}

#Setting processor number to 1 for all VMs
Get-LabVM -All | Stop-VM -Passthru | Set-VMProcessor -Count 1
Get-LabVM -All | Start-VM

Show-LabDeploymentSummary
Checkpoint-LabVM -SnapshotName 'FullInstall' -All

$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript