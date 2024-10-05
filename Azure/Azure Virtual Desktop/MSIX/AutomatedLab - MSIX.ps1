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
    break
} 
Clear-Host
Import-Module -Name AutomatedLab
try {
    while (Stop-Transcript) {
    }
}
catch {
}
$PreviousVerbosePreference = $VerbosePreference
$VerbosePreference = 'SilentlyContinue'
$PreviousErrorActionPreference = $ErrorActionPreference
#$ErrorActionPreference = 'Stop'
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
$NetworkID = '10.0.0.0/16' 

$DC01IPv4Address = '10.0.0.1'
$MSIXIPv4Address = '10.0.0.10'
 
$MSIXCodeSigningTemplateName = "MSIXCodeSigning"
$LabName = 'MSIX'

$MsixPackagingTool = "https://download.microsoft.com/download/d/0/0/d0043667-b1db-4060-9c82-eaee1fa619e8/493b543c21624db8832da8791ebf98f3.msixbundle"
$PsfToolPackageURL = "https://www.tmurgent.com/AppV/Tools/PsfTooling/PsfTooling-6.3.0.0-x64.msix"
#From https://learn.microsoft.com/en-us/windows/msix/packaging-tool/disconnected-environment#example-of-offline-installation
#$MsixPackagingToolDriverPackageURL = "https://download.microsoft.com/download/6/c/7/6c7d654b-580b-40d4-8502-f8d435ca125a/Msix-PackagingTool-Driver-Package%7E31bf3856ad364e35%7Eamd64%7E%7E1.cab"
#endregion


#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List)) {
    Remove-Lab -Name $LabName -Confirm:$false -ErrorAction SilentlyContinue
}

#endregion

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
    'Add-LabMachineDefinition:MinMemory'       = 2GB
    'Add-LabMachineDefinition:Memory'          = 3GB
    'Add-LabMachineDefinition:MaxMemory'       = 4GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 2
}

#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC, CaRoot -IpAddress $DC01IPv4Address
#region Client machine : 2 NICS for  (1 for server communications and 1 for Internet)
$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $MSIXIPv4Address -InterfaceName Corp
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp -InterfaceName Internet
Add-LabMachineDefinition -Name MSIX -NetworkAdapter $netAdapter -OperatingSystem 'Windows 11 Enterprise' -Memory 4GB
#endregion

#Installing servers
Install-Lab -Verbose
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'FreshInstall' -All -Verbose

#region Certification Authority : Creation and SSL Certificate Generation
#Get the CA
$CertificationAuthority = Get-LabIssuingCA
#Generating a new template for Code Signing only for members of the PSCodeSigners AD group 
New-LabCATemplate -TemplateName $MSIXCodeSigningTemplateName -DisplayName 'MSIX Code Signing' -SourceTemplateName CodeSigning -ApplicationPolicy 'Code Signing' -PrivateKeyFlags AllowKeyExport -Version 2 -SamAccountName 'Domain Computers' -ComputerName $CertificationAuthority -ErrorAction Stop
#endregion


$Client = (Get-LabVM -All | Where-Object -FilterScript { $_.Name -eq "MSIX" }).Name
#Installing required PowerShell features for VHD Management
Install-LabWindowsFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -ComputerName $Client -IncludeAllSubFeature

Copy-LabFileItem -Path $CurrentDir\MSIX -ComputerName $Client -DestinationFolderPath C:\ -Recurse
Restart-LabVM $Client -Wait

Checkpoint-LabVM -SnapshotName BeforeMSIX -All -Verbose
#Restore-LabVMSnapshot -SnapshotName 'BeforeMSIX' -All -Verbose

Invoke-LabCommand -ActivityName "Installing 'MSIX Packaging Tool' and 'PSFTooling'" -ComputerName $Client -ScriptBlock {
    #Installing MSIX Packaging Tool
    $OutFile = "C:\MSIX\MsixPackagingTool.msixbundle"
    Invoke-WebRequest -Uri $Using:MsixPackagingTool -OutFile $OutFile
    Add-AppPackage -Path $OutFile

    #Installing MSIX Packaging Tool Driver Package
    <#
    $OutFile = "C:\MSIX\Msix-PackagingTool-Driver-Package~31bf3856ad364e35~amd64~~1.cab"
    Invoke-WebRequest -Uri $Using:dsim -OutFile $OutFile
    Add-AppPackage -Path $OutFile
    #From https://www.manishbangia.com/how-to-install-msix-packaging-tool-driver/
    #dism /online /add-package /packagepath:$OutFile
    Add-WindowsPackage -Online -PackagePath $OutFile
    Add-WindowsCapability -Online -Name "Msix.PackagingTool.Driver~~~~0.0.1.0" #-ErrorAction Ignore
    #>
    dism /online /add-capability /capabilityname:Msix.PackagingTool.Driver~~~~0.0.1.0

    #Installing PSFTooling Tool
    $OutFile = "C:\MSIX\PsfTooling-x64.msix"
    Invoke-WebRequest -Uri $Using:PsfToolPackageURL -OutFile $OutFile
    #Using a Job because it hangs for a long time
    Start-Job -ScriptBlock { Param($OutFile) Add-AppPackage -Path $OutFile } -ArgumentList $OutFile

    # Stops the Shell HW Detection service to prevent the format disk popup
    #Stop-Service -Name ShellHWDetection -Force
    #set-service -Name ShellHWDetection -StartupType Disabled

    #region Turn off auto updates
    #reg add HKLM\Software\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 0 /f
    #Schtasks /Change /Tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
    $RegistryPath = "HKLM:\Software\Policies\Microsoft\WindowsStore"
    $null = New-Item -Path $RegistryPath -Force
    Set-ItemProperty -Path $RegistryPath -Name "AutoDownload" -Value 0 -Type "DWORD" -Force

    # Define the task name
    # Disable the scheduled task
    $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start"
    if ($task) {
        $task | Disable-ScheduledTask
    }
    #endregion 

    Set-WinUserLanguageList -LanguageList fr-fr -Force

    #Customizing Taskbar
    Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
    #Stopping and Disabling windows Update Service
    #Stop-Service -Name wuauserv -PassThru | Set-Service -StartupType Disabled
} -Verbose

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript