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
try {while (Stop-Transcript) {}} catch {}
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
$NetworkID='10.0.0.0/16' 

$DC01IPv4Address = '10.0.0.1'
$MSIXIPv4Address = '10.0.0.10'

$LabName = 'MSIX'
#endregion


#Cleaning previously existing lab
if ($LabName -in (Get-Lab -List))
{
    Remove-Lab -name $LabName -confirm:$false -ErrorAction SilentlyContinue
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
    'Add-LabMachineDefinition:Memory'          = 2GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2022 Datacenter (Desktop Experience)'
    'Add-LabMachineDefinition:Processors'      = 2
}

#Domain controller
Add-LabMachineDefinition -Name DC01 -Roles RootDC -IpAddress $DC01IPv4Address
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

$Client = (Get-LabVM -All | Where-Object -FilterScript { $_.Name -eq "MSIX"}).Name
#Installing required PowerShell features for VHD Management
Install-LabWindowsFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -ComputerName $Client -IncludeAllSubFeature
<#
Invoke-LabCommand -ActivityName "Installing required PowerShell features for VHD Management" -ComputerName $Client -ScriptBlock {
    $Result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart:$false
    if ($Result.RestartNeeded) {
        Restart-Computer -Force
    }
}
#>

Copy-LabFileItem -Path $CurrentDir\MSIX -ComputerName $Client -DestinationFolderPath C:\ -Recurse
Restart-LabVM $Client -Wait

Invoke-LabCommand -ActivityName "Installing winget and 'MSIX Packaging Tool'" -ComputerName $Client -ScriptBlock {
    Set-WinUserLanguageList -LanguageList fr-fr -Force
    #region Installing winget via the WingetTools Powershell module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name WingetTools -Force -Verbose
    Install-WinGet -Preview -PassThru -Verbose
    #endregion

    $CommandLine = 'winget install "MSIX Packaging Tool" --source msstore --accept-source-agreements --accept-package-agreements'
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $CommandLine -Wait
}

Show-LabDeploymentSummary -Detailed
Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript