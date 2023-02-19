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
$ErrorActionPreference = 'Continue'
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f (get-date)).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Global variables definition
$Logon = 'Administrator'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$NetBiosDomainName = 'CONTOSO'
$FQDNDomainName = 'contoso.com'

#$GitURI = 'https://github.com/git-for-windows/git/releases/download/v2.33.1.windows.1/Git-2.33.1-64-bit.exe'
$MSEdgeEntUri = 'http://go.microsoft.com/fwlink/?LinkID=2093437'
$GitURI = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.InnerText -eq "64-bit Git For Windows Setup"}).href

$NetworkID='10.0.0.0/16' 

$DC01IPv4Address = '10.0.0.1'
$WIN11IPv4Address = '10.0.0.10'


$VSCodeExtension = [ordered]@{
    #"PowerShell" = "ms-vscode.powershell"
    'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
}

#$VSCodeUri = "https://go.microsoft.com/fwlink/?linkid=852157"
$LabName = 'PoShCore'
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
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $LabName -Ipv4Address $WIN11IPv4Address
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp
Add-LabMachineDefinition -Name WIN11 -NetworkAdapter $netAdapter -OperatingSystem 'Windows 11 Enterprise'
#endregion

#Installing servers
Install-Lab 
Checkpoint-LabVM -SnapshotName FreshInstall -All -Verbose

$Job = @()
$Client = (Get-LabVM | Where-Object -FilterScript { $_.Name -eq "WIN11"}).Name

#Installing Git
$Git = Get-LabInternetFile -Uri $GitUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $Client -Path $Git.FullName -CommandLine " /SILENT /CLOSEAPPLICATIONS" -AsJob -PassThru

$MSEdgeEnt = Get-LabInternetFile -Uri $MSEdgeEntUri -Path $labSources\SoftwarePackages -PassThru -Force
$Job += Install-LabSoftwarePackage -ComputerName $Client -Path $MSEdgeEnt.FullName -CommandLine "/passive /norestart" -AsJob -PassThru

Invoke-LabCommand -ActivityName "Installing Powershell7+, VSCode, PowerShell extensions (and optionally additional ones) and posh-git module" -ComputerName $Client -ScriptBlock {
	#Setting Keyboard to French
    Set-WinUserLanguageList -LanguageList "fr-FR" -Force

    #Installing the NuGet Provider
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

    #Installing Powershell 7+ : Silent Install
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

    <#
    #Installing VSCode with Powershell extension (and optional additional ones)
    Set-ExecutionPolicy Unrestricted -Force
    Install-Script Install-VSCode -Force
    Install-VSCode.ps1 -AdditionalExtensions $VSCodeExtension.Values
    #>

    #Installing VSCode with Powershell extension (and optional additional ones)
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose

    #Installing posh-git module
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-Module posh-git -force
    #Enable-GitColors
} -Variable (Get-Variable -Name VSCodeExtension) -Verbose

$Job | Wait-Job | Out-Null

Show-LabDeploymentSummary -Detailed
Restart-LabVM $Client -Wait

Checkpoint-LabVM -SnapshotName 'FullInstall' -All -Verbose
$VerbosePreference = $PreviousVerbosePreference
$ErrorActionPreference = $PreviousErrorActionPreference
#Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose

Stop-Transcript