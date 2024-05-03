#requires -Version 7 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$ConfigurationName = "ExampleConfiguration"
$ConfigurationScriptFilePath = Join-Path -Path $CurrentDir -ChildPath "$ConfigurationName.ps1"
Set-Location -Path $CurrentDir

#Installing the NuGet Provider
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az.Accounts, Az.Compute, Az.PolicyInsights, Az.Resources, Az.Ssh, Az.Storage -Scope AllUsers -AllowClobber -Force
#Install-Module -Name Microsoft.PowerShell.GraphicalTools -Force
Install-Module -Name GuestConfiguration -Scope AllUsers -AllowClobber -Force
Install-Module PSDesiredStateConfiguration -AllowPreRelease -RequiredVersion 3.0.0-beta1 -AllowClobber -Scope AllUsers -Force
Install-Module nxtools -Scope AllUsers -Force

# Compiling the Configuration
& $ConfigurationScriptFilePath

# Creating the guest configuration package for Azure Policy
$GuestConfigurationPackage = New-GuestConfigurationPackage -Name $ConfigurationName -Configuration "./$ConfigurationName/localhost.mof" -Type AuditAndSet -Force
$GuestConfigurationPackage
