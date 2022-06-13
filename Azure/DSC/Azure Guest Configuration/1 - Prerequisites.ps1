#requires -Version 5 -RunAsAdministrator 
#More info on https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Disabling IE Enhanced Security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force
#endregion

#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az.Compute, Az.Resources, GuestConfiguration, PSDSCResources, Az.PolicyInsights -Force

Connect-AzAccount
Get-AzSubscription | Out-GridView -PassThru | Select-AzSubscription

#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

#Installing VSCode with Powershell extension
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }" -Verbose

Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Get-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute | Where-Object RegistrationState -eq Registered

Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
Get-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration | Where-Object RegistrationState -eq Registered

Start-Process -FilePath "C:\Program Files\Microsoft VS Code\Code.exe" -ArgumentList "."