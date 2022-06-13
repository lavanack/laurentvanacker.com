#requires -Version 5 -RunAsAdministrator 
#More info on https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-setup
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Install the guest configuration DSC resource module from PowerShell Gallery
Install-Module -Name GuestConfiguration, PSDSCResources, Az.PolicyInsights -Force

#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

#Installing VSCode with Powershell extension
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }" -Verbose

Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Get-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute | Where-Object RegistrationState -eq Registered

Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
Get-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration | Where-Object RegistrationState -eq Registered

Start-Process -FilePath "C:\Program Files\Microsoft VS Code\Code.exe" -ArgumentList "."