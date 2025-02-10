#To run from the Azure VM
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
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
#Install-Module -Name Az.Compute, Az.PolicyInsights, Az.Resources, Az.Storage, GuestConfiguration, PSDesiredStateConfiguration, PSDSCResources -Force
Install-Module -Name Az.Accounts, Az.Compute, Az.PolicyInsights, Az.Resources, Az.Storage, PSDesiredStateConfiguration, PSDSCResources -Force
Install-Module -Name GuestConfiguration -Force

#Connection to Azure and Subscription selection
Connect-AzAccount -UseDeviceAuthentication
#Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription

#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

#region Installing VSCode with useful extensions : Silent Install
$VSCodeExtension = [ordered]@{
    #"PowerShell" = "ms-vscode.powershell"
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    #'Git Graph' = 'mhutchie.git-graph'
    #'Git History' = 'donjayamanne.githistory'
    #'GitLens - Git supercharged' = 'eamodio.gitlens'
    #'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
    'Azure Policy'   = 'AzurePolicy.azurepolicyextension'
}

while (-not(Test-Path -Path "$env:ProgramFiles\Microsoft VS Code\Code.exe" -PathType Leaf)) {
    Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
} 

#endregion

#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
Register-AzResourceProvider -ProviderNamespace Microsoft.PolicyInsights
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration, Microsoft.PolicyInsights | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}

Start-Process -FilePath "$env:ProgramFiles\Microsoft VS Code\Code.exe" -ArgumentList "`"$CurrentDir`""