﻿#Installing the NuGet Provider
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az.Accounts, Az.Compute, Az.PolicyInsights, Az.Resources, Az.Ssh, Az.Storage -Force
#Install-Module -Name Microsoft.PowerShell.GraphicalTools -Force
Install-Module -Name GuestConfiguration -Force
Install-Module PSDesiredStateConfiguration -AllowPreRelease -RequiredVersion 3.0.0-beta1 -Force
Install-Module nxtools -Force

#Connection to Azure and Subscription selection
if (-not(Get-AzContext)) {
    Connect-AzAccount -UseDeviceAuthentication
    #Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}

#From https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
Register-AzResourceProvider -ProviderNamespace Microsoft.PolicyInsights
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration, Microsoft.PolicyInsights | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Start-Sleep -Seconds 10
}