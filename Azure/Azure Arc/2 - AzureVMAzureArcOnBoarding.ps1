#region Disabling IE Enhanced Security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force
#endregion

#Installing the NuGet Provider
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Get-PackageProvider -Name Nuget -ForceBootstrap -Force
Install-Module -Name Az.ConnectedMachine, Az.Compute, Az.Resources -Repository PSGallery -Force
Connect-AzAccount
Get-AzSubscription | Out-GridView -PassThru | Select-AzSubscription
$resourceGroupName = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName

Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Get-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute | Where-Object RegistrationState -eq Registered

#region Azure Arc OnBoarding
#region Prerequisite for onboarding an Azure VM in Azure Arc
#From https://docs.microsoft.com/en-us/azure/azure-arc/servers/plan-evaluate-on-azure-virtual-machine
Get-Service WindowsAzureGuestAgent | Stop-Service -PassThru | Set-Service -StartupType Disabled
New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
#az
Connect-AzConnectedMachine -ResourceGroupName $resourceGroupName -Location $resourceGroup.Location
#endregion
