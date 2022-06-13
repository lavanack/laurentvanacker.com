#region Prerequisite for onboarding an Azure VM in Azure Arc
#From https://docs.microsoft.com/en-us/azure/azure-arc/servers/plan-evaluate-on-azure-virtual-machine
Get-Service WindowsAzureGuestAgent | Stop-Service -PassThru | Set-Service -StartupType Disabled
New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
#endregion

#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Install-Module -Name Az.ConnectedMachine, Az.Compute, Az.Resources -Repository PSGallery -Force

#region Logging to Azure and selecting the subscription
Connect-AzAccount
Get-AzSubscription | Out-GridView -PassThru | Select-AzSubscription
#endregion

$resourceGroupName = (Get-AzVM -Name $env:COMPUTERNAME).ResourceGroupName
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
Connect-AzConnectedMachine -ResourceGroupName $resourceGroupName -Location $resourceGroup.Location