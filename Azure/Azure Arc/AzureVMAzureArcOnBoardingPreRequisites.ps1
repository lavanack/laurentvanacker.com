#region Prerequisite for onboarding an Azure VM in Azure Arc
#From https://docs.microsoft.com/en-us/azure/azure-arc/servers/plan-evaluate-on-azure-virtual-machine
Get-Service WindowsAzureGuestAgent | Stop-Service -PassThru | Set-Service -StartupType Disabled
New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
#endregion
