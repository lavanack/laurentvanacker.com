#Installing PowerShell
wget https://aka.ms/install-powershell.sh; sudo bash install-powershell.sh; rm install-powershell.sh

#https://github.com/orgs/PowerShell/discussions/15310
sudo pwsh -Command 'Install-Module -Name PSWSMan -Scope AllUsers -Force'
sudo pwsh -Command 'Install-WSMan'
sudo pwsh -Command 'Install-Module -Name Az.Accounts, Az.Compute, Az.PolicyInsights, Az.Resources, Az.Ssh, Az.Storage, GuestConfiguration -Scope AllUsers -Force'

sudo pwsh -File './4 - AzureAutomanageMachineConfiguration.ps1'
