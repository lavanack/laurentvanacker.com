#Installing PowerShell
wget https://aka.ms/install-powershell.sh; sudo bash install-powershell.sh; rm install-powershell.sh

#Installing Visual Studio Code
#sudo snap install --classic code
#code --version

#https://github.com/orgs/PowerShell/discussions/15310
sudo pwsh -Command 'Install-Module -Name PSWSMan -Scope AllUsers -Force'
sudo pwsh -Command 'Install-WSMan -Distribution ubuntu18.04'

sudo pwsh -File './2 - Prerequisites.ps1'
sudo pwsh -File './3 - AzureAutomanageMachineConfiguration.ps1'
