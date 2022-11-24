sudo apt --fix-broken install -y
# Update the list of products
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt autoremove -y

#For network tools like netstat
#sudo apt install net-tools -y

#For SSH Client / Server
sudo apt install openssh-client -y
sudo apt install openssh-server -y

#allowing ssh in the firewall rules
#sudo systemctl status ssh
sudo ufw allow ssh

#Start : Old school install
# Download the Microsoft repository GPG keys
#wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# Register the Microsoft repository GPG keys
#sudo dpkg -i packages-microsoft-prod.deb

# Update the list of products
#sudo apt-get update

# Enable the "universe" repositories
#sudo add-apt-repository universe

# Install PowerShell
#sudo apt-get install powershell -y
#End : Old school install

#Easy install : https://www.thomasmaurer.ch/2019/07/how-to-install-and-update-powershell-7
#-includeide : Installs VSCode and VSCode PowerShell extension (only relevant to machines with a desktop environment)
#wget https://aka.ms/install-powershell.sh; sudo bash install-powershell.sh -includeide; rm install-powershell.sh
wget -O - https://aka.ms/install-powershell.sh | sudo bash

#To allow inbound connection from another machine via PowerShell Remoting via SSH tunneling
#Changing the SSH config (via RegEx) to meet our needs
sudo -- sh -c "echo 'RSAAuthentication yes' >> /etc/ssh/sshd_config"
sudo -- sh -c "echo 'Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile' >> /etc/ssh/sshd_config"

sudo sed -i 's/^\(#\?\)\(PubkeyAuthentication\|PasswordAuthentication\|RSAAuthentication\) \(yes\|no\)$/\2 yes/g' /etc/ssh/sshd_config

sudo service sshd restart

#starting PowerShell
sudo pwsh