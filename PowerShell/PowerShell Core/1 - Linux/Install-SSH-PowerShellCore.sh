# Update the list of products
sudo apt-get update -y
#sudo apt-get upgrade -y
#sudo apt autoremove -y

#For network tools like netstat
sudo apt install net-tools -y

#For SSH Client / Server
sudo apt install openssh-client -y
sudo apt install openssh-server -y

#sudo systemctl status ssh
#sudo ufw allow ssh


# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb

# Update the list of products
sudo apt-get update

# Enable the "universe" repositories
sudo add-apt-repository universe

# Install PowerShell from the "universe" repositories
sudo apt-get install powershell -y

#cd ~
#mkdir -p .ssh
#chmod 700 .ssh
#cat /tmp/lavanack_rsa.pub >> .ssh/authorized_keys
#chmod 640 .ssh/authorized_keys
#sudo service sshd restart

sudo -- sh -c "echo 'RSAAuthentication yes' >> /etc/ssh/sshd_config"
sudo -- sh -c "echo 'Subsystem powershell /usr/bin/pwsh -sshs -NoLogo -NoProfile' >> /etc/ssh/sshd_config"

sudo sed -i 's/^\(#\?\)\(PubkeyAuthentication\|PasswordAuthentication\|RSAAuthentication\) \(yes\|no\)$/\2 yes/g' /etc/ssh/sshd_config

sudo service sshd restart
