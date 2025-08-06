#requires -Version 5 -RunAsAdministrator 
trap {
    Write-Host "Stopping Transcript ..."
    Stop-Transcript
} 
Clear-Host


$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$TranscriptFile = $CurrentScript -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
Set-Location -Path $CurrentDir
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

Set-WinUserLanguageList -LanguageList fr-fr -Force
#wsl --update #--pre-release 

#wsl --install -d Ubuntu-24.04 --web-download --no-launch
$Results = Invoke-RestMethod -Uri https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json
$LatestUbuntuDistribution = $Results.Distributions | Where-Object -FilterScript {$_.Name -match "^Ubuntu"} | Sort-Object -Property Name -Descending | Select-Object -First 1
#$LatestUbuntuDistribution.Amd64PackageUrl
#From https://github.com/microsoft/WSL/issues/3369
$OutFile = Join-Path -Path $env:TEMP -ChildPath "$($LatestUbuntuDistribution.Name).appx"
$distro = ($LatestUbuntuDistribution.Name -replace "\W").ToLower()
#Checking if the Linux distribution already installed
if (($(& wsl -l -q | Out-String) -replace "\W") -notmatch "^$distro$")
{
    if (-not(Test-Path -Path $OutFile -PathType Leaf)) {
        Invoke-WebRequest -Uri $LatestUbuntuDistribution.Amd64PackageUrl -OutFile $OutFile -UseBasicParsing
    }
    Add-AppxPackage -Path $OutFile
}
#RefreshEnv

$Results = Invoke-RestMethod -Uri https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json
$LatestUbuntuDistribution = $Results.Distributions | Where-Object -FilterScript {$_.Name -match "^Ubuntu"} | Sort-Object -Property Name -Descending | Select-Object -First 1
$distro = ($LatestUbuntuDistribution.Name -replace "\W").ToLower()

$username = "ubuntu"
$password = "ubuntu"

& $distro install --root
# create user account
& $distro run useradd -m "$username"
& $distro run "echo ${username}:${password} | chpasswd"
& $distro run chsh -s /bin/bash "$username"
& $distro run usermod -aG adm,cdrom,sudo,dip,plugdev "$username"

& $distro config --default-user "$username"

# apt install -y isn't enough to be truly noninteractive
$env:DEBIAN_FRONTEND = "noninteractive"
$env:WSLENV += ":DEBIAN_FRONTEND"

# update software
& $distro run sudo apt-get update -y
& $distro run sudo apt-get full-upgrade -y 
& $distro run sudo apt-get autoremove -y 
& $distro run sudo apt-get autoclean
& $distro config --default-user "$username"

& $distro sudo rm /etc/resolv.conf
& $distro sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
& $distro sudo bash -c 'echo "[network]" > /etc/wsl.conf'
& $distro sudo bash -c 'echo "generateResolvConf = false" >> /etc/wsl.conf'
& $distro sudo chattr +i /etc/resolv.conf

& $distro sudo apt-get update -y
& $distro sudo apt-get install -y apt-transport-https  ca-certificates curl software-properties-common
& $distro curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
& $distro sudo apt-key fingerprint 0EBFCD88

& $distro sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y
& $distro sudo apt-get update -y
& $distro sudo apt-get install -y docker-ce

& $distro sudo usermod -aG docker "$username"

& $distro # automatiser le démarrage du démon docker
& $distro echo "sudo service docker status || sudo service docker start" >> ~/.bashrc

& $distro # désactiver la demande de mot de passe pour gérer le service docker
& $distro echo "%docker ALL=(ALL) NOPASSWD: /usr/sbin/service docker *" | sudo tee -a /etc/sudoers

& $distro sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
& $distro sudo chmod +x /usr/local/bin/docker-compose

wsl --shutdown

Stop-Transcript