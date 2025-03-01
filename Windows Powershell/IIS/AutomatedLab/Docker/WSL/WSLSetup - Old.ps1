Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

Set-WinUserLanguageList -LanguageList fr-fr -Force

#wsl --install -d Ubuntu-24.04 --web-download --no-launch
$Results = Invoke-RestMethod -Uri https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json
$LatestUbuntuDistribution = $Results.Distributions | Where-Object -FilterScript {$_.Name -match "^Ubuntu"} | Sort-Object -Property Name -Descending | Select-Object -First 1
$LatestUbuntuDistribution.Amd64PackageUrl
#From https://github.com/microsoft/WSL/issues/3369
$OutFile = "~/$($LatestUbuntuDistribution.Name).appx"
$distro = ($LatestUbuntuDistribution.Name -replace "\W").ToLower()
Invoke-WebRequest -Uri $LatestUbuntuDistribution.Amd64PackageUrl -OutFile $OutFile -UseBasicParsing
Add-AppxPackage -Path $OutFile
#RefreshEnv


$username = "ubuntu"
$password = "ubuntu"

Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro install --root" -Wait -RedirectStandardError install.stderr.txt -RedirectStandardOutput install.stdout.txt
# create user account
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro run useradd -m '$username'" -Wait -RedirectStandardError useradd.stderr.txt -RedirectStandardOutput useradd.stdout.txt
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro run ""echo ${username}:${password} | chpasswd""" -Wait -RedirectStandardError chpasswd.stderr.txt -RedirectStandardOutput chpasswd.stdout.txt
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro run chsh -s /bin/bash '$username'" -Wait -RedirectStandardError chsh.stderr.txt -RedirectStandardOutput chsh.stdout.txt
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro run usermod -aG adm,cdrom,sudo,dip,plugdev '$username'" -Wait -RedirectStandardError usermod.stderr.txt -RedirectStandardOutput usermod.stdout.txt

Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro config --default-user '$username'" -Wait -RedirectStandardError config.stderr.txt -RedirectStandardOutput config.stdout.txt

# apt install -y isn't enough to be truly noninteractive
$env:DEBIAN_FRONTEND = "noninteractive"
$env:WSLENV += ":DEBIAN_FRONTEND"

# update software
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro run sudo apt-get update && sudo apt-get full-upgrade -y && sudo apt-get autoremove -y && sudo apt-get autoclean" -Wait -RedirectStandardError apt-get .stderr.txt -RedirectStandardOutput apt-get .stdout.txt
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$distro config --default-user '$username'" -Wait -RedirectStandardError config.stderr.txt -RedirectStandardOutput config.stdout.txt
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "wsl --shutdown" -Wait -RedirectStandardError shutdown.stderr.txt -RedirectStandardOutput shutdown.stdout.txt