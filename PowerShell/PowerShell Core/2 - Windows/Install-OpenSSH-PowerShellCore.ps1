<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free
right to use and modify the Sample Code and to reproduce and distribute
the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software
product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#From https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse

#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$UbuntuServer="ubuntu.mshome.net"
$UbuntuUser="lavanack"

#Region Install Powershell Core
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$uri = 'https://github.com/PowerShell/PowerShell/releases/download/v7.0.0/PowerShell-7.0.0-win-x64.msi'
$outFile = $uri.Split("/")[-1]
New-Item -Path C:\Temp -Type Directory -Force
Invoke-WebRequest -Uri $uri -OutFile "C:\Temp\$outFile" -UseBasicParsing -Verbose
Set-Location C:\Temp
Start-Process -FilePath $outFile -ArgumentList "/passive" -Wait

#New-Item -ItemType SymbolicLink -Path "C:\pwsh" -Target $($(Get-Command pwsh).Source | Split-Path -Parent)
New-Item -ItemType SymbolicLink -Path "C:\pwsh" -Target $((Get-ChildItem -Path $env:SystemDrive\ -File -Filter pwsh.exe -Recurse -ErrorAction SilentlyContinue).DirectoryName)

#endregion

#Region Install OpenSSH Client & Server
# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
#End region

#Region Configure OpenSSH Server
# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'
# Starting the SSH Service
Start-Service sshd
# Confirm the Firewall rule is configured. It should be created automatically by setup. 
# There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
# If the firewall does not exist, create one
if (-not(Get-NetFirewallRule "OpenSSH-Server-In-TCP"))
{
	New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH-Server-In-TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
#End region

$SshdConfig = Get-Content -Path "$env:SystemRoot\System32\OpenSSH\sshd_config_default"
$SshdConfig += "RSAAuthentication yes"
$SshdConfig += "Subsystem powershell C:\pwsh\pwsh.exe -sshs -NoLogo -NoProfile"
$SshdConfig = $SshdConfig -replace "(#?)(PubkeyAuthentication|PasswordAuthentication|RSAAuthentication)(\s+)(yes|no)", '$2$3yes'
$SshdConfig | Out-File "C:\Windows\System32\OpenSSH\sshd_config"

Restart-Service sshd
$PrivateSSHRSAKeyFolder = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
$PrivateSSHRSAKey = Join-Path -Path $PrivateSSHRSAKeyFolder -ChildPath "id_rsa"
$PublicSSHRSAKey = "$PrivateSSHRSAKey.pub"

New-Item -Path $PrivateSSHRSAKeyFolder -ItemType Directory -Force
Remove-Item $PrivateSSHRSAKey, $PublicSSHRSAKey -ErrorAction SilentlyContinue -Force 

ssh-keygen -f $PrivateSSHRSAKey --% -t rsa -q -N ""

#ssh-add.exe $PrivateSSHRSAKey
#Checking the SSH connectivity
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c ssh -o StrictHostKeyChecking=no $UbuntuUser@$UbuntuServer"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c scp -o StrictHostKeyChecking=no $PublicSSHRSAKey $($UbuntuUser)@$($UbuntuServer):/tmp/lavanack_rsa.pub"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c ssh -o StrictHostKeyChecking=no $UbuntuUser@$UbuntuServer `"cd ~ && mkdir -p .ssh && chmod 700 .ssh && cat /tmp/lavanack_rsa.pub >> .ssh/authorized_keys && chmod 640 .ssh/authorized_keys && sudo service sshd restart`""
#End region

$PwshCmdLine = "Invoke-Command -ScriptBlock { `"Hello from `$(hostname)`" } -UserName lavanack -HostName ubuntu.mshome.net #-KeyFilePath $PrivateSSHRSAKey"
Write-Host "[CLIPBOARD] $PwshCmdLine"

#Copy 
Set-Clipboard -Value $PwshCmdLine

#Paste the output and run it from PowerShell Core
