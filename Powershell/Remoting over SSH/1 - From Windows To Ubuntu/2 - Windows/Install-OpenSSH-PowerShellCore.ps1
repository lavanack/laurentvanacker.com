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
#Replace the following lines with your own values
$UbuntuServer="ubuntu.mshome.net"
$UbuntuUser="administrator"
$PassPhrase = ""

#region Install OpenSSH Client & Server
# Install the OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
#endregion

<#
#region Install Powershell Core : Manual Install
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$uri = 'https://github.com/PowerShell/PowerShell/releases/download/v7.0.2/PowerShell-7.0.2-win-x64.msi'
$MSIPackageName = Split-Path -Path $uri -Leaf
$MSIPackageFullName = Join-Path -Path $CurrentDir -ChildPath $MSIPackageName
if (-not(Test-Path -Path $MSIPackageFullName))
{
    Invoke-WebRequest -Uri $uri -outFile $MSIPackageFullName -UseBasicParsing -Verbose
}

#Start-Process -FilePath $MSIPackageName -ArgumentList "/passive" -Wait
Start-Process msiexec.exe -ArgumentList "/package PowerShell-7.0.2-win-x64.msi /passive ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1" -Wait
#endregion
#>
#region Install Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
#endregion

#New-Item -ItemType SymbolicLink -Path "C:\pwsh" -Target $($(Get-Command pwsh).Source | Split-Path -Parent)
New-Item -ItemType SymbolicLink -Path "C:\pwsh" -Target $((Get-ChildItem -Path $env:SystemDrive\ -File -Filter pwsh.exe -Recurse -ErrorAction SilentlyContinue).DirectoryName)

#region Configure OpenSSH Server
# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'
# Starting the SSH Service
Start-Service sshd
# Confirm the Firewall rule is configured. It should be created automatically by setup. 
# There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
# If the firewall does not exist, create one
if (-not(Get-NetFirewallRule "OpenSSH-Server-In-TCP"))
{
	New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH-Server-In-TCP' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}

#Changing the SSH config (via RegEx) to meet our needs
$SshdConfig = Get-Content -Path "$env:ProgramData\ssh\sshd_config"
$SshdConfig += "RSAAuthentication yes"
$SshdConfig = $SshdConfig -replace "(#?)(PubkeyAuthentication|PasswordAuthentication|RSAAuthentication)(\s+)(yes|no)", '$2$3yes'
$SshdConfig = $SshdConfig -replace "^(Subsystem.*)$", "`$0`r`nSubsystem powershell C:\pwsh\pwsh.exe -sshs -NoLogo -NoProfile"

# The two command lines below are for disabling  the use of a dedicated administrators_authorized_keys file for administrators 
# If you want to use this shared file (administrators_authorized_keys) you need to comment the 2 lines below and to fix the ACL with the 3 lines below  
# From https://stackoverflow.com/questions/16212816/setting-up-openssh-for-windows-using-public-key-authentication
# cmd : icacls C:\ProgramData\ssh\administrators_authorized_keys /remove "NT AUTHORITY\Authenticated Users" 
# cmd : icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r
# Powershell : get-acl C:\ProgramData\ssh\ssh_host_dsa_key | set-acl C:\ProgramData\ssh\administrators_authorized_keys
# Instead we will use dedicated authorized_keys per user 
$SshdConfig = $SshdConfig -replace "(#?)(Match Group administrators)", '#$2'
$SshdConfig = $SshdConfig -replace "(\s+)(AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys)", '#$1$2'

#$SshdConfig += "Subsystem powershell C:\pwsh\pwsh.exe -sshs -NoLogo -NoProfile"
$SshdConfig | Out-File "$env:ProgramData\ssh\sshd_config" -Encoding utf8

Restart-Service sshd
#endregion

#region key generation
$PrivateSSHRSAKeyFolder = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh"
$PrivateSSHRSAKey = Join-Path -Path $PrivateSSHRSAKeyFolder -ChildPath "id_rsa"
$PublicSSHRSAKey = "$PrivateSSHRSAKey.pub"

New-Item -Path $PrivateSSHRSAKeyFolder -ItemType Directory -Force
Remove-Item $PrivateSSHRSAKey, $PublicSSHRSAKey -ErrorAction SilentlyContinue -Force 

Start-Process -FilePath "$env:comspec" -ArgumentList "/c ssh-keygen -f $PrivateSSHRSAKey -t rsa -q -N `"$PassPhrase`"" -Wait


# Replace /k by /C for closing automatically the windows prompt. With /k you need to close the windows by yourself

#Checking the SSH connectivity
#You will be prompted for entering the password for connecting to the Ubuntu server. It will be the two only times
# Start-Process -FilePath "$env:comspec" -ArgumentList "/k ssh -o StrictHostKeyChecking=no $UbuntuUser@$UbuntuServer" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/k scp -o StrictHostKeyChecking=no $PublicSSHRSAKey $($UbuntuUser)@$($UbuntuServer):/tmp/$($env:USERNAME)_rsa.pub" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/k ssh -o StrictHostKeyChecking=no $UbuntuUser@$UbuntuServer `"cd ~ && mkdir -p .ssh && chmod 700 .ssh && cat /tmp/$($env:USERNAME)_rsa.pub >> .ssh/authorized_keys && chmod 640 .ssh/authorized_keys && sudo service sshd restart && rm /tmp/$($env:USERNAME)_rsa.pub`"" -Wait
#endregion

#region testing PowerShell remoting via SSH tunnelling (without password prompt)
$WindowsPwshCmdLine = "Invoke-Command -ScriptBlock { `"Hello from `$(hostname)`" } -UserName $UbuntuUser -HostName $UbuntuServer"
Write-Host "[CLIPBOARD] $WindowsPwshCmdLine"

#Copy the line into the clipboard and just paste it in a new PowerShell Core host (opened at the next line). It should work like a charm :)
Set-Clipboard -Value $WindowsPwshCmdLine

#Starting a new PowerShell Core host and paste the previously code copied into the clipboard
Start-Process pwsh
#endregion