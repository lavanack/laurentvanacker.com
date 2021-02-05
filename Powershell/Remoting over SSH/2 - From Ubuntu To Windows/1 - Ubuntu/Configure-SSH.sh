PrivateSSHRSAKey=~/.ssh/id_rsa
PublicSSHRSAKey=${PrivateSSHRSAKey}.pub
WindowsUser=contoso\\administrator
WindowsServer=win10.mshome.net
Username=$(whoami)
Passphrase=""
#Dedicated authorized file per user
AuthorizedKeys=.ssh/authorized_keys
#shared authorized file for administrators
#AuthorizedKeys="%ProgramData%\ssh\administrators_authorized_keys"
sudo apt install xclip -y

rm $PublicSSHRSAKey, $PrivateSSHRSAKey -f

ssh-keygen -f $PrivateSSHRSAKey -t rsa -q -N "$Passphrase"

#For testing the SSH connection
#ssh -o StrictHostKeyChecking=no $WindowsUser@$WindowsServer
#You will be prompted for entering the password for connecting to the Windows server. It will be the two only times
scp -o StrictHostKeyChecking=no $PublicSSHRSAKey $WindowsUser@$WindowsServer:${Username}_rsa.pub
ssh -o StrictHostKeyChecking=no $WindowsUser@$WindowsServer "type ${Username}_rsa.pub >> $AuthorizedKeys && net stop sshd && net start sshd && del ${Username}_rsa.pub"

#Copy the line into the clipboard and just paste it in a new PowerShell Core host (opened at the next line). It should work like a charm :)
echo "Invoke-Command -ScriptBlock { \"Hello from \$(hostname)\" } -UserName $WindowsUser -HostName $WindowsServer" | xclip -selection clipboard 

#To avoid an access denied on this file
sudo chown -R $UserName ~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt

#Starting a new PowerShell Core host and paste the previously code copied into the clipboard
pwsh