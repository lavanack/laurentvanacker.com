#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#    - On CONTOSODC : We have an AD security group for hosting all host pool VMs
$MSIXHosts = (Get-ADGroupMember -Identity MSIXHosts -Recursive).Name
$Session = New-PSSession -ComputerName $MSIXHosts
#Copying the PFX to all session hosts
$Session | ForEach-Object -Process { Copy-Item -Path $CurrentDir\MSIXDigitalSignature.pfx -Destination C:\ -ToSession $_ -Force}
Invoke-command -Session $Session -ScriptBlock {
    $SecurePassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
    #Adding the self-signed certificate to the Trusted People (To validate this certificate)
    Import-PfxCertificate C:\MSIXDigitalSignature.pfx -CertStoreLocation Cert:\LocalMachine\TrustedPeople\ -Password $SecurePassword
    #Removing the PFX file (useless now)
    Remove-Item -Path C:\MSIXDigitalSignature.pfx -Force
}

