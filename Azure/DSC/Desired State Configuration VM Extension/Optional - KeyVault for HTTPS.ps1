Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$ResourcePrefix     = "dscvmext"
$ResourceGroupName  = "$ResourcePrefix-rg-$Location"
$Location           = "eastus"
$VMName 	        = "{0}ws2019" -f $ResourcePrefix
$VMName             = $VMName.Substring(0, [system.math]::min(15, $VMName.Length))
$FQDN               = "$VMName.$Location.cloudapp.azure.com".ToLower()
$KeyVaultName       = "{0}keyvault{1:D3}" -f $ResourcePrefix, $(Get-Random -Minimum 1 -Maximum 1000)
$CertificateName    = "mycert"
#From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/tutorial-secure-web-server

#region Adding the DSC extension
$VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

#Create an Azure Key Vault
New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment

#Generate a certificate and store in Key Vault
$Policy = New-AzKeyVaultCertificatePolicy -SubjectName "CN=www.contoso.com" -SecretContentType "application/x-pkcs12" -IssuerName Self -ValidityInMonths 12
Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $Policy
While (-not(Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName))
{
    Write-Host "Sleeping 30 seconds ..."
    Start-Sleep 30
}
#Add a certificate to VM from Key Vault
$CertUrl=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName).id
$VaultId=(Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName).ResourceId
$VM = Add-AzVMSecret -VM $VM -SourceVaultId $VaultId -CertificateStore "My" -CertificateUrl $CertUrl
$VM | Update-AzVM -Verbose
#endregion 

#Configure IIS manually to set the HTTPS binding

#Get the Public IP address dynamically
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.IpConfiguration.Id -like "*$VMName*" } | Select-Object -First 1

#Browsing to the IIS Web Site via HTTPS
Start-Process "https://$FQDN"
