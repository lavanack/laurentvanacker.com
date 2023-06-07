Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$ResourcePrefix     = "dscvmext"
$VM = Get-AzVM -Name $ResourcePrefix* 
$Location           = $VM.Location
$ResourceGroupName  = $VM.ResourceGroupName
$VMName 	        = $VM.Name
$FQDN               = "$VMName.$Location.cloudapp.azure.com".ToLower()
$KeyVaultName       = "{0}keyvault" -f $VMName
$CertificateName    = "mycert"
#$UserPrincipalName  = (Get-AzContext).Account.Id
#From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/tutorial-secure-web-server

#region KeyVault Management

#Create an Azure Key Vault
$Vault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,List,Set -PassThru

#Generate a certificate and store in Key Vault
$Policy = New-AzKeyVaultCertificatePolicy -SubjectName "CN=$FQDN" -SecretContentType "application/x-pkcs12" -IssuerName Self -ValidityInMonths 12
Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $Policy

While (-not((Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName).SecretId)) 
{
    Write-Host "Sleeping 30 seconds ..."
    Start-Sleep 30
}

#Add a certificate to VM from Key Vault
#$CertUrl=(Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName).SecretId
#$VaultId=(Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName).ResourceId

$CertUrl=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName).id
$VaultId=$Vault.ResourceId
$VM = Add-AzVMSecret -VM $VM -SourceVaultId $VaultId -CertificateStore "My" -CertificateUrl $CertUrl
$VM | Update-AzVM -Verbose
#endregion 

#Configure IIS manually to set the HTTPS binding

#Get the Public IP address dynamically
#$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.IpConfiguration.Id -like "*$VMName*" } | Select-Object -First 1

#Browsing to the IIS Web Site via HTTPS
#Start-Process "https://$FQDN"

mstsc /v $FQDN
