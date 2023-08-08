# Azure Key Vault

Table of content:
- [Azure Key Vault](#azure-key-vault)
  - [Preliminary Remarks](#preliminary-remarks)
  - [Azure KeyVault Secret.ps1](#azure-keyvault-secretps1)
  - [Azure Key Vault with ARM.ps1](#azure-key-vault-with-armps1)
  - [Azure Key Vault for HTTPS and WinRM.ps1](#azure-key-vault-for-https-and-winrmps1)
  - [Azure Key Vault for HTTPS and WinRM with Service Endpoint.ps1](#azure-key-vault-for-https-and-winrm-with-service-endpointps1)
  - [Azure Key Vault for HTTPS and WinRM with Private Endpoint.ps1](#azure-key-vault-for-https-and-winrm-with-private-endpointps1)
  - [Azure Key Vault for Disk Encryption with Generated Customer Managed Key.ps1](#azure-key-vault-for-disk-encryption-with-generated-customer-managed-keyps1)
  - [Azure Key Vault for Disk Encryption with Customer Managed Key (New Certificate).ps1](#azure-key-vault-for-disk-encryption-with-customer-managed-key-new-certificateps1)
  - [Azure Key Vault for Disk Encryption with Customer Managed Key (Imported Certificate).ps1](#azure-key-vault-for-disk-encryption-with-customer-managed-key-imported-certificateps1)


## Preliminary Remarks

All scripts are standalone scripts and have a dedicated use case. 

***The scripts are not intended to be used in a production environment. The scripts are provided as is without any warranty. The scripts could be used as a starting point for further development.***

## Azure KeyVault Secret.ps1
The [Azure KeyVault Secret.ps1](<Azure KeyVault Secret.ps1>) is just a simple demo about how to handle secrets within an Azure Key Vault with Windows PowerShell.

## Azure Key Vault with ARM.ps1

The [Azure Key Vault with ARM.ps1](<Azure Key Vault with ARM.ps1>) is just a demo about how to handle secrets within an Azure Key Vault by using them in an ARM Template  (with Windows PowerShell). This script will deploy :
- 1 SQL Server: The [SQLServerARMTemplate.json ARM Template](<SQLServerARMTemplate.json>) is used.
- 1 Azure VM: The [VMARMTemplate.json ARM Template](<VMARMTemplate.json>) is used and the secret is dynamically recovered from the Azure KeyVault.
- 1 Azure VM: The [VMARMTemplate.json ARM Template](<VMARMTemplate.json>) and [VMARMTemplate.parameters.json parameter file](<VMARMTemplate.parameters.json>) are used and a reference to the secret added to the ARM Template dynamically.

## Azure Key Vault for HTTPS and WinRM.ps1
The [Azure Key Vault for HTTPS and WinRM.ps1](<Azure Key Vault for HTTPS and WinRM.ps1>) script uses a self-signed certificate to secure the HTTPS and WinRM endpoints of a Windows Server Azure VM. The certificate is stored in an Azure Key Vault and the Azure VM is configured to use the certificate from the Azure Key Vault. 
## Azure Key Vault for HTTPS and WinRM with Service Endpoint.ps1
The [Azure Key Vault for HTTPS and WinRM with Service Endpoint.ps1](<Azure Key Vault for HTTPS and WinRM with Service Endpoint.ps1>) is the same script as [Azure Key Vault for HTTPS and WinRM.ps1](<Azure Key Vault for HTTPS and WinRM.ps1>) but with a Service Endpoint for the Azure Key Vault.

## Azure Key Vault for HTTPS and WinRM with Private Endpoint.ps1
The [Azure Key Vault for HTTPS and WinRM with Private Endpoint.ps1](<Azure Key Vault for HTTPS and WinRM with Private Endpoint.ps1>) is the same script as [Azure Key Vault for HTTPS and WinRM.ps1](<Azure Key Vault for HTTPS and WinRM.ps1>) but with a Private Endpoint for the Azure Key Vault.

## Azure Key Vault for Disk Encryption with Generated Customer Managed Key.ps1
The [Azure Key Vault for Disk Encryption with Generated Customer Managed Key.ps1](<Azure Key Vault for Disk Encryption with Generated Customer Managed Key.ps1>) will use a generated key for encrypting the disks of a Windows Server Azure VM.

## Azure Key Vault for Disk Encryption with Customer Managed Key (New Certificate).ps1
The [Azure Key Vault for Disk Encryption with Customer Managed Key (New Certificate).ps1](<Azure Key Vault for Disk Encryption with Customer Managed Key (New Certificate).ps1>) will use a new self-signed certificate for encrypting the disks of a Windows Server Azure VM.

## Azure Key Vault for Disk Encryption with Customer Managed Key (Imported Certificate).ps1
The [Azure Key Vault for Disk Encryption with Customer Managed Key (Imported Certificate).ps1](<Azure Key Vault for Disk Encryption with Customer Managed Key (Imported Certificate).ps1>) will use an imported self-signed certificate (just generated some lines before in the script) for encrypting the disks of a Windows Server Azure VM.
