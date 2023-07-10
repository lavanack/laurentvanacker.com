Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$Random = Get-Random -Minimum 0 -Maximum 1000
$Location = "eastus"
$ResourceGroupName = "rg-keyvault-posh-eu-{0:D3}" -f $Random
$KeyVaultName = "kv-keyvault-posh-eu-{0:D3}" -f $Random
#$UserPrincipalName  = (Get-AzContext).Account.Id

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Verbose "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}
#endregion

#region Resource Group Management
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
# Create Resource Groups and Storage Account for diagnostic
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion

#region KeyVault Management
#Create an Azure Key Vault
#From https://learn.microsoft.com/en-us/powershell/module/az.keyvault/new-azkeyvault?view=azps-10.0.0#-enabledfordeployment
$Vault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment #-EnablePurgeProtection
#As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru


#$KeyVaultName = "kv-kv-sep-eu-378905"
#From https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
#Adding a secret to Key Vault
$SecurePassword = New-RandomPassword -AsSecureString -Verbose
$Timestamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
$SecretName = $Timestamp

Write-Host -Object "Creating a secret in $KeyVaultName called '$SecretName' with the value '$SecurePassword' ..."
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue $SecurePassword -Verbose
Write-Host -Object "Done ..."

Write-Host -Object "Retrieving your secret called '$SecretName' from $KeyVaultName ..."
$Secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -AsPlainText -Verbose
Write-Host -Object "Your secret is '$Secret' ..."
Write-Host -Object "Done ..."

Write-Host -Object "Deleting your secret called '$SecretName' from $KeyVaultName ..."
Remove-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -Force -Verbose
Write-Host -Object "Done ..."

<#
#(Painful) Alternative to the above command. Using -AsPlainText is easier ;) 
$secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
try {
   $ClearTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
} finally {
   [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}
Write-Output $ClearTextPassword
#>
#endregion 
