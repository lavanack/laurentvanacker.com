Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$Random             = Get-Random -Minimum 0 -Maximum 100
$Location           = "eastus"
$ResourceGroupName  = "rg-keyvault-demo-eu-{0:D3}" -f $Random
$KeyVaultName       = "kv-keyvault-demo-eu-{0:D3}" -f $Random
$ClearTextPassword  = "P@ssw0rd"
#$UserPrincipalName  = (Get-AzContext).Account.Id
#From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/tutorial-secure-web-server

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding=$false)]
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
    if ($ClipBoard)
    {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString)
    {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else
    {
        $RandomPassword
    }
}
#endregion

#region Resource Group Management
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup)
{
    #Remove previously existing Azure Resource Group with the "AutomatedLab-rg" name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
# Create Resource Groups and Storage Account for diagnostic
New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion


#region KeyVault Management
#Create an Azure Key Vault
$Vault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,List,Set -PassThru

#From https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
#Adding a secret to Key Vault
#$SecurePassword = ConvertTo-SecureString $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -AsSecureString -Verbose

$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "ExamplePassword" -SecretValue $SecurePassword
$secret = Get-AzKeyVaultSecret -VaultName "$KeyVaultName" -Name "ExamplePassword" -AsPlainText
Write-Host -Object "ExamplePassword: $secret"
#endregion 
