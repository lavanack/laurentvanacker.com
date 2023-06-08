Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$Random                     = Get-Random -Minimum 0 -Maximum 1000
$Location                   = "eastus"
$ResourceGroupName          = "rg-keyvault-arm-eu-{0:D3}" -f $Random
$KeyVaultName               = "kv-keyvault-arm-eu-{0:D3}" -f $Random
$SQLServerARMTemplate       = Join-Path -Path $CurrentDir -ChildPath "SQLServerARMTemplate.json"
$VMARMTemplateUri           = "https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/quickstarts/microsoft.compute/vm-simple-windows/azuredeploy.json"
$VMARMTemplateParameterFile = Join-Path -Path $CurrentDir -ChildPath "VMARMTemplate.parameters.json"
$VMARMTemplateFile          = Join-Path -Path $CurrentDir -ChildPath "VMARMTemplate.json"
#$UserPrincipalName          = (Get-AzContext).Account.Id

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
#https://learn.microsoft.com/en-us/powershell/module/az.keyvault/new-azkeyvault?view=azps-10.0.0#-enabledfortemplatedeployment
$Vault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForTemplateDeployment 
#As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru

#From https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
#Adding a secret to Key Vault
$SecurePassword = New-RandomPassword -AsSecureString -Verbose
$secretName = "ExamplePassword"
#Setting the secret in the KeyVault
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue $SecurePassword
#Getting the secret in the KeyVault in clear text
$ClearTextPassword = Get-AzKeyVaultSecret -VaultName "$KeyVaultName" -Name $secretName -AsPlainText
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
Write-Host -Object "Clear Text Password retrieved from key vault: $ClearTextPassword"

#region ARM Template Management
#region SQL Server Deployment
$SQLServerARMTemplateParameterObject = @{
    vaultName = $KeyVaultName
    secretName = $secretName
    vaultResourceGroupName = $ResourceGroupName
    <#
    #The following parameters have default values (cf. ARM template)
    location = $Location
    vaultSubscription = $((Get-AzSubscription).Id)
    #>
}
#From https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/key-vault-parameter?tabs=azure-powershell#reference-secrets-with-dynamic-id
New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $SQLServerARMTemplate -TemplateParameterObject $SQLServerARMTemplateParameterObject -Verbose
#endregion

#region Azure VM Deployment #1
$SecurePasswordFromKeyVault = Get-AzKeyVaultSecret -VaultName "$KeyVaultName" -Name $secretName
$VMARMTemplateParameterObject = @{
    adminUsername = $env:USERNAME
    #Getting the password as securestring directly from the KeyVault (Be aware reverse engineering is possible to get clear text value from this code - cf. code commented as (painful) alterative some lines above)
    adminPassword = $SecurePasswordFromKeyVault.SecretValue
    #We are using the defaut values for the others parameters (cf. ARM template)
}

New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri $VMARMTemplateUri -TemplateParameterObject $VMARMTemplateParameterObject -Verbose
#endregion 

#region Azure VM Deployment #2
$SecurePasswordFromKeyVault = Get-AzKeyVaultSecret -VaultName "$KeyVaultName" -Name $secretName
$TimeStampedVMARMTemplateParameterFile = $VMARMTemplateParameterFile -replace ".json$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date)).json"
$TimeStampedVMARMTemplateParameterFile 
(Get-Content -Path $VMARMTemplateParameterFile -Encoding UTF8) -replace "<adminUsername>", $env:USERNAME`
                                                               -replace "<vmName>", "simple-vm2"`
                                                               -replace "<KeyVaultResourceGroupName>", $ResourceGroupName`
                                                               -replace "<SubscriptionID>", (Get-AzSubscription).Id`
                                                               -replace "<KeyVaultName>", $KeyVaultName`
                                                               -replace "<secretName>", $secretName`
                                                               | Set-Content -Path $TimeStampedVMARMTemplateParameterFile -Encoding UTF8
#From https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/key-vault-parameter?tabs=azure-powershell#reference-secrets-with-static-id
#From https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-tutorial-use-key-vault
#New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri $VMARMTemplateUri -TemplateParameterFile $TimeStampedVMARMTemplateParameterFile -Verbose
New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $VMARMTemplateFile -TemplateParameterFile $TimeStampedVMARMTemplateParameterFile -Verbose
Remove-Item -Path $TimeStampedVMARMTemplateParameterFile -Force
#endregion 
#endregion 