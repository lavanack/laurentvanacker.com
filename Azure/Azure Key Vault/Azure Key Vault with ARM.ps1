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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Storage, Az.Resources, Az.KeyVault

[CmdletBinding()]
param
(
)

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


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}

$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$KeyVaultPrefix = "kv"
$ResourceGroupPrefix = "rg"
$VirtualMachinePrefix = "vm"

$Project = "kv"
$Role = "arm"
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length

Do {
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $KeyVaultName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $KeyVaultPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $KeyVaultName = $KeyVaultName.ToLower()
} While (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
       
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = $ResourceGroupName.ToLower()

#region Resource Group Management
$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Remove previously existing Azure Resource Group with the "AutomatedLab-rg" name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
#endregion


#region KeyVault Management
#Create an Azure Key Vault
#https://learn.microsoft.com/en-us/powershell/module/az.keyvault/new-azkeyvault?view=azps-10.0.0#-enabledfortemplatedeployment
$Vault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForTemplateDeployment #-EnablePurgeProtection 
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
    vaultName              = $KeyVaultName
    secretName             = $secretName
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