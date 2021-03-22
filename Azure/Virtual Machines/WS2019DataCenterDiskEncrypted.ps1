Clear-Host

#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword
{
    [CmdletBinding(PositionalBinding=$false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 5,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $TimestampPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $TimestampPassword"
    if ($ClipBoard)
    {
        Write-Verbose "The password has beeen copied into the clipboard ..."
        $TimestampPassword | Set-Clipboard
    }
    if ($AsSecureString)
    {
        ConvertTo-SecureString -String $TimestampPassword -AsPlainText -Force
    }
    else
    {
        $TimestampPassword
    }
}
#endregion

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Defining variables for networking part
$Timestamp                  = "{0:yyyyMMddHHmmss}" -f (Get-Date)
$ResourceGroupName          = "myTempResourceGroup$Timestamp"
$Location                   = "FranceCentral"
$SubscriptionName           = "Microsoft Azure Internal Consumption"
$Image                      = "win2019datacenter"
$Size                       = "Standard_D2S_V3"
$VMName                     = "MyVm2019"
$KeyVaultName               = "MyKV$Timestamp"
#endregion

#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
#$SecurePassword = Read-Host -Prompt "Enter your Password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

# Login to your Azure subscription.
Connect-AzAccount
#$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *

#Step 1: Create Azure Resource Group
# Create Resource Groups and Storage Account for diagnostic
New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#Step 2: Create the VM
New-AzVM -Name $VMName -Credential $Credential -ResourceGroupName $ResourceGroupName -Image $Image -Size $Size

#Step 2: Create a Key Vault VM
$KeyVault = New-AzKeyvault -name $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $Location -EnabledForDiskEncryption

#Step 2: Encrypt the disk
#$KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName
Set-AzVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId -Force
Get-AzVmDiskEncryptionStatus -VMName $VMName -ResourceGroupName $ResourceGroupName

#Get the Public IP address dynamically
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.IpConfiguration.Id -like "*$VMName*" } | Select-Object -First 1

#Step 11: Start RDP Session
mstsc /v $PublicIP.IpAddress