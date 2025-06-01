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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Microsoft.PowerShell.ThreadJob

[CmdletBinding()]
Param (
    [Alias("Number")]
    [uint16] $VMNumber = 3,
    [ValidateScript({$_ -in (Get-AzLocation).Location})]
    [string] $Location = "eastus2",
    [switch] $RandomVMLocation
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
    Write-Host "The password is : $RandomPassword"
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

#region Main Code

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

$VMSize = "Standard_D2s_v3"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$AzureVMNameMaxLength = 15
$VirtualMachinePrefix = "vm"
$ResourceGroupPrefix = "rg"
$Project = "vm"
$Role = "rand"
#$DigitNumber = 4
$DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = $ResourceGroupName.ToLower()
#endregion

#region Defining credential(s)
$Username = $env:USERNAME
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

#region Quickly create a random Spot Windows VM(s)
$Jobs = 1..$VMNumber | ForEach-Object -Process {
    $ScriptBlock = {
        param(
            [Parameter(Mandatory = $true)]
            [string] $VMName, 
            [Parameter(Mandatory = $true)]
            [PSCredential] $Credential, 
            [Parameter(Mandatory = $true)]
            [string] $ResourceGroupName,
            [Parameter(Mandatory = $false)]
            [string] $Location
        )
        if ($Location) {
            New-AzVM -Name $VMName  -Credential $Credential -ResourceGroupName $ResourceGroupName -Image Win2022AzureEdition -Priority Spot -Location $Location #-Verbose
        }
        else {
            New-AzVM -Name $VMName  -Credential $Credential -ResourceGroupName $ResourceGroupName -Image Win2022AzureEdition -Priority Spot #-Verbose
        }
    }
    $VMName = "{0}{1:yyMMddHHmmss}" -f $VirtualMachinePrefix, (Get-Date)
    if ($RandomVMLocation) {
        $CurrentRandomVMLocation = (Get-AzLocation).Location | Get-Random
        Write-Host -Object "Creating '$VMName' VM in the '$ResourceGroupName' ResourceGroup (Location: $CurrentRandomVMLocation)"
        Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $VMName, $Credential, $ResourceGroupName, $CurrentRandomVMLocation #-StreamingHost $Host
    }
    else {
        Write-Host -Object "Creating '$VMName' VM in the '$ResourceGroupName' ResourceGroup (Location: $Location)"
        Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $VMName, $Credential, $ResourceGroupName #-StreamingHost $Host
    }
    Start-Sleep -Seconds 1
}
Write-Host -Object "Waiting Jobs complete"
#$null = $Jobs | Receive-Job -Wait -AutoRemoveJob
$null = $Jobs | Wait-Job
$null = $Jobs | Remove-Job

Write-Host -Object "Jobs completed"
#endregion
#endregion