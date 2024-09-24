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

[CmdletBinding()]
Param (
)

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#$LogDir = "~\Documents\"
$LogDir = [Environment]::GetFolderPath("MyDocuments")
Set-Location -Path $CurrentDir

$Global:MaximumFunctionCount = 32768
try { while (Stop-Transcript) {} } catch {}
#Get-Job | Remove-Job -Force
Get-Job | Where-Object -FilterScript {$_.PSJobTypeName -eq "ThreadJob"} | Remove-Job -Force -Verbose
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -Force -Verbose

<#
#>
Connect-MgGraph -NoWelcome
try { 
    $null = Get-AzAccessToken -ErrorAction Stop
} catch {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
}

#region Dirty Cleanup
try {
    Get-ChildItem -Path $LogDir -Filter HostPool_* -Directory | Remove-Item -Force -Recurse -ErrorAction Stop
}
catch {
    Stop-Process -Name notepad, powershell* -Force -ErrorAction Ignore
    Get-ChildItem -Path $LogDir -Filter HostPool_* -Directory | Remove-Item -Force -Recurse -ErrorAction Stop
}

Get-AzResourceGroup | Where-Object -FilterScript { $_.ResourceGroupName -match '^rg-avd-.*-(poc)-.*-\d+'} | Remove-AzResourceGroup -AsJob -Force -Verbose
Get-MgBetaGroup -Filter "DisplayName eq 'No-MFA Users'" | ForEach-Object -Process { Remove-MgBetaGroup -GroupId $_.Id -Verbose }
Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '[AVD] Require multifactor authentication for all users'" | ForEach-Object -Process { Remove-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $_.Id -Verbose }
Get-AzKeyVault -InRemovedState | Remove-AzKeyVault -InRemovedState -AsJob -Force
& '.\Clear-WindowsCredentials.ps1' -Verbose
#endregion

#$DebugPreference = "Continue"
& '.\New-AzAvdHostPoolSetup.ps1' -LogDir $LogDir -Verbose -AsJob
#$DebugPreference = "SilentlyContinue"

<#
#region for openning the fileshares for FSLogix and MSIX
$storageAccounts = Get-AzStorageAccount
# Loop through each storage account
foreach ($storageAccount in $storageAccounts)
{
    # Get the list of file shares in the storage account
    $AzStorageShare = Get-AzStorageShare -Context $storageAccount.Context -ErrorAction Ignore
    $StorageShare = $AzStorageShare | Where-Object  -FilterScript {$_.Name -in "profiles", "msix"}
    if ($null -ne $StorageShare) {
        start $("\\{0}.file.{1}\{2}" -f $StorageShare.context.StorageAccountName, ($StorageShare.context.EndPointSuffix -replace "/"), $StorageShare.Name)
    }
}
#endregion
#> 