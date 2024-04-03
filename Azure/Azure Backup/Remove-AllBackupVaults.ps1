<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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
##requires -Version 5 -Modules Az.Accounts, Az.DataProtection


[CmdletBinding()]
param
(
    [switch] $All,
    [switch] $AsJob,
    [switch] $Wait
)


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Login to your Azure subscription.
$SubscriptionName = "Cloud Solution Architect"
While (-not((Get-AzContext).Subscription.Name -eq $SubscriptionName)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}
#endregion

if ($All) {
    $BackupVaults = Get-AzDataProtectionBackupVault
} 
else {
    $BackupVaults = Get-AzDataProtectionBackupVault | Out-GridView -PassThru
}

$Jobs = foreach ($CurrentBackupVault in $BackupVaults) {
    Write-Host -Object "Removing '$($CurrentBackupVault.Name)' Backup Vault ..." 
    $ScriptBlock = {
        param($CurrentBackupVault) 
        $ResourceGroupName = ($CurrentBackupVault.Id -split "/")[4]
        Write-Host -Object "`t[$($CurrentBackupVault.Name)] Removing Backup Instances ..." 
        Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $CurrentBackupVault.Name | Remove-AzDataProtectionBackupInstance -Verbose
        Write-Host -Object "`t[$($CurrentBackupVault.Name)] Removing Backup Policies ..." 
        Get-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $CurrentBackupVault.Name | Remove-AzDataProtectionBackupPolicy -Verbose
        Write-Host -Object "`t[$($CurrentBackupVault.Name)] Removing Resource Groups ..." 
        if ($Wait) {
            Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob -Verbose | Wait-Job
        } 
        else {
            Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob -Verbose
        }
    }
    if ($AsJob)
    {
        Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $CurrentBackupVault -Verbose | Out-Null #-StreamingHost $Host
    }
    else
    {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $CurrentBackupVault -Verbose
    }
}
if ($Wait) {
    $Jobs | Wait-Job
}