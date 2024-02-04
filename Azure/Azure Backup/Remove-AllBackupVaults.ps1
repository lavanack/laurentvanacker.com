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
#requires -Version 5 -Modules Az.Accounts, Az.Aks, Az.Compute, Az.DataProtection, Az.KubernetesConfiguration, Az.Network, Az.RecoveryServices, Az.ResourceGraph, Az.Resources, Az.Security, Az.Storage, ThreadJob


[CmdletBinding()]
param
(
    [switch] $All,
    [switch] $AsJob
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
    Write-Host -Object "Processing '$($CurrentBackupVault.Name)' Backup Vault ..." 
    $ScriptBlock = {
        param($CurrentBackupVault) 
        $ResourceGroupName = ($CurrentBackupVault.Id -split "/")[4]
        Write-Host -Object "`tRemoving Backup Instances ..." 
        Get-AzDataProtectionBackupInstance -ResourceGroupName $ResourceGroupName -VaultName $CurrentBackupVault.Name | Remove-AzDataProtectionBackupInstance -Verbose
        Write-Host -Object "`tRemoving Backup Policies ..." 
        Get-AzDataProtectionBackupPolicy -ResourceGroupName $ResourceGroupName -VaultName $CurrentBackupVault.Name | Remove-AzDataProtectionBackupPolicy
        Write-Host -Object "`tRemoving Resource Groups ..." 
        Get-AzResourceGroup "*$ResourceGroupName*" | Remove-AzResourceGroup -Force -AsJob | Wait-Job
    }
    if ($AsJob)
    {
        Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $CurrentBackupVault -StreamingHost $Host
    }
    else
    {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $CurrentBackupVault
    }
}
$Jobs | Wait-Job