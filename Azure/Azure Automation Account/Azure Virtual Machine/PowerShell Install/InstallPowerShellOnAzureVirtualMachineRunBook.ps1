#requires -Version 3.0 -Modules Az.Accounts, Az.Compute, Az.Resources

Param(
    [Parameter(Mandatory = $true)]
    [String]
    $TagName,
    [Parameter(Mandatory = $true)]
    [String]
    $TagValue
)

#region Azure connection
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject $AzureContext
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject $AzureContext
#endregion

Write-Output "Tag: $TagName = $TagValue"
$vms = Get-AzResource -TagName $TagName -TagValue $TagValue -ResourceType 'Microsoft.Compute/virtualMachines' | Get-AzVM -Status | Where-Object -FilterScript { $_.Statuses.DisplayStatus -match "running" }
#$vms = Get-AzResource -TagName $TagName -ResourceType 'Microsoft.Compute/virtualMachines' | Get-AzVM -Status | Where-Object -FilterScript { $_.Statuses.DisplayStatus -match "running" }

$Jobs = @()
foreach ($vm in $vms) {
    Write-Output "Processing VM '$($vm.Name)' ..."
    [ScriptBlock]$ScriptBlock = {
        if (-not(Get-ChildItem -Path "$env:ProgramFiles\PowerShell" -Filter pwsh.exe -Recurse)) {
            Write-Host -Object  "[$env:COMPUTERNAME] Installing PowerShell 7+ ..."
            Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
        }
        else {
            $PowershellFullName = (Get-ChildItem -Path "$env:ProgramFiles\PowerShell" -Filter pwsh.exe -Recurse).FullName
            $Version = & $PowershellFullName -v
            Write-Host -Object "[$env:COMPUTERNAME] PowerShell 7+ is already installed (Installed Version: '$Version') ..."
        }
    }
    if (Get-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name) {
        Write-Warning -Message "[$($vm.Name)] A command is already running (Unable to start another one) ..."
    }
    else {
        Write-Output "[$($vm.Name)] Running the Powershell Script (PowerShell 7+ Test and Install if needed) ..."
        $Jobs += $vm | Invoke-AzVMRunCommand -CommandId 'RunPowerShellScript' -ScriptString $ScriptBlock -AsJob
    }
}
Write-Output "`Jobs Number: $($Jobs.Count)'"
Write-Output "`$Jobs:`r`n'$($Jobs | Out-String)'"
$Result = $Jobs | Receive-Job -Wait -AutoRemoveJob
foreach ($CurrentResult in $Result) {
    Write-Output "`Result:`r`n'$($CurrentResult.Value[0].Message | Out-String)'"
}
Write-Output "Runbook completed !"
    