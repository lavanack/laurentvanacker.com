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

$vms = Get-AzResource -TagName $TagName -TagValue $TagValue -ResourceType 'Microsoft.Compute/virtualMachines' | Get-AzVM -Status | Where-Object -FilterScript { $_.Statuses.DisplayStatus -match "running" }

$Jobs = foreach ($vm in $vms) {
    Write-Output "Processing VM '$($vm.Name)' ..."
    [ScriptBlock]$ScriptBlock = {
        if (-not(Get-ChildItem -Path "$env:ProgramFiles\PowerShell" -Filter pwsh.exe -Recurse)) {
            Write-Output "[$($vm.Name)] Installing PowerShell 7+ ..."
            Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
        }
        else {
            $PowershellFullName = (Get-ChildItem -Path "C:\Program Files\PowerShell" -Filter pwsh.exe -Recurse).FullName
            $Version = & $PowershellFullName -v
            Write-Output "[$($vm.Name)] PowerShell 7+ is already installed (Installed Version: '$Version')..."
        }
    }
    $vm | Invoke-AzVMRunCommand -CommandId 'RunPowerShellScript' -ScriptString $ScriptBlock -AsJob
}
$Jobs | Receive-Job -Wait -AutoRemoveJob
