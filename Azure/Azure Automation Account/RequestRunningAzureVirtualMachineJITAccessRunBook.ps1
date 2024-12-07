#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
)

$IP  = Get-AutomationVariable -Name IP


#region Azure connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
$AzureContext = (Connect-AzAccount -Identity).context
Write-Output -InputObject $AzureContext
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
Write-Output -InputObject $AzureContext
#endregion

#region Variable definition(s)
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines.Id
$VM = $(Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "running" })
#endregion

$AzJitNetworkAccessPolicy = foreach ($CurrentVMJitNetworkAccessPolicyVM in $VM) {
    Write-Output -InputObject "VM : $($CurrentVMJitNetworkAccessPolicyVM.Name)"
    if ($CurrentVMJitNetworkAccessPolicyVM.Id -in $JitNetworkAccessPolicyVM) {
        $JitPolicy = (@{
                id    = $CurrentVMJitNetworkAccessPolicyVM.Id
                ports = (@{
                        number                     = $RDPPort;
                        endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                        allowedSourceAddressPrefix = @($IP) 
                    })
            })
        $ActivationVM = @($JitPolicy)
        Write-Output -InputObject "Requesting Temporary Acces via Just in Time for $($CurrentVMJitNetworkAccessPolicyVM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours from $IP ..."
        #Get-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName 
        #Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'endTimeUtc'; Expression = { $JitPolicy.ports.endTimeUtc } }, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } }
        Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc
    }
    else {
        Write-Output -InputObject "[WARNING] Just in Time for is not enabled for $($CurrentVMJitNetworkAccessPolicyVM.Name)"
    }
}
