#requires -Version 3.0 -Modules Az.Accounts, Az.Resources
#Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
)

$IP  = Get-AutomationVariable -Name IP

#region Varibale definition(s)
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines.Id
$VM = $(Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "running" })
#endregion

$AzJitNetworkAccessPolicy = foreach ($CurrentVMJitNetworkAccessPolicyVM in $VM) {
    Write-Verbose -Message "VM : $($CurrentVMJitNetworkAccessPolicyVM.Name)"
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
        Write-Host -Object "Requesting Temporary Acces via Just in Time for $($CurrentVMJitNetworkAccessPolicyVM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours from $IP ..."
        #Get-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName 
        #Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'endTimeUtc'; Expression = { $JitPolicy.ports.endTimeUtc } }, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } }
        Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc
    }
    else {
        Write-Warning -Message "Just in Time for is not enabled for $($CurrentVMJitNetworkAccessPolicyVM.Name)"
    }
}
