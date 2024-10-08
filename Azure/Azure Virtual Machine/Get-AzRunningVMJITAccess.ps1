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

Clear-Host

#region Defining variables 
$RDPPort = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"
$MyPublicIp = (Invoke-RestMethod -Uri http://ip-api.com/json/?fields=query).query
$RunningVM = Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "running" }
#endregion

$JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines.Id

#region Requesting Temporary Access : 3 hours
$AzJitNetworkAccessPolicy = foreach ($VM in $RunningVM) {
    if ($VM.Id -in $JitNetworkAccessPolicyVM) {
        $JitPolicy = (@{
                id    = $VM.Id
                ports = (@{
                        number                     = $RDPPort;
                        endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                        allowedSourceAddressPrefix = @($MyPublicIP) 
                    })
            })
        $ActivationVM = @($JitPolicy)
        Write-Host -Object "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours from $MyPublicIp ..."
        #Get-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName 
        #Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'endTimeUtc'; Expression = { $JitPolicy.ports.endTimeUtc } }, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } }
        Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc
    }
    else {
        Write-Warning -Message "Just in Time for is not enabled for $($VM.Name)"
    }
}
#Displaying the overall result
$AzJitNetworkAccessPolicy | Format-List * -Force
#endregion

