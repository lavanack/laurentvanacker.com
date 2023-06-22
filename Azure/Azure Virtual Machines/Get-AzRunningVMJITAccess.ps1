Clear-Host

#region Defining variables 
$RDPPort              = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName        = "Default"
$MyPublicIp           = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
$RunningVM            = Get-AzVM -Status | Where-Object -FilterScript {$_.PowerState -match "running"}
#endregion

$JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript {$_.Name -eq $JitPolicyName})).VirtualMachines.Id

#region Requesting Temporary Access : 3 hours
$AzJitNetworkAccessPolicy = foreach ($VM in $RunningVM)
{
    if ($VM.Id -in $JitNetworkAccessPolicyVM)
    {
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
        Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name='endTimeUtc'; Expression={$JitPolicy.ports.endTimeUtc}}
    }
    else
    {
        Write-Warning -Message "Just in Time for is not enabled for $($VM.Name)"
    }
}
#Displaying the overall result
$AzJitNetworkAccessPolicy | Format-List * -Force
#endregion

