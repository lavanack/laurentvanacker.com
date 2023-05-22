Clear-Host

#region Defining variables 
$RDPPort              = 3389
$JitPolicyTimeInHours = 3
$JitPolicyName        = "Default"
$MyPublicIp           = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
$RunningVM            = Get-AzVM -Status | Where-Object -FilterScript {$_.PowerState -match "running"}
#endregion

#region Requesting Temporary Access : 3 hours
$AzJitNetworkAccessPolicy = foreach ($VM in $RunningVM)
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
    Write-Host "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours from $MyPublicIp ..."
    Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
}
#Diplaying the overall result
$AzJitNetworkAccessPolicy | Format-List * -Force
#endregion

