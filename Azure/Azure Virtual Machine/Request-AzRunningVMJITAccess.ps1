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

#requires -Module Az.Compute

Clear-Host

#region Function Definition(s)
function Request-AzRunningVMJITAccess {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM = $(Get-AzVM -Status | Where-Object -FilterScript { $_.PowerState -match "running" }),
        [Alias('PublicIP')]
        [string[]] $IP = $((Invoke-RestMethod -Uri http://ip-api.com/json/?fields=query).query),
        [switch] $PassThru
    )

    begin {
        Write-Verbose -Message "Public IP(s) : $($IP -join ', ')"
        #region Defining variables 
        $RDPPort = 3389
        $JitPolicyTimeInHours = 3
        $JitPolicyName = "Default"
        #endregion

        $JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines.Id
    }

    process {
        #region Requesting Temporary Access : 3 hours
        $AzJitNetworkAccessPolicy = foreach ($CurrentVMJitNetworkAccessPolicyVM in $VM) {
            Write-Verbose -Message "VM : $($CurrentVMJitNetworkAccessPolicyVM.Name)"
            if ($CurrentVMJitNetworkAccessPolicyVM.Id -in $JitNetworkAccessPolicyVM) {
                $JitPolicy = (@{
                        id    = $CurrentVMJitNetworkAccessPolicyVM.Id
                        ports = (@{
                                number                     = $RDPPort;
                                endTimeUtc                 = (Get-Date).AddHours($JitPolicyTimeInHours).ToUniversalTime()
                                allowedSourceAddressPrefix = $IP 
                            })
                    })
                $ActivationVM = @($JitPolicy)
                Write-Host -Object "Requesting Temporary Acces via Just in Time for $($CurrentVMJitNetworkAccessPolicyVM.Name) on port number $RDPPort for maximum $JitPolicyTimeInHours hours from '$($IP -join ',')' ..."
                #Get-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName 
                #Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'endTimeUtc'; Expression = { $JitPolicy.ports.endTimeUtc } }, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } }
                Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVMJitNetworkAccessPolicyVM.ResourceGroupName) -Location $CurrentVMJitNetworkAccessPolicyVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc
            }
            else {
                Write-Warning -Message "Just in Time for is not enabled for $($CurrentVMJitNetworkAccessPolicyVM.Name)"
            }
        }
    }
    #endregion
    end {
        if ($PassThru) {
            $AzJitNetworkAccessPolicy
        }
    }

}
#endregion

#region Main code
#Get-AzVM | Request-AzRunningVMJITAccess -Verbose | Format-List * -Force
#Request-AzRunningVMJITAccess -Verbose -PassThru | Format-List * -Force
Request-AzRunningVMJITAccess -Verbose
#endregion