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

#requires -Module Az.Accounts, Az.Compute, Az.Security

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
        [switch] $PassThru,
        [switch] $AsJob
    )

    begin {
        Write-Verbose -Message "Public IP(s) : $($IP -join ', ')"
        #region Defining variables 
        $JitPolicyTimeInHours = 3
        $JitPolicyName = "Default"
        #endregion

        $JitNetworkAccessPolicy = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines | Group-Object -Property Id -AsHashTable -AsString
        Write-Verbose -Message "Running VM(s) : $($VM.Name -join ', ')"
        Write-Verbose -Message "Jit Network Access Policy VM(s) : $($JitNetworkAccessPolicy.Keys -join ', ')"
        $AzJitNetworkAccessPolicy = @()
    }

    process {
        #region Requesting Temporary Access : 3 hours
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "VM : $($CurrentVM.Name)"
            $CurrentJitNetworkAccessPolicy = $JitNetworkAccessPolicy[$CurrentVM.Id]
            if ($CurrentJitNetworkAccessPolicy) {
                $JitPolicy = (
                    @{
                        id    = $CurrentVM.Id
                        ports = 
                            #Going through all configured management ports
                            foreach ($CurrentJitNetworkAccessPolicyPort in $CurrentJitNetworkAccessPolicy.Ports.Number) {
                                Write-Verbose -Message "Processing Port : $CurrentJitNetworkAccessPolicyPort"
                                @{
                                    number                     = $CurrentJitNetworkAccessPolicyPort;
                                    endTimeUtc                 = (Get-Date).AddHours($JitPolicyTimeInHours).ToUniversalTime()
                                    allowedSourceAddressPrefix = @($IP) 
                                }
                            }
                    }
                )
                $ActivationVM = @($JitPolicy)
                Write-Host "Requesting Temporary Acces via Just in Time for $($CurrentVM.Name) on port number(s) $($JitPolicy.Ports.Number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
                if ($ASJob) {
                    $AzJitNetworkAccessPolicy += $(Start-Job -Name $($CurrentVM.Name) -ScriptBlock { Start-AzJitNetworkAccessPolicy -ResourceGroupName $($using:CurrentVM.ResourceGroupName) -Location $using:CurrentVM.Location -Name $using:JitPolicyName -VirtualMachine $using:ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $($using:JitPolicy).ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc })
                }
                else {
                    $AzJitNetworkAccessPolicy += Start-AzJitNetworkAccessPolicy -ResourceGroupName $($CurrentVM.ResourceGroupName) -Location $CurrentVM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM | Select-Object -Property *, @{Name = 'startTime'; Expression = { $_.startTimeUtc.ToLocalTime() } }, @{Name = 'endTime'; Expression = { $JitPolicy.ports.endTimeUtc.ToLocalTime() } } -ExcludeProperty StartTimeUtc
                }
            }
            else {
                Write-Warning -Message "Just in Time for is not enabled for $($CurrentVM.Name)"
            }
        }
    }
    #endregion
    end {
        if ($PassThru) {
            if ($AsJob) {
                $AzJitNetworkAccessPolicy | Receive-Job -Wait -AutoRemoveJob
            }
            else {
                $AzJitNetworkAccessPolicy
            }
        }
    }

}
#endregion

#region Main code
#Get-AzVM | Request-AzRunningVMJITAccess -Verbose | Format-List * -Force
#Request-AzRunningVMJITAccess -Verbose -PassThru | Format-List * -Force
Request-AzRunningVMJITAccess -PassThru -AsJob -Verbose | Format-List -Property * -Force 
#endregion