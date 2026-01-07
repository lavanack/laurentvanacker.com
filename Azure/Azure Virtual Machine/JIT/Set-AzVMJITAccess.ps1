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
function Set-AzVMJITAccess {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        #All VMs by default but not the AVD Session Hosts
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM = $(Get-AzVM | Where-Object -FilterScript { $_.Id -notin $(Get-AzWvdHostPool | ForEach-Object { (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName).ResourceId }) })
    )

    begin {
        #region Defining variables 
        $RDPPort = 3389
        $SSHPort = 22
        $JITPolicyPorts = $RDPPort, $SSHPort
        $JitPolicyTimeInHours = 3
        $JitPolicyName = "Default"
        #endregion

        $JitNetworkAccessPolicyVM = ((Get-AzJitNetworkAccessPolicy | Where-Object -FilterScript { $_.Name -eq $JitPolicyName })).VirtualMachines.Id
        Write-Verbose -Message "Jit Network Access Policy VM(s) : $($JitNetworkAccessPolicyVM -join ', ')"
    }

    process {
        #region JIT Access Management
        #region Enabling JIT Access
        $AzJitNetworkAccessPolicy = foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "VM : $($CurrentVM.Name)"
            $NewJitPolicy = (
                @{
                    id    = $CurrentVM.Id
                    ports = 
                        foreach ($CurrentJITPolicyPort in $JITPolicyPorts) {
                            @{
                                number                     = $CurrentJITPolicyPort;
                                protocol                   = "*";
                                allowedSourceAddressPrefix = "*";
                                maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
                            }
                        }
                }
            )

            Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
            $ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $CurrentVM.ResourceGroupName -Location $CurrentVM.Location -Name $JitPolicyName).VirtualMachines
            $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($CurrentVM.Id)" } # Exclude existing policy for $CurrentVM.Name
            $UpdatedJITPolicy.Add($NewJitPolicy)

            # Enable Access to the VM including management Port, and Time Range in Hours
            Write-Host "Enabling Just in Time VM Access Policy for ($($CurrentVM.Name)) on port number(s) $($NewJitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
            $null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $CurrentVM.ResourceGroupName -Location $CurrentVM.Location -Name $JitPolicyName -Kind "Basic"
        }
        #endregion
        #endregion
    }
    end {
    }

}
#endregion

#region Main code
#Get-AzVM | Set-AzVMJITAccess -Verbose | Format-List * -Force
#Set-AzVMJITAccess -Verbose -PassThru | Format-List * -Force
Set-AzVMJITAccess -Verbose | Format-List -Property * -Force 
#endregion