<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.Resources

[CmdletBinding(PositionalBinding = $false)]
Param(
)

#region Function Definitions 
function Resize-AzVM {
    [CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'VM')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine[]]$VM,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'HostPool' )]
        [ValidateNotNullOrEmpty()]
        [ Microsoft.Azure.PowerShell.Cmdlets.DesktopVirtualization.Models.HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $OldVMSize = "Standard_NV8as_v4",
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $NewVMSize = "Standard_NV8ads_V710_v5",
        [switch] $Force
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    }

    process {
        if ($HostPool) {
            $VM = foreach ($CurrentHostPool in $HostPool) {
                $CurrentHostPool | ForEach-Object { 
                    $HostPoolId=$_.Id
                    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | ForEach-Object { 
                        Get-AzResource -ResourceId $_.ResourceId | Get-AzVM
                    }
                }
            }
        }
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVM:`r`n$($CurrentVM | Out-String))"
            if ($CurrentVM.HardwareProfile.VmSize -ne $OldVMSize) {
                Write-Warning -Message "$($CurrentVM.Id) is not a '$OldVMSize' VM. Skipping it ..."
            }
            else {
                If ($PSCmdlet.ShouldProcess($CurrentVM.Id, "Resizing from '$OldVMSize' to '$NewVMSize'")) {
                    $WasTurnedOff = $false
                    $OKForResizing = $false
                    $PowerState = ($CurrentVM | Get-AzVM -Status).Statuses.Code -match "running"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PowerState: $PowerState"
                    if (-not([string]::IsNullOrEmpty($PowerState))) {
                        if ($Force) {
                            Write-Warning -Message "$($CurrentVM.Id) is running -Force specify to force the shutdown. Turned it Off ..."
                            $null = $VM | Stop-AzVM -Force
                            $WasTurnedOff = $true
                            $OKForResizing = $true
                        }
                        else {
                            Write-Warning -Message "$($CurrentVM.Id) is running -Force NOT specify to force the shutdown. Skipping it ..."
                        }
                    }
                    else {
                        $OKForResizing = $true
                    }
                    
                    if ($OKForResizing) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Resizing '$($CurrentVM.Id)' from '$OldVMSize' to '$NewVMSize'"
                        $CurrentVM.HardwareProfile.VmSize = $NewVMSize
                        $null = Update-AzVM -VM $CurrentVM -ResourceGroupName $CurrentVM.ResourceGroupName
                    }
                    
                    if ($WasTurnedOff) {
                        Write-Warning -Message "$($CurrentVM.Id) was running before the resizing. Restarting it ..."
                        $null = $VM | Start-AzVM -NoWait
                    }
                }
            }
        }
    }

    end {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

# Set working directory to script location for relative path operations
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$SubscriptionId = (Get-AzContext).Subscription.Id

$SessionHosts = Get-AzWvdHostPool | ForEach-Object { 
    $HostPoolId=$_.Id
    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | ForEach-Object { 
        Get-AzResource -ResourceId $_.ResourceId | Get-AzVM
    }
}
$FilteredSessionHosts = $SessionHosts #| Where-Object -FilterScript { $_.HardwareProfile.VmSize -eq "Standard_NV8as_v4"}

#region Parameters
$OldVMSize = "Standard_D8ads_v5"
$NewVMSize = "Standard_D4ads_v5"

$Parameters = @{
    OldVMSize = $OldVMSize
    NewVMSize = $NewVMSize
}
#endregion 

#VM Context 
$FilteredSessionHosts | Resize-AzVM @Parameters -Force -Verbose

#AVD Host Context
#Get-AzWvdHostPool | Resize-AzVM @Parameters -Force -Verbose

#endregion
