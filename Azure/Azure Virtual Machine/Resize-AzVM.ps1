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
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVM: $($CurrentVM.Id)"
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
                            Write-Warning -Message "$($CurrentVM.Id) is running -Force specify to force the shutdown. Turned it off ..."
                            $null = $CurrentVM | Stop-AzVM -Force
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
                        $null = $CurrentVM | Start-AzVM -NoWait
                    }
                }
            }
        }
    }

    end {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function Get-RunspaceState {
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('PowerShell')]
        [PowerShell]$PS,

        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('Handle')]
        # Should be of type [System.Management.Automation.PowerShellAsyncResult]. value returned from BeginInvoke
        [PSObject]$AsyncResult
    )

    Begin {
        # Set the Binding Flags for Reflection to get Non-Public Fields from PowerShell Instance
        $BindingFlags = [System.Reflection.BindingFlags]'static', 'nonpublic', 'instance'
    }
    process {
        # Get Value Runspace Worker Field
        $Worker = $PS.GetType().GetField('worker', $BindingFlags).GetValue($PS)

        # Get the 'CurrentlyRunningPipline' Property for the runspaces worker
        $CurrentlyRunningPipeline = $worker.GetType().GetProperty('CurrentlyRunningPipeline', $BindingFlags).GetValue($Worker)

        # Check Com
        if ($AsyncResult.IsCompleted -and $null -eq $CurrentlyRunningPipeline) {
            $State = 'Completed'
        }
        elseif (-not $AsyncResult.IsCompleted -and $null -ne $CurrentlyRunningPipeline ) {       

            $State = 'Running'
        }
        elseif (-not $AsyncResult.IsCompleted -and $null -eq $CurrentlyRunningPipeline) {
            # The logic here is that pipeline will be cleared when Completed.
            # So if it is Not Completed and there nothing in the Pipeline it has not started yet
            $State = 'NotStarted'
        }
        
        [PSCustomObject]@{
            PipelineRunning = [bool]$CurrentlyRunningPipeline
            State           = $State
            IsCompleted     = $AsyncResult.IsCompleted
            Synchronous     = $AsyncResult.CompletedSynchronously
        }
    }
}

function Resize-AzVMWithRunSpace {
    [CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $false)]
        [int] $RunspacePoolSize = $([math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)),
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false, ParameterSetName = 'VM')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine[]]$VM,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false, ParameterSetName = 'HostPool' )]
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

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RunspacePoolSize: $RunspacePoolSize"

    #[scriptblock] $scriptblock = Get-Content -Path Function:\Resize-AzVM
    [scriptblock] $scriptblock = [Scriptblock]::Create(((Get-Content -Path Function:\Resize-AzVM) -replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "))

    #region RunSpace Management
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $OverallStartTime = Get-Date

    if ($VM) {
        foreach ($CurrentVM in $VM) {
            Write-Host -Object "Processing '$($CurrentVM.Id)' VM"
            $PowerShell = [powershell]::Create()
            $PowerShell.RunspacePool = $RunspacePool

            $null = $PowerShell.AddScript($ScriptBlock)
            $null = $PowerShell.AddParameter("VM", $CurrentVM)
            $null = $PowerShell.AddParameter("OldVMSize", $OldVMSize)
            $null = $PowerShell.AddParameter("NewVMSize", $NewVMSize)
            $null = $PowerShell.AddParameter("Force", $Force.IsPresent)

            Write-Host -Object "Invoking RunSpace for '$($CurrentVM.Id)' ..."
            $null = $RunspaceList.Add([PSCustomObject]@{
                    VMName      = $CurrentVM.Name
                    PowerShell  = $PowerShell
                    AsyncResult = $PowerShell.BeginInvoke()
                    Result      = $null
                })
        }
    }

    if ($HostPool) {
        foreach ($CurrentHostPool in $HostPool) {
            Write-Host -Object "Processing '$CurrentHostPool' VM"
            $PowerShell = [powershell]::Create()
            $PowerShell.RunspacePool = $RunspacePool

            $null = $PowerShell.AddScript($ScriptBlock)
            $null = $PowerShell.AddParameter("HostPool", $HostPool)
            $null = $PowerShell.AddParameter("OldVMSize", $OldVMSize)
            $null = $PowerShell.AddParameter("NewVMSize", $NewVMSize)
            $null = $PowerShell.AddParameter("Force", $Force.IsPresent)

            Write-Host -Object "Invoking RunSpace for '$CurrentHostPool' ..."
            $null = $RunspaceList.Add([PSCustomObject]@{
                    HostPoolName = $CurrentHostPool.Name
                    PowerShell   = $PowerShell
                    AsyncResult  = $PowerShell.BeginInvoke()
                    Result       = $null
                })
        }
    }

    # View available runspaces
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Available Runspaces: $($RunspacePool.GetAvailableRunspaces())"

    # View the list object runspace status
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Runspace Status:`r`n$($RunspaceList.AsyncResult | Out-String)"

    # View the list using the function declared at the top of this file !!!
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Runspace State:`r`n$($RunspaceList | Get-RunspaceState | Out-String)"

    Write-Host -Object "Waiting the overall processing completes ..."

    Foreach ($Instance in $RunspaceList) {
        $Instance.Result = $Instance.PowerShell.Endinvoke($Instance.AsyncResult)
        $Instance.PowerShell.Dispose()
    }
    $RunspacePool.Dispose() 

    $OverallEndTime = Get-Date

    Write-Host -Object "Runspace Results:`r`n$($RunspaceList.Result | Out-String)"

    $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
    Write-Host -Object "Overall - Processing Time: $($TimeSpan.ToString())" -ForegroundColor Green
    #endregion
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
}

function Resize-AzVMWithThreadJob {
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
        $OverallStartTime = Get-Date
        $Results = @()
        $Jobs = @()
        $ExportedFunctions = [scriptblock]::Create(@"
            Function Resize-AzVM { ${Function:Resize-AzVM} }
"@)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ExportedFunctions:`r`n$($ExportedFunctions | Out-String)"
    }
    process {
        if ($VM) {
            foreach ($CurrentVM in $VM) {
                $Job = Start-ThreadJob -ScriptBlock {Resize-AzVM -VM $using:CurrentVM -OldVMSize $using:OldVMSize -NewVMSize $using:NewVMSize -Force:$($using:Force).IsPresent} -InitializationScript $ExportedFunctions #-StreamingHost $Host
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `Running Job #$($Job.Id) for '$($CurrentVM.Id)' VM"
			    $Jobs += $Job
            }
        }

        if ($HostPool) {
            foreach ($CurrentHostPool in $HostPool) {
                $Job = Start-ThreadJob -ScriptBlock {Resize-AzVM -HostPool $using:HostPool -OldVMSize $using:OldVMSize -NewVMSize $using:NewVMSize -Force:$($using:Force).IsPresent} -InitializationScript $ExportedFunctions #-StreamingHost $Host
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `Running Job #$($Job.Id) for '$($CurrentHostPool.Id)' HostPool"
			    $Jobs += $Job
            }
        }
    }
    end {
		$Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
        $OverallEndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Overall - Processing Time: $TimeSpan"
        return $Results 
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


#region Parameters
$OldVMSize = "Standard_D2s_v5"
$NewVMSize = "Standard_D4s_v5"

<#
$OldVMSize = "Standard_NV8as_v4"
$NewVMSize = "Standard_NV8ads_V710_v5"
#>

$Parameters = @{
    OldVMSize = $OldVMSize
    NewVMSize = $NewVMSize
}
#endregion 


#region AVD Session Hosts
$SessionHosts = Get-AzWvdHostPool | ForEach-Object { 
    $HostPoolId=$_.Id
    (Get-AzWvdSessionHost -HostPoolName $_.Name -ResourceGroupName $_.ResourceGroupName) | ForEach-Object { 
        Get-AzResource -ResourceId $_.ResourceId | Get-AzVM
    }
}
$FilteredVMs = $SessionHosts #| Where-Object -FilterScript { $_.HardwareProfile.VmSize -eq $Parameters['OldVMSize'] }
#endregion

#region Azure VM
$FilteredVMs = Get-AzResourceGroup -ResourceGroupName rg-vm-rand-* | Get-AzVM #| Where-Object -FilterScript { $_.HardwareProfile.VmSize -eq $Parameters['OldVMSize'] }
#endregion

#VM Context 
$StartTime = Get-Date
#$FilteredVMs | Resize-AzVM @Parameters -Force -Verbose
Resize-AzVMWithRunSpace -VM $FilteredVMs @Parameters -Force -Verbose
#$FilteredVMs | Resize-AzVMWithThreadJob @Parameters -Force -Verbose
$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing Time: $TimeSpan"

#AVD Host Context
#Get-AzWvdHostPool | Resize-AzVM @Parameters -Force -Verbose

#endregion
