#region function definition
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
#endregion

Clear-Host
$RunspacePoolSize = 2
$InstanceNumber = 10
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
$RunspacePool.Open()

[System.Collections.ArrayList]$RunspaceList = @()

$StartTime = Get-Date
Foreach ($Instance in 1..$InstanceNumber ) {
    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $ScriptBlock = {
        param ($InstanceNumber)
        $timeToSleep = Get-Random -Minimum 10 -Maximum 20
        Start-Sleep -Seconds $timeToSleep
        Write-Output -InputObject $("Runspace {0:D2} took {1:D2} seconds!" -f $InstanceNumber, $timeToSleep)
    }

    $null = $PowerShell.AddScript($ScriptBlock)
    $null = $PowerShell.AddParameter("InstanceNumber", $Instance)

    $null = $RunspaceList.Add([pscustomobject]@{
            InstanceNumber = $Instance
            PowerShell     = $PowerShell
            AsyncResult    = $PowerShell.BeginInvoke()
            Result         = $null
        })
}

# View available runspaces
$RunspacePool.GetAvailableRunspaces() 

# View the list object with all runspaces 
$RunspaceList

# View the list object runspace status
$RunspaceList.AsyncResult 

# View the list using the function declared at the top of this file !!!
$RunspaceList | Get-RunspaceState 

Foreach ($Instance in $RunspaceList) {
    $Instance.Result = $Instance.PowerShell.Endinvoke($Instance.AsyncResult)
    $Instance.PowerShell.Dispose()
}
$RunspacePool.Dispose() 
$RunspaceList.Result

$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
$TimeSpan