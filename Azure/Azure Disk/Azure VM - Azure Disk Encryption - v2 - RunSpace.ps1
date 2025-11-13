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
#requires -Version 5 -Modules PSScheduledJob, PSWorkflow

#region function definitions 
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

function Start-ScriptWithRunSpace {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [int] $RunspacePoolSize = 10,
        [Parameter(Mandatory = $true)]
        [int] $Count,
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.ps1$")})]
        [string[]] $FullName,
		[Parameter(Mandatory = $false)]
        #Checking if is an array of hashtables (only)
        #The index if for each instance and the hashtable contains key/value pairs for parameter name/parameter value
        [ValidateNotNull()]
        [ValidateScript({($_ -is [array]) -and ((($_ | Get-Member).TypeName | Select-Object -Unique).count -eq 1) -and ((($_ | Get-Member).TypeName | Select-Object -Unique) -contains "System.Collections.Hashtable")})]
        [object[]] $Parameters
    )

    Write-Verbose -Message "`$FullName: $FullName"
    Write-Verbose -Message "`$RunspacePoolSize: $RunspacePoolSize"

    #[ScriptBlock] $ScriptBlock = Get-Content -Path Function:\Repair-AzVM
    [ScriptBlock] $ScriptBlock = [ScriptBlock]::Create(((Get-Content -Path $FullName -Raw) -replace "Write-Host\s+(-Object)?\s*", "Write-Output -InputObject " <#-replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "#> ))

    #region RunSpace Management
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $StartTime = Get-Date
    Write-Host -Object "Start Time: $StartTime"

    Foreach ($Instance in 0..($Count-1)) {
        Write-Host -Object "`$Instance: $Instance"
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool

        $null = $PowerShell.AddScript($ScriptBlock)
        if (($Parameters) -and ($Parameters[$Instance])) {
            $InstanceArguments = $Parameters[$Instance]
            foreach ($ParameterName in $InstanceArguments) {
                $ParameterValue = $InstanceArguments[$ParameterName]
                #$null = $PowerShell.AddParameter("Param1", "Value1")
                $null = $PowerShell.AddParameter($ParameterName, $ParameterValue)
            }
        }
        Write-Host -Object "[#$Instance] Invoking RunSpace  ..."
        $null = $RunspaceList.Add([PSCustomObject]@{
                VMName      = $Instance.Name
                PowerShell  = $PowerShell
                AsyncResult = $PowerShell.BeginInvoke()
                Result      = $null
            })
    }

    # View available runspaces
    Write-Verbose -Message "Available Runspaces: $($RunspacePool.GetAvailableRunspaces())"

    # View the list object runspace status
    Write-Verbose -Message "Runspace Status:`r`n$($RunspaceList.AsyncResult | Out-String)"

    # View the list using the function declared at the top of this file !!!
    Write-Verbose -Message "Runspace State:`r`n$($RunspaceList | Get-RunspaceState | Out-String)"

    Write-Host -Object "Waiting the overall processing completes ..."

    Foreach ($Instance in $RunspaceList) {
        $Instance.Result = $Instance.PowerShell.Endinvoke($Instance.AsyncResult)
        $Instance.PowerShell.Dispose()
    }
    $RunspacePool.Dispose() 

    $EndTime = Get-Date
    Write-Host -Object "End Time: $EndTime"

    Write-Host -Object "Runspace Results:`r`n$($RunspaceList.Result | Out-String)"

    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Processing Time: $($TimeSpan.ToString())"
    #endregion
}
#endregion 

#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$FullName = Join-Path -Path $CurrentDir -ChildPath "Azure VM - Azure Disk Encryption - v2.ps1"

Start-ScriptWithRunSpace -Count 3 -FullName $FullName -Verbose
#endregion