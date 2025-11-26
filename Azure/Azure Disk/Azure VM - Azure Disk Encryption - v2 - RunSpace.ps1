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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.ResourceGraph, Az.Resources, Az.Security, PSScheduledJob, PSWorkflow

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
        [int] $RunspacePoolSize = $([math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)),
        [Parameter(Mandatory = $true)]
        [int] $Count,
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.ps1$")})]
        [string[]] $FullName,
		[Parameter(Mandatory = $false)]
        #Checking if is an array of hashtables (only)
        #The index if for each instance and the hashtable contains key/value pairs for parameter name/parameter value
        [ValidateNotNull()]
        [ValidateScript({(($_ -is [hashtable]) -or ($_ -is [System.Collections.Specialized.OrderedDictionary]))})]
        [object[]] $Parameters
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FullName: $FullName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RunspacePoolSize: $RunspacePoolSize"

    #[ScriptBlock] $ScriptBlock = Get-Content -Path Function:\Repair-AzVM
    [ScriptBlock] $ScriptBlock = [ScriptBlock]::Create(((Get-Content -Path $FullName -Raw) -replace "Write-Host\s+(-Object)?\s*", "Write-Output -InputObject " <#-replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "#> ))

    #region RunSpace Management
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $StartTime = Get-Date
    Write-Host -Object "Start Time: $StartTime"

    Foreach ($Instance in 0..($Count-1)) {
        #Write-Host -Object "`$Instance: $Instance"
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool

        $null = $PowerShell.AddScript($ScriptBlock)
        if (($Parameters) -and ($Parameters[$Instance])) {
            $InstanceArguments = $Parameters[$Instance]
            foreach ($ParameterName in $InstanceArguments.Keys) {
                $ParameterValue = $InstanceArguments[$ParameterName]
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ParameterName: $ParameterName"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ParameterValue: $ParameterValue"
                #$null = $PowerShell.AddParameter("Param1", "Value1")
                $null = $PowerShell.AddParameter($ParameterName, $ParameterValue)
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PowerShell: $($PowerShell | Out-String)"
            }
        }
        Write-Host -Object "[#$Instance] Invoking RunSpace  ..."
        $null = $RunspaceList.Add([PSCustomObject]@{
                Instance    = $Instance
                PowerShell  = $PowerShell
                AsyncResult = $PowerShell.BeginInvoke()
                Result      = $null
            })
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

    $EndTime = Get-Date
    Write-Host -Object "End Time: $EndTime"

    Write-Host -Object "Runspace Results:`r`n$($RunspaceList.Result | Out-String)"

    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Processing Time: $($TimeSpan.ToString())" -ForegroundColor Green
    #endregion
}

function Get-AzVMBitLockerVolume {
    [CmdletBinding(PositionalBinding = $false)]    
    param
    (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Alias('SourceVM')]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine[]] $VM,
        [switch] $Raw
    )
    begin {
        $OverallStartTime = Get-Date
        $BitLockerVolume = @()
        $Jobs = @() 
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `Processing: $($CurrentVM.Name) ..."
            try {
                #Checking if the VM is running
                #Bug: if (($VM | Get-AzVM -Status).PowerState -match "running") {
                if ((Get-AzVM -Name $VM.Name -Status).PowerState -match "running") {
                    if (Get-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name) {
                        Write-Warning -Message "A command is aready running on '$($CurrentVM.ResourceGroupName)' VM (RG: '$($CurrentVM.ResourceGroupName))'"
                    }
                    else {
                        $Job = Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString "Get-BitLockerVolume | ConvertTo-Json" -AsJob -ErrorAction Stop 
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($CurrentVM.Name)] Job #$($Job.Id)"
                        $Jobs += $Job
                    }
                }
                else {
                    Write-Warning -Message "$($CurrentVM.Name) is turned off. skipping it ..."
                }
            }
            catch {
                #Write-Error -Message "$($_ | Out-String)"
            }
        }
    }
    end {
        if ($Jobs) {
            Write-Host -Object "Waiting the jobs complete ..."
            $Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
            if ($Results) {
                $BitLockerVolume = $Results | ForEach-Object {$_.Value[0].Message} | ConvertFrom-Json| ForEach-Object -Process {$_ }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$BitLockerVolume: $($BitLockerVolume | Out-String)"
                $OverallEndTime = Get-Date
                $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Overall - Processing Time: $TimeSpan"
                if ($Raw) {
                    return $BitLockerVolume 
                }
                else {
                    #Volumestatus value : 0 = 'FullyDecrypted', 1 = 'FullyEncrypted', 2 = 'EncryptionInProgress', 3 = 'DecryptionInProgress', 4 = 'EncryptionPaused', 5 = 'DecryptionPaused'
                    $VolumeStatus = @('FullyDecrypted', 'FullyEncrypted', 'EncryptionInProgress', 'DecryptionInProgress', 'EncryptionPaused', 'DecryptionPaused')
                    $BitLockerVolume | Where-Object -FilterScript {$_.MountPoint -match "^\w:$"} |  Select-Object -Property ComputerName, MountPoint, EncryptionPercentage, @{Name="VolumeStatus"; Expression = {$VolumeStatus[$_.VolumeStatus]}}
                }
            }
        }
    }
}
#endregion 

#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$FullName = Join-Path -Path $CurrentDir -ChildPath "Azure VM - Azure Disk Encryption - v2.ps1"
$Count = 10
#$Parameters=@([ordered]@{"Wait"=$True})*$Count
#$Parameters=@([ordered]@{"PublicIP"=$True})*$Count
$Parameters=@([ordered]@{"NSGOnNIC"=$True})*$Count
Start-ScriptWithRunSpace -Count $Count -FullName $FullName -Parameters $Parameters -Verbose
#Start-ScriptWithRunSpace -Count $Count -FullName $FullName -Verbose

#region Checking Encryption Status
$Pattern = "*vmade*"
<#
$VM = Get-AzVM -Name $Pattern 
$VM | Start-AzVM -AsJob | Receive-Job -Wait -AutoRemoveJob
#>
$VM = Get-AzVM -Name $Pattern -Status
$VM = $VM | Where-Object -FilterScript {($_.PowerState -match  "running")}
Do {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 60 seconds"
    Start-Sleep -Second 60
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing VM(s): $($VM.Name -join ', ')"
    $BitLockerVolume = $VM | Get-AzVMBitLockerVolume #-Verbose
    #Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$BitLockerVolume:`r`n$($BitLockerVolume | Out-String)"
    Write-Host -Object "`$BitLockerVolume:`r`n$($BitLockerVolume | Out-String)"
    $AverageEncryptionPercentage = "{0:n2}" -f ($BitLockerVolume | Measure-Object -Property EncryptionPercentage -Average).Average
    Write-Host -Object "Average Encryption Percentage: $AverageEncryptionPercentage %"
    #Keeping only the VMs where the disks are not Fully Encrypted
    $VM = $VM | Where-Object -FilterScript { $_.Name -in $($($BitLockerVolume | Where-Object -FilterScript { $_.VolumeStatus -ne "FullyEncrypted"}).ComputerName | Select-Object -Unique)}
} While ($VM)
#endregion
#endregion