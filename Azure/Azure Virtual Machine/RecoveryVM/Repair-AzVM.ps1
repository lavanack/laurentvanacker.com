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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.KeyVault, Az.Network, Az.Resources, Az.Security, Az.Storage

#region function definitions 
function New-AzVMBSOD {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )

    begin {
        $ScriptBlock = {
            param(
            )
            #region Disabling automatic restart
            #From https://www.ninjaone.com/blog/configure-bsod-automatic-restart/
            #From https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/configure-system-failure-and-recovery-options
            #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0 -PassThru -Force
            #endregion

            #region NotMyFault Setup: Downloading and Extracting
            $NotMyFaultURI = "https://download.sysinternals.com/files/NotMyFault.zip"
            $Destination = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $NotMyFaultURI -Leaf)
            Start-BitsTransfer -Source $NotMyFaultURI -Destination $Destination
            #Creating a dedicated directory for extracting the zip file content
            $DestinationPath = Join-Path -Path $env:TEMP -ChildPath $(Get-Item -Path $Destination).BaseName
            Remove-Item -Path $DestinationPath -Recurse -Force -ErrorAction Ignore
            Expand-Archive -Path $Destination -DestinationPath $DestinationPath -Force
            #endregion

            #region BSOD
            $CommandLineExecutable = (Get-ChildItem -Path $DestinationPath -Filter *c64.exe).FullName
            #Running a BSOD: From https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault
            $CommandLine = "$CommandLineExecutable -accepteula crash 0x01"
            Write-Verbose -Message "`$CommandLine : $CommandLine"
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", $CommandLine
            #endregion
        }
        $ScriptString = [scriptblock]::create($ScriptBlock)
    }
    process {
        $Jobs = foreach ($CurrentVM in $VM) {
            Write-Host -Object "Processing '$($CurrentVM.Name)' ..."
            $DisplayStatus = ($CurrentVM | Get-AzVM -Status).Statuses.DisplayStatus
            Write-Verbose -Message "`$DisplayStatus:`r`n$($DisplayStatus | Out-String)"

            if ($DisplayStatus -notcontains "VM running") {
                Write-Verbose -Message "Starting '$($CurrentVM.Name)' VM"
                $null = $CurrentVM | Start-AzVM
                Write-Verbose -Message "'$($CurrentVM.Name)' VM Started"
            }
            else {
                Write-Verbose -Message "'$($CurrentVM.Name)' VM is running"
            }
            Write-Verbose -Message "Setting up CrashControl on '$($CurrentVM.Name)' VM"
            $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 0 -PassThru -Force } #-Verbose
            Write-Verbose -Message "`$Result:`r`n$($Result | Out-String)"
            Write-Verbose -Message "Restarting '$($CurrentVM.Name)' VM"
            $null = $CurrentVM | Restart-AzVM
            Write-Verbose -Message "Raising BSOD' on '$($CurrentVM.Name)' VM"
            Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString $ScriptString -AsJob #-Verbose
        }
        $Jobs
        #$Jobs | Receive-Job -Wait -AutoRemoveJob
    }
    end {
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

#From https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-vm-by-use-nested-virtualization
function Repair-AzVM {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList] $RecoveryVM,
        [Parameter(Mandatory = $false)]
        [uint16] $vCPUNumberPerHyperVVM = 4
    )

    begin {
        $SnapshotDiskPattern = "_FromSnapShot"
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Output -InputObject "Processing '$($CurrentVM.Name)' VM"

            $CurrentDataDiskLun = ($RecoveryVM.StorageProfile.DataDisks.Lun | Measure-Object -Maximum).Maximum + 1
            #region Getting OS Disk
            $CurrentVMOSDisk = $CurrentVM.StorageProfile.OSDisk.ManagedDisk
            $CurrentVMOSAzDisk = Get-AzResource -ResourceId $CurrentVMOSDisk.Id | Get-AzDisk
            #endregion

            if ($CurrentVMOSAzDisk.Name -notmatch "$SnapshotDiskPattern$") {
                $NewOSDiskName = "{0}{1}" -f $CurrentVMOSAzDisk.Name, $SnapshotDiskPattern
                $NewOSDisk = Get-AzDisk -ResourceGroupName $CurrentVM.ResourceGroupName -DiskName $NewOSDiskName -ErrorAction Ignore
                if ($NewOSDisk) {
                    Write-Warning -Message "[WARNING] The '$NewOSDiskName' in the '$($CurrentVM.ResourceGroupName)' already exists. We take it. If you don't want this then unattach it if any, delete it and rerun the process"
                }
                else {
                    Write-Verbose -Message "The '$NewOSDiskName' in the '$($CurrentVM.ResourceGroupName)' DOESN'T exist."
                
                    #region SnapShot Creation
                    $TimeStamp = '{0:yyyyMMddHHmmss}' -f (Get-Date)
                    $SnapshotName = "{0}_{1}" -f $CurrentVMOSAzDisk.Name, $TimeStamp
                    Write-Output -InputObject "Creating the '$SnapshotName' Snapshot from the '$($CurrentVMOSAzDisk.Name)' Snapshot ..."
                    $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $CurrentVMOSAzDisk.Id -Location $CurrentVM.Location -CreateOption Copy
                    $AzSnapshot = New-AzSnapshot -ResourceGroupName $CurrentVM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
                    #endregion

                    #region Disk Creation
                    Write-Output -InputObject "Creating the '$NewOSDiskName' OS Disk from the '$($AzSnapshot.Name)' Disk ..."
                    $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMOSAzDisk.Sku.Name -Location $CurrentVMOSAzDisk.Location -CreateOption Copy -SourceResourceId $AzSnapshot.Id -DiskSizeGB $CurrentVMOSAzDisk.DiskSizeGB -OsType $CurrentVMOSAzDisk.OsType
                    $NewOSDisk = New-AzDisk -ResourceGroupName $CurrentVM.ResourceGroupName -DiskName $NewOSDiskName -Disk $DiskConfig        
                    #endregion

                    #region Removing Disk Snapshot
                    Write-Output -InputObject "Deleting the '$($AzSnapshot.Name)' Snapshot ..."
                    $null = $AzSnapshot | Remove-AzSnapshot -Force -AsJob
                    #endregion
                }

                #region Adding the data disk to a virtual machine
                if ($NewOSDisk.Id -notin $(($RecoveryVM.StorageProfile.DataDisks | Get-AzDisk).Id)) {
                    Write-Output -InputObject "Attaching the '$($NewOSDisk.Name)' disk to the '$($RecoveryVM.Name)' VM (Lun: $CurrentDataDiskLun) ..."
                    $null = Add-AzVMDataDisk -VM $RecoveryVM -Name $NewOSDisk.Name -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $NewOSDisk.Id -Lun $CurrentDataDiskLun
                    $null = $RecoveryVM | Update-AzVM
                }
                else {
                    $CurrentDataDiskLun = ($RecoveryVM.StorageProfile.DataDisks | Where-Object -FilterScript { $_.Name -eq $NewOSDisk.Name }).Lun
                    Write-Warning -Message "[WARNING] The '$($NewOSDisk.Name)' disk is already attached to the '$($RecoveryVM.Name)' VM (Lun: $CurrentDataDiskLun). We don't add it as a Data disk"
                }
                #endregion

                #region Hyper-V VM Management
                $ScriptBlock = {
                    param(
                        [Parameter(Mandatory = $true)]
                        [string] $VMName,
                        [Parameter(Mandatory = $true)]
                        [uint16] $Lun,
                        [Parameter(Mandatory = $false)]
                        [uint16] $vCPUNumberPerHyperVVM = 4
                    )
                    $DiskNumber = (Get-WmiObject -Class Win32_DiskDrive | Where-Object { ($_.InterfaceType -eq "SCSI") -and ($_.SCSILogicalUnit -eq $Lun) }).Index
                    if ($DiskNumber) {
                        Write-Output -InputObject "`$DiskNumber: $DiskNumber"
                        Get-Disk -Number $DiskNumber | Set-Disk -IsOffline $true
                        if (-not(Get-VM -Name $VMName -ErrorAction Ignore)) {
                            $VM = New-VM -Name $VMName -MemoryStartupBytes 4GB -NoVHD -Generation 2 -Force
                            Set-VMProcessor -VMName $VMName -Count $vCPUNumberPerHyperVVM
                            Get-VMScsiController -VMName $VMName -ControllerNumber 0 | Add-VMHardDiskDrive -DiskNumber $DiskNumber
                            Write-Output -InputObject "Starting '$($VMName)' Hyper-V VM"
                            $StartTime = Get-Date
                            $null = $VM | Start-VM
                            Write-Output -InputObject "Start Time: $StartTime"
                            Do {
                                Write-Output -InputObject "Sleeping 30 seconds"
                                Start-Sleep -Seconds 30
                                $status = Get-VMIntegrationService -VMName $VMName | Where-Object -FilterScript { $_.Name -eq "Heartbeat" } | Select-Object VMName, Enabled, PrimaryStatusDescription
                                Write-Output -InputObject "Primary Status Description: $($Status.PrimaryStatusDescription)"
                            } While ($Status.PrimaryStatusDescription -ne "OK")
                            Write-Output -InputObject "Stopping '$($VMName)' Hyper-V VM"
                            $null = $VM | Stop-VM -Force
                            Write-Output -InputObject "Deleting '$($VMName)' Hyper-V VM"
                            $null = $VMName | Remove-VM -Force
                            $EndTime = Get-Date
                            Write-Output -InputObject "End Time: $EndTime"
                            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                            Write-Output -InputObject "'$VMName' VM Processing Time: $($TimeSpan.ToString())"
                        }
                        else {
                            Write-Warning -Message "[WARNING] The '$VMName' Hyper-V VM already exists. We don't (re)create it !"
                        }
                    }
                    else {
                        Write-Error -Message "[ERROR] No Disk Number found for LUN $Lun"
                    }
                }
                $ScriptString = [scriptblock]::create($ScriptBlock)
                $Parameter = @{
                    VMName                = $CurrentVM.Name
                    Lun                   = $CurrentDataDiskLun
                    vCPUNumberPerHyperVVM = $vCPUNumberPerHyperVVM
                }
                Write-Verbose -Message "`$Parameter:`r`n$($Parameter | Out-String)"
                Write-Output -InputObject "Creating a '$($CurrentVM.Name)' VM on '$($RecoveryVM.Name)' Recovery VM (with Hyper-V)"
                $Result = Invoke-AzVMRunCommand -ResourceGroupName $RecoveryVM.ResourceGroupName -VMName $RecoveryVM.Name -CommandId 'RunPowerShellScript' -ScriptString  $ScriptString  -Parameter $Parameter -Verbose
            
                # Display the output
                Write-Verbose -Message "Result:`r`n$($Result.Value.Message | Out-String)"
                #endregion

                #region Removing the data disk from a virtual machine
                $null = Remove-AzVMDataDisk -VM $RecoveryVM -Name $NewOSDisk.Name
                $null = $RecoveryVM | Update-AzVM
                #endregion

                #region Swapping the OS Disk on the VM
                Write-Output -InputObject "Stopping the '$($CurrentVM.Name)' VM"
                $CurrentVM | Stop-AzVM -Force
                Write-Output -InputObject "Swapping the OS Disk for the '$($CurrentVM.Name)' VM"
                $CurrentVM.StorageProfile.OsDisk.ManagedDisk.Id = $NewOSDisk.Id
                $CurrentVM.StorageProfile.OsDisk.Name = $NewOSDisk.Name
                $null = $CurrentVM | Update-AzVM
                Write-Output -InputObject "Starting the '$($CurrentVM.Name)' VM"
                $CurrentVM | Start-AzVM -NoWait
                #endregion
            }
            else {
                Write-Warning -Message "[WARNING] The '$($CurrentVM.Name)' was already processed (OS Disk Name ending with '$SnapshotDiskPattern': '$($CurrentVMOSAzDisk.Name)')"
            }
        }
    }
    end {
    }
}

function Repair-AzVMWithRunSpace {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList] $RecoveryVM,
        [Parameter(Mandatory = $false)]
        [uint16] $vCPUNumberPerHyperVVM = 4
    )

    $RecoveryVMSize = $RecoveryVM.HardwareProfile.VmSize
    Write-Verbose -Message "`$RecoveryVMSize: $RecoveryVMSize"
    $RecoveryVMNumberOfLogicalProcessors = ((Get-AzComputeResourceSku -Location $RecoveryVM.Location | Where-Object -FilterScript { $_.Name -eq $RecoveryVMSize }).Capabilities | Where-Object -FilterScript { $_.Name -eq "vCPUs" }).Value
    Write-Verbose -Message "`$RecoveryVMNumberOfLogicalProcessors: $RecoveryVMNumberOfLogicalProcessors"
    #We calculate the RunSpace Pool Size based on the vCPU Number of the Recovery VM divised by the vCPU Number for every Hyper-V VM and keep on occurence for the Guest OS.
    #For instance on a Standard D32ds v5 (32 vcpus, 128 GiB memory) = (32/4)-1 = 7 (so we will be able to repair 7 Azure VMs at once)
    #For instance on a Standard D16ds v5 (16 vcpus, 64 GiB memory)  = (16/4)-1 = 3 (so we will be able to repair 3 Azure VMs at once)
    #For instance on a Standard D8ds v5 (8 vcpus, 32 GiB memory)    =  (8/4)-1 = 1 (so we will only be able to repair 1 Azure VM at once)
    $RunspacePoolSize = [math]::Max(1, $RecoveryVMNumberOfLogicalProcessors / $vCPUNumberPerHyperVVM - 1)
    Write-Verbose -Message "`$RunspacePoolSize: $RunspacePoolSize"

    #[scriptblock] $scriptblock = Get-Content -Path Function:\Repair-AzVM
    [scriptblock] $scriptblock = [Scriptblock]::Create(((Get-Content -Path Function:\Repair-AzVM) -replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "))

    #region RunSpace Management
    $InstanceNumber = $VM.Count
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $StartTime = Get-Date
    Write-Host -Object "Start Time: $StartTime"

    Foreach ($CurrentVM in $VM) {
        Write-Host -Object "Processing '$($CurrentVM.Name)' VM"
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool

        $null = $PowerShell.AddScript($ScriptBlock)
        $null = $PowerShell.AddParameter("VM", $CurrentVM)
        $null = $PowerShell.AddParameter("RecoveryVM", $RecoveryVM)
        $null = $PowerShell.AddParameter("vCPUNumberPerHyperVVM", $vCPUNumberPerHyperVVM)

        Write-Host -Object "Invoking RunSpace for '$($CurrentVM.Name)' ..."
        $null = $RunspaceList.Add([pscustomobject]@{
                VMName      = $CurrentVM.Name
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

$RecoveryVMName = "vmalhypvuse2858"
$RecoveryVM = Get-AzVM -Name $RecoveryVMName

Write-Host -Object "Removing any previously existing rg-vm-rand-* ResourceGroup ..."
$null = Get-AzResourceGroup rg-vm-rand-* | Remove-AzResourceGroup -AsJob -Force
& '..\New-AzRandomVM.ps1' -Location $RecoveryVM.Location -VMNumber 10

$VMToRepair = Get-AzVM -ResourceGroupName rg-vm-rand-*
Write-Host -Object "OS Disk Names:`r`n$($VMToRepair | Select-Object -Property Name, @{Name="OSDiskName"; Expression = { $_.StorageProfile.OSDisk.Name }} | Out-String)"

#$VMToRepair | Start-AzVM -AsJob | Receive-Job -Wait -AutoRemoveJob
#region Creating BSOD on the VM(s) with No Restart
#$Jobs = $VMToRepair | New-AzVMBSOD -Verbose
#$Jobs
#endregion

#region Reparing VM via Hyper-V
#$VMToRepair | Repair-AzVM -RecoveryVM $RecoveryVM -Verbose
Repair-AzVMWithRunSpace -VM $VMToRepair -RecoveryVM $RecoveryVM -Verbose
#Checking if the OS Disk Name end with _FromSnapShot
Write-Host -Object "OS Disk Names:`r`n$($VMToRepair | Select-Object -Property Name, @{Name="OSDiskName"; Expression = { $_.StorageProfile.OSDisk.Name }} | Out-String)"
#endregion
#endregion