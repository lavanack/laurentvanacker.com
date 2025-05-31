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
function Repair-AzVM {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList] $RecoveryVM
    )

    begin {
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Host -Object "Processing '$($CurrentVM.Name)'..."

            $CurrentDataDiskLun = ($RecoveryVM.StorageProfile.DataDisks.Lun | Measure-Object -Maximum).Maximum+1
            #region OS Disk SnapShot
            #region OS Disk
            $CurrentVMOSDisk = $CurrentVM.StorageProfile.OSDisk.ManagedDisk
            $CurrentVMOSAzDisk = Get-AzResource -ResourceId $CurrentVMOSDisk.Id | Get-AzDisk
            #endregion
            
            $NewOSDiskName = "{0}_FromSnapShot" -f $CurrentVMOSAzDisk.Name
            $NewOSDisk = Get-AzDisk -ResourceGroupName $CurrentVM.ResourceGroupName -DiskName $NewOSDiskName -ErrorAction Ignore
            if ($NewOSDisk) {
                Write-Warning -Message "The '$NewOSDiskName' in the '$($CurrentVM.ResourceGroupName)' already exists. We take it. If you don't want this then unattach it if any, delete it and rerun the process"
            } else {
                Write-Host -Object "The '$NewOSDiskName' in the '$($CurrentVM.ResourceGroupName)' DOESN'T exist."
                
                #region SnapShot Creation
                $TimeStamp = '{0:yyyyMMddHHmmss}' -f (Get-Date)
                $SnapshotName = "{0}_{1}" -f $CurrentVMOSAzDisk.Name, $TimeStamp
                Write-Host -Object "Creating the '$SnapshotName' Snapshot from the '$($CurrentVMOSAzDisk.Name)' Snapshot ..."
                $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $CurrentVMOSAzDisk.Id -Location $CurrentVM.Location -CreateOption Copy
                $AzSnapshot = New-AzSnapshot -ResourceGroupName $CurrentVM.ResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
                #endregion

                #region Disk Creation
                Write-Host -Object "Creating the '$NewOSDiskName' OS Disk from the '$($AzSnapshot.Name)' Disk ..."
                $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMOSAzDisk.Sku.Name -Location $CurrentVMOSAzDisk.Location -CreateOption Copy -SourceResourceId $AzSnapshot.Id -DiskSizeGB $CurrentVMOSAzDisk.DiskSizeGB -OsType $CurrentVMOSAzDisk.OsType
                $NewOSDisk = New-AzDisk -ResourceGroupName $CurrentVM.ResourceGroupName -DiskName $NewOSDiskName -Disk $DiskConfig        
                #endregion

                #region Removing Disk Snapshot
                Write-Host -Object "Deleting the '$($AzSnapshot.Name)' Snapshot ..."
                $null = $AzSnapshot | Remove-AzSnapshot -Force -AsJob
                #endregion
            }

            #region Adding the data disk to a virtual machine
            if ($NewOSDisk.Id -notin $(($RecoveryVM.StorageProfile.DataDisks | Get-AzDisk).Id)) {
                Write-Host -Object "Attaching the '$($NewOSDisk.Name)' disk to the '$($RecoveryVM.Name)' VM (Lun: $CurrentDataDiskLun) ..."
                $null = Add-AzVMDataDisk -VM $RecoveryVM -Name $NewOSDisk.Name -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $NewOSDisk.Id -Lun $CurrentDataDiskLun
                $null = $RecoveryVM | Update-AzVM
            } else {
                $CurrentDataDiskLun = ($RecoveryVM.StorageProfile.DataDisks | Where-Object -FilterScript { $_.Name -eq $NewOSDisk.Name}).Lun
                Write-Warning "The '$($NewOSDisk.Name)' disk is already attached to the '$($RecoveryVM.Name)' VM (Lun: $CurrentDataDiskLun). We don't add it as a Data disk"
            }
            #endregion

            #region Hyper-V VM Management
            $ScriptBlock = {
                param([string] $VMName, $Lun)
                $DiskNumber = (Get-WmiObject -Class Win32_DiskDrive | Where-Object { ($_.InterfaceType -eq "SCSI") -and ($_.SCSILogicalUnit -eq $Lun) }).Index
                if ($DiskNumber) {
                    Write-Host -Object "`$DiskNumber: $DiskNumber"
                    Get-Disk -Number $DiskNumber | Set-Disk -IsOffline $true
                    if (-not(Get-VM -Name $VMName -ErrorAction Ignore)) {
                        $VM = New-VM -Name $VMName -MemoryStartupBytes 4GB -NoVHD -Generation 2 -Force
                        Set-VMProcessor -VMName $VMName -Count 4
                        Get-VMScsiController -VMName $VMName -ControllerNumber 0 | Add-VMHardDiskDrive -DiskNumber $DiskNumber
                        Write-Host -Object "Starting '$($VMName)' VM "
                        $null = $VM | Start-VM
                        $StartTime = Get-Date
                        Write-Host -Object "Start Time: $StartTime"
                        Do {
                            Write-Host -Object "Sleeping 30 seconds"
                            Start-Sleep -Seconds 30
                            $status = Get-VMIntegrationService -VMName $VMName | Where-Object -FilterScript {$_.Name -eq "Heartbeat"} | Select-Object VMName, Enabled, PrimaryStatusDescription
                            Write-Host -Object "Primary Status Description: $($Status.PrimaryStatusDescription)"
                            Write-Host -Object "Primary Operational Status: $($Status.PrimaryOperationalStatus)"
                        #} While ($Status.PrimaryOperationalStatus -ne [Microsoft.HyperV.PowerShell.VMIntegrationComponentOperationalStatus]::Ok)
                        } While ($Status.PrimaryStatusDescription -ne "OK")
                        $EndTime = Get-Date
                        Write-Host -Object "End Time: $EndTime"
                        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                        Write-Host -Object "'$VMName' VM Processing Time: $($TimeSpan.ToString())"
                        Write-Host -Object "Stopping '$($VMName)' VM "
                        $null = $VM | Stop-VM -Force
                        Write-Host -Object "Deleting '$($VMName)' VM "
                        $VMName | Remove-VM -Force
                    }
                    else {
                        Write-Warning "The '$VMName' Hyper-V VM already exists. We don't (re)create it !"
                    }
                }
                else {
                    Write-Error -Message "No Disk Number found for LUN $Lun"
                }
            }
            $ScriptString = [scriptblock]::create($ScriptBlock)
            $Parameter = @{
                VMName = $CurrentVM.Name
                Lun = $CurrentDataDiskLun
            }
            Write-Verbose -Message "`$Parameter:`r`n$($Parameter | Out-String)"
            Write-Host -Object "Creating a '$($CurrentVM.Name)' VM on '$($RecoveryVM.Name)' Recovery VM (with Hyper-V)"
            $Result = Invoke-AzVMRunCommand -ResourceGroupName $RecoveryVM.ResourceGroupName -VMName $RecoveryVM.Name -CommandId 'RunPowerShellScript' -ScriptString  $ScriptString  -Parameter $Parameter -Verbose
            
            # Display the output
            Write-Host -Object "Result:`r`n$($Result.Value.Message | Out-String)"
            #endregion

            #region Removing the data disk from a virtual machine
            $null = Remove-AzVMDataDisk -VM $RecoveryVM -Name $NewOSDisk.Name
            $null = $RecoveryVM | Update-AzVM
            #endregion

            #region Swapping the OS Disk on the VM
            Write-Host -Object "Stopping the '$($CurrentVM.Name)' VM"
            $CurrentVM | Stop-AzVM -Force
            Write-Host -Object "Swapping the OS Disk for the '$($CurrentVM.Name)' VM"
            $CurrentVM.StorageProfile.OsDisk.ManagedDisk.Id = $NewOSDisk.Id
            $CurrentVM.StorageProfile.OsDisk.Name = $NewOSDisk.Name
            $null = $CurrentVM | Update-AzVM
            Write-Host -Object "Starting the '$($CurrentVM.Name)' VM"
            $CurrentVM | Start-AzVM
            #endregion
        }
    }
    end {
    }
}
#endregion 



#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$RecoveryVMName = "vmalhypvuse2858"
$RecoveryVM = Get-AzVM -Name $RecoveryVMName

$VMToRepair = Get-AzVM -ResourceGroupName rg-vm-rand-* | Select-Object -First 1 
$VMToRepair | Repair-AzVM -RecoveryVM $RecoveryVM -Verbose
#endregion 