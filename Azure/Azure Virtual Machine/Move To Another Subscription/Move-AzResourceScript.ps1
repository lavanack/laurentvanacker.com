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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Resources

#From https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription#use-azure-powershell

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
    [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,
    [Parameter(Mandatory = $true)]
    [string] $TargetResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string] $TargetSubscriptionId,
    [Parameter(Mandatory = $true)]
    [string] $TargetDiskEncryptionSetId,
    [Parameter(Mandatory = $true)]
    [string] $TargetSubnetId,
    [switch] $Snapshot,
    [switch] $AsJob
)

begin {
    Clear-Host
    $Error.Clear()
    $MyPublicIp = (Invoke-WebRequest -Uri "https://ipv4.seeip.org").Content
    $SourceSubscription = (Get-AzContext).Subscription
    $TargetSubscription =  Get-AzSubscription -SubscriptionId $TargetSubscriptionId
    $Jobs = @()
}

process {
    foreach ($CurrentVM in $VM) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Switching to '$($SourceSubscription.Name)' Subscription"
        $null = Select-AzSubscription -SubscriptionObject $SourceSubscription

        <#
        if ($CurrentVM.Id -match "/subscriptions/(?<Id>[^/]+)") {
            $CurrentVMSubscriptionId =  $Matches["Id"]
            Write-Verbose -Verbose "VM Subscription: $CurrentVMSubscriptionId"
        }
        else {
            Write-Error -Message "Unable to get the Subscription Id from '$($CurrentVM.Id)'" -ErrorAction Stop
        }
        #>
        Write-Verbose -Verbose "Processing '$($CurrentVM.Name)' VM ..."

        #region Network
        $CurrentVMNIC = Get-AzNetworkInterface -ResourceGroupName $CurrentVM.ResourceGroupName -Name $CurrentVM.NetworkProfile.NetworkInterfaces[0].Id.Split('/')[-1]

        # Get the public IP address of the network interface
        $CurrentVMPublicIPs = foreach ($IPConfig in $CurrentVMNIC.IpConfigurations) {
            if ($IPConfig.PublicIpAddress) {
                Get-AzPublicIpAddress -ResourceGroupName $CurrentVM.ResourceGroupName -Name $IPConfig.PublicIpAddress.Id.Split('/')[-1]
            }
        }
        #endregion

        #region Disks
        #region OS Disk
        $CurrentVMOSDisk = $CurrentVM.StorageProfile.OSDisk.ManagedDisk
        $CurrentVMOSAzDisk = Get-AzResource -ResourceId $CurrentVMOSDisk.Id | Get-AzDisk
        #endregion

        #region Data Disks
        $CurrentVMDataDisks = $CurrentVM.StorageProfile.DataDisks.ManagedDisk
        $CurrentVMDataAzDisks = foreach ($CurrentVMDataDisk in $CurrentVMDataDisks) {
            Get-AzResource -ResourceId $CurrentVMDataDisk.Id | Get-AzDisk
        }
        #endregion

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Switching to '$($TargetSubscription.Name)' Subscription"
        $null = Select-AzSubscription -SubscriptionObject $TargetSubscription

        #region Cloning the OS Disk on the Target Subscription
        if ($Snapshot) {
            #region V1 : From a Disk Snapshot
            $SnapshotName = "{0}_{1}" -f $CurrentVMOSAzDisk.Name,  $('{0:yyyyMMddTHHmmss}' -f (Get-Date))
            $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $CurrentVMOSAzDisk.Id -Location $CurrentVM.Location -CreateOption Copy
            $AzSnapshot = New-AzSnapshot -ResourceGroupName $TargetResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
        
            $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMOSAzDisk.Sku.Name -Location $CurrentVMOSAzDisk.Location -CreateOption Copy -SourceResourceId $AzSnapshot.Id -DiskEncryptionSetId $TargetDiskEncryptionSetId -DiskSizeGB $CurrentVMOSAzDisk.DiskSizeGB -OsType $CurrentVMOSAzDisk.OsType
            $OSDisk = New-AzDisk -ResourceGroupName $TargetResourceGroupName -DiskName $CurrentVMOSAzDisk.Name -Disk $DiskConfig        
            #Removing Disk Snapshot
            $null = $AzSnapshot | Remove-AzSnapshot -Force -AsJob
            #endregion
        }
        else {
            #region V2 : Directly from the Disk
            $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMOSAzDisk.Sku.Name -Location $CurrentVMOSAzDisk.Location -CreateOption Copy -SourceResourceId $CurrentVMOSAzDisk.Id -DiskEncryptionSetId $TargetDiskEncryptionSetId -DiskSizeGB $CurrentVMOSAzDisk.DiskSizeGB -OsType $CurrentVMOSAzDisk.OsType
            $OSDisk = New-AzDisk -ResourceGroupName $TargetResourceGroupName -DiskName $CurrentVMOSAzDisk.Name -Disk $DiskConfig        
            #endregion
        }
        #endregion

        #region Cloning the Data Disks on the Target Subscription
        $DataDisks = foreach ($CurrentVMDataAzDisk in $CurrentVMDataAzDisks) {
            if ($Snapshot) {
                #region V1 : From a Disk Snapshot
                $SnapshotName = "{0}_{1}" -f $CurrentVMDataAzDisk.Name,  $('{0:yyyyMMddTHHmmss}' -f (Get-Date))
                $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $CurrentVMDataAzDisk.Id -Location $CurrentVM.Location -CreateOption Copy
                $AzSnapshot = New-AzSnapshot -ResourceGroupName $TargetResourceGroupName -SnapshotName $SnapshotName -Snapshot $SnapshotConfig
        
                $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMDataAzDisk.Sku.Name -Location $CurrentVMDataAzDisk.Location -CreateOption Copy -SourceResourceId $AzSnapshot.Id -DiskEncryptionSetId $TargetDiskEncryptionSetId -DiskSizeGB $CurrentVMDataAzDisk.DiskSizeGB -OsType $CurrentVMDataAzDisk.OsType
                New-AzDisk -ResourceGroupName $TargetResourceGroupName -DiskName $CurrentVMDataAzDisk.Name -Disk $DiskConfig        
                #Removing Disk Snapshot
                $null = $AzSnapshot | Remove-AzSnapshot -Force -AsJob
                #endregion
            }
            else {
                #region V2 : Directly from the Disk
                $DiskConfig = New-AzDiskConfig -SkuName $CurrentVMDataAzDisk.Sku.Name -Location $CurrentVMDataAzDisk.Location -CreateOption Copy -SourceResourceId $CurrentVMDataAzDisk.Id -DiskEncryptionSetId $TargetDiskEncryptionSetId -DiskSizeGB $CurrentVMDataAzDisk.DiskSizeGB -OsType $CurrentVMDataAzDisk.OsType
                New-AzDisk -ResourceGroupName $TargetResourceGroupName -DiskName $CurrentVMDataAzDisk.Name -Disk $DiskConfig        
                #endregion
            }
        }
        #endregion
        
        #region NIC
        #region Public IP Address
        # Get the public IP address of the network interface
        if ($null -eq $CurrentVMPublicIPs) {
            $NIC = New-AzNetworkInterface -Name $CurrentVMNIC.Name -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMNIC.Location -SubnetId $TargetSubnetId #-NetworkSecurityGroupId $NetworkSecurityGroup.Id
        }
        else {
            foreach ($CurrentVMPublicIP in $CurrentVMPublicIPs) {
                if ($IPConfig.PublicIpAddress) {
                    if ([string]::IsNullOrEmpty($CurrentVMPublicIP.DnsSettings.DomainNameLabel)) {
                        $PublicIP = New-AzPublicIpAddress -Name $CurrentVMPublicIP.Name -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMPublicIP.Location -AllocationMethod Static
                    }
                    else
                    {
                        $DomainNameLabel = ("{0}-tgt" -f $CurrentVMPublicIP.DnsSettings.DomainNameLabel).ToLower()
                        $PublicIP = New-AzPublicIpAddress -Name $CurrentVMPublicIP.Name -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMPublicIP.Location -AllocationMethod Static -DomainNameLabel $DomainNameLabel
                    }
                    $NIC = New-AzNetworkInterface -Name $CurrentVMNIC.Name -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMNIC.Location -SubnetId $TargetSubnetId -PublicIpAddressId $PublicIP.Id #-NetworkSecurityGroupId $NetworkSecurityGroup.Id
                }
            }
        }
        #endregion
        #endregion

        $VMConfig = New-AzVMConfig -VMName $CurrentVM.Name -VMSize $CurrentVM.HardwareProfile.VmSize -IdentityType SystemAssigned -EncryptionAtHost -Priority "Spot" -MaxPrice -1
        Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id
        $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable
        $null = Set-AzVMOSDisk -VM $VMConfig -ManagedDiskId $OSDisk.Id -StorageAccountType $CurrentVMOSAzDisk.Sku.Name -DiskSizeInGB $CurrentVMOSAzDisk.DiskSizeGB -CreateOption Attach -Windows


        #region Adding Data Disk(s)
        foreach($CurrentDataDisk in $DataDisks) {
            $null = Add-AzVMDataDisk -VM $VMConfig -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $CurrentDataDisk.Id -Lun 0 -DiskEncryptionSetId $TargetDiskEncryptionSetId
        }
        #endregion
        #endregion

        #region Azure VM
        if ($AsJob) {
            $Jobs += New-AzVM -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMOSAzDisk.Location -VM $VMConfig -AsJob | Add-Member -Name VMName -Value $CurrentVM.Name -MemberType NoteProperty -PassThru | Add-Member -Name PSDuration -Value { $this.PSEndTime - $this.PSBeginTime } -MemberType ScriptProperty -PassThru
        }
        else {
            $StartTime = Get-Date
            New-AzVM -ResourceGroupName $TargetResourceGroupName -Location $CurrentVMOSAzDisk.Location -VM $VMConfig
            $Endtime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Host -Object "Azure VM Move Processing Time: $($TimeSpan.ToString())"
            $Jobs += [PSCustomObject]@{VMName = $CurrentVM.Name; PSBeginTime = $StartTime; PSEndTime = $Endtime; PSDuration = $TimeSpan}
        }
        #endregion
    }
}

end {
    if ($AsJob) {
        $Result = $Jobs | Receive-Job -Wait
        Write-Verbose -Message $($Jobs | Format-Table -Property VMName, PSBeginTime, PSEndTime, PSDuration | Out-String)
        $Jobs | Remove-Job
        Write-Verbose -Message $Result
    }
    else {
        Write-Verbose -Message $($Jobs | Format-Table -Property VMName, PSBeginTime, PSEndTime, PSDuration | Out-String)
    }
<#
    #region Cleanup on the Target Subscription 
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Switching to '$($TargetSubscription.Name)' Subscription"
    $null = Select-AzSubscription -SubscriptionObject $TargetSubscription
    Get-AzDisk -ResourceGroupName $TargetResourceGroupName | Remove-AzDisk -Force -Verbose -AsJob
    #endregion
#>
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Switching to '$($SourceSubscription.Name)' Subscription"
    $null = Select-AzSubscription -SubscriptionObject $SourceSubscription
}