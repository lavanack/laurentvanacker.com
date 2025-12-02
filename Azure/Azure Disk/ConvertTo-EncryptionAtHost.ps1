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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Resources, Az.Security, Microsoft.PowerShell.ThreadJob

<#
Must read:
- https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling
#>

[CmdletBinding(PositionalBinding = $false)]    
param
(
    [string] $AzCopyDir = "C:\Tools"
)

#region Function Definition(s)
function ConvertTo-EncryptionAtHost {
    [CmdletBinding(PositionalBinding = $false)]    
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Alias('SourceVM')]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine[]] $VM
    )

    begin {
        $OverallStartTime = Get-Date
        $ConvertedVMs = @()
    }
    process {
        foreach ($CurrentVM in $VM) {
            $VMStartTime = Get-Date
            $ResourceGroupName = $CurrentVM.ResourceGroupName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName :$ResourceGroupName"
            $VMName = $CurrentVM.Name
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMName :$VMName"
            $TargetVMName = "{0}_Target" -f $VMName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TargetVMName :$TargetVMName"
            $TargetVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $TargetVMName -ErrorAction Ignore
            if ($TargetVM) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($TargetVM.Name)] Removing Existing Target VM (Resource Group: '$($TargetVM.ResourceGroupName)') ..."
                $TargetVM | Remove-AzVM -Force
            }

            #region Revoking Disk Access
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Revoking Disk Access ..."
            $StartTime = Get-Date
            $null = $CurrentVM.StorageProfile.OSDisk | Get-AzDisk | Where-Object -FilterScript { $_.DiskState -eq "ActiveSAS" } | Revoke-AzDiskAccess
            $null = $CurrentVM.StorageProfile.DataDisks | Get-AzDisk | Where-Object -FilterScript { $_.DiskState -eq "ActiveSAS" } | Revoke-AzDiskAccess
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Revoking Disk Access - Processing Time: $TimeSpan"
            #endregion

            #region Disable encryption and remove the encryption extension
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Starting VM (Resource Group: '$($CurrentVM.ResourceGroupName)') ..."
            $StartTime = Get-Date
            $null = $CurrentVM | Start-AzVM
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Starting VM - Processing Time: $TimeSpan"
            if (($VM | Get-AzVMExtension).Id -match "AzureDiskEncryption") {
                #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#disable-encryption-and-remove-the-encryption-extension
                #Disable encryption
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Disabling Encryption ..."
                $StartTime = Get-Date
                $null = Disable-AzVMDiskEncryption -ResourceGroupName $ResourceGroupName -VMName $VMName -VolumeType "all" -Force
                $EndTime = Get-Date
                $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Revoking Disabling Encryption - Processing Time: $TimeSpan"
                #Remove the encryption extension
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Removing the Encryption Extension ..."
                $StartTime = Get-Date
                $null = Remove-AzVMDiskEncryptionExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Force
                $EndTime = Get-Date
                $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Removing Encryption Extension - Processing Time: $TimeSpan"
            }
            <#
            Do {
                $RunPowerShellScript = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString "manage-bde -status"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] $($RunPowerShellScript.value[0].Message)"
                $Statuses = ([regex]"\s*Conversion Status:\s*(.+)\s*").Matches($RunPowerShellScript.value[0].Message).captures | ForEach-Object -Process { $_.groups[1].Value}
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] `$Statuses:`r`n$($Statuses | Out-String)"
                Start-Sleep -Seconds 30
            } While (($Statuses | Select-Object -Unique) -ne "Fully Decrypted")
            #>
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Decrypting Disk ..."
            $StartTime = Get-Date
            #Volumestatus value : 0 = 'FullyDecrypted', 1 = 'FullyEncrypted', 2 = 'EncryptionInProgress', 3 = 'DecryptionInProgress', 4 = 'EncryptionPaused', 5 = 'DecryptionPaused'
            $VolumeStatus = @('FullyDecrypted', 'FullyEncrypted', 'EncryptionInProgress', 'DecryptionInProgress', 'EncryptionPaused', 'DecryptionPaused')
            Do {
                $RunPowerShellScript = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString "Get-BitLockerVolume | ConvertTo-Json"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$("{0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date))][$VMName] `$Statuses (As Json):`r`n$($RunPowerShellScript.value[0].Message)"
                $Drives = ($RunPowerShellScript.value[0].Message | ConvertFrom-Json) | Where-Object -FilterScript { $_.MountPoint -match "^\w:$" } |  Select-Object -Property ComputerName, MountPoint, EncryptionPercentage, @{Name = "VolumeStatus"; Expression = { $VolumeStatus[$_.VolumeStatus] } }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$("{0:yyyy-MM-dd HH:mm:ss}" -f (Get-Date))][$VMName] `$Drives:`r`n$($Drives | Out-String)"
                $AverageEncryptionPercentage = "{0:n2}" -f ($Drives | Measure-Object -Property EncryptionPercentage -Average).Average
                Write-Verbose -Message "Average Encryption Percentage: $AverageEncryptionPercentage %"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 60 seconds"
                Start-Sleep -Seconds 60
            } While (($Drives.VolumeStatus | Select-Object -Unique) -ne "FullyDecrypted")
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Decrypting Disk - Processing Time: $TimeSpan"
            #endregion

            #region Create new managed disks
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Stopping VM (Resource Group: '$($CurrentVM.ResourceGroupName)') ..."
            $StartTime = Get-Date
            $null = $CurrentVM | Stop-AzVM -Force
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Stopping VM - Processing Time: $TimeSpan"
            #From https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-migrate?tabs=azurepowershell%2Cazurepowershell2%2CCLI3%2CCLI4%2CCLI5%2CCLI-cleanup#create-new-managed-disks
            # Get source disk information
            $VMSourceDisks = @{
                "OSDisk"   = $(Get-AzResource -ResourceId $CurrentVM.StorageProfile.OsDisk.ManagedDisk.Id | Get-AzDisk)
                "DataDisk" = foreach ($SourceDisk in $CurrentVM.StorageProfile.DataDisks) {
                    Get-AzResource -ResourceId $SourceDisk.ManagedDisk.Id | Get-AzDisk
                }
            }


            #region Installing AzCopy
            #Looking for all installed azcopy.exe 
            $AzCopy = Get-ChildItem -Path (Get-PSDrive | Where-Object -FilterScript { $_.Provider.Name -eq "FileSystem" }).Root -Filter azcopy.exe -File -Recurse -ErrorAction Ignore
            $MaxVersionNumber = [System.Version]::new(0, 0, 0)
            foreach ($CurrentAzCopy in $AzCopy.FullName) {
                $VersionNumber = & $CurrentAzCopy -v
                #Looking for the highest installed version of azcopy.exe 
                if ($VersionNumber -gt $MaxVersionNumber) {
                    $MaxVersionNumber = $VersionNumber
                    $HighestAzCopy = $CurrentAzCopy
                }
            }

            #If not version found then downloading the latest one
            if (-not($HighestAzCopy)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AzCopy not found"
                $AzCopyURI = 'https://aka.ms/downloadazcopy-v10-windows'
                #$AzCopyURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/Azure/azure-storage-azcopy/releases/latest").assets | Where-Object -FilterScript { $_.name -match "windows_amd64" }).browser_download_url)
                $OutputFile = Join-Path -Path $CurrentDir -ChildPath 'azcopy_windows_amd64_latest.zip'
                Invoke-WebRequest -Uri $AzCopyURI -OutFile $OutputFile
                $null = New-Item -Path $AzCopyDir -ItemType Directory -Force
                Expand-Archive -Path $OutputFile -DestinationPath $AzCopyDir -Force
                Remove-Item -Path $OutputFile -Force
                $HighestAzCopy = (Get-ChildItem -Path $(Join-Path -Path $AzCopyDir -ChildPath "azcopy_windows*") -Filter azcopy.exe -Recurse  | Sort-Object -Property Name -Descending | Select-Object -First 1).Fullname

            }
            #endregion

            $VMDiskData = @{}
            foreach ($DiskType in $VMSourceDisks.Keys) {
                $SourceDisks = $VMSourceDisks[$DiskType]
                foreach ($SourceDisk in $SourceDisks) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Processing '$($SourceDisk.Id)' Disk ..."
                    $DiskName = "{0}_Target" -f $SourceDisk.Name
                    $TargetDisk = Get-AzDisk -Name $DiskName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore
                    if ($TargetDisk) {
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$($TargetDisk.Name)] Removing Existing Target Disk (Resource Group: '$($TargetDisk.ResourceGroupName)') ..."
                        $TargetDisk | Remove-AzDisk -Force
                    }
                    # For Linux OS disks (if not ADE-encrypted)
                    # $TargetDiskConfig = New-AzDiskConfig -Location $SourceDisk.Location -CreateOption Upload -UploadSizeInBytes $($SourceDisk.DiskSizeBytes+512) -OsType Linux #   -HyperVGeneration "V2"

                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Creating '$DiskName' Disk ..."
                    $StartTime = Get-Date
                    if ($DiskType -eq "OSDisk") {
                        # Create a new empty target disk
                        # For Windows OS disks
                        $TargetDiskConfig = New-AzDiskConfig -SkuName $SourceDisk.sku.Name -Location $SourceDisk.Location -CreateOption Upload -UploadSizeInBytes $($SourceDisk.DiskSizeBytes + 512) -OsType Windows -HyperVGeneration "V2"
                        $TargetDiskConfig = Set-AzDiskSecurityProfile -Disk $TargetDiskConfig -SecurityType "TrustedLaunch"
                        $TargetDisk = New-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $DiskName -Disk $TargetDiskConfig
                        $DiskData = [PSCustomObject]@{SourceDisk = $SourceDisk; TargetDisk = $TargetDisk }
                        $VMDiskData[$DiskType] = $DiskData
                    }
                    else {
                        # For data disks (no OS type needed)
                        $TargetDiskConfig = New-AzDiskConfig -SkuName $SourceDisk.sku.Name -Location $SourceDisk.Location -CreateOption Upload -UploadSizeInBytes $($SourceDisk.DiskSizeBytes + 512)
                        $TargetDisk = New-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $DiskName -Disk $TargetDiskConfig
                        $DiskData = [PSCustomObject]@{SourceDisk = $SourceDisk; TargetDisk = $TargetDisk }
                        if ($null -eq $VMDiskData[$DiskType]) {
                            $VMDiskData[$DiskType] = @($DiskData)
                        }
                        else {
                            $VMDiskData[$DiskType] += $DiskData
                        }
                    }
                    $EndTime = Get-Date
                    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Creating '$DiskName' Disk - Processing Time: $TimeSpan"


                    # Generate SAS URIs and copy the data
                    # Get SAS URIs for source and target disks
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Getting SAS URIs for source and target disks ..."
                    $StartTime = Get-Date
                    $SourceSAS = Grant-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $SourceDisk.Name -Access Read -DurationInSecond 7200
                    $TargetSAS = Grant-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $TargetDisk.Name -Access Write -DurationInSecond 7200
                    $EndTime = Get-Date
                    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Getting SAS URIs for source and target disks - Processing Time: $TimeSpan"

                    # Copy the target disk data using AzCopy
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Copying the target disk data using AzCopy"
                    $StartTime = Get-Date
                    $AzCopyResult = & $HighestAzCopy copy $SourceSAS.AccessSAS $TargetSAS.AccessSAS --blob-type PageBlob
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] AzCopy Result:`r`n$($AzCopyResult | Out-String)"
                    $EndTime = Get-Date
                    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Copying the target disk data using AzCopy - Processing Time: $TimeSpan"

                    # Revoke SAS access when complete
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Revoking SAS access when complete"
                    $StartTime = Get-Date
                    $null = Revoke-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $SourceDisk.Name
                    $null = Revoke-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $TargetDisk.Name                
                }
                $EndTime = Get-Date
                $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Revoking SAS access - Processing Time: $TimeSpan"
            }
            #endregion

            #region Create a new VM with encryption
            #From https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-migrate?tabs=azurepowershell%2Cazurepowershell2%2Cazurepowershell3%2CCLI4%2CCLI5%2CCLI-cleanup#create-a-new-vm-with-encryption
            #region Create Network Interface Card 
            $StartTime = Get-Date
            $NIC = Get-AzResource -ResourceId $CurrentVM.NetworkProfile.NetworkInterfaces.Id | Get-AzNetworkInterface
            $Subnet = $NIC.IpConfigurations.subnet
            $TargetNICName = "{0}_Target" -f $NIC.Name
            #endregion


            #region Create Azure Public Address if source vm has one
            $NICParameters = @{
                Name              = $TargetNICName 
                ResourceGroupName = $ResourceGroupName 
                Location          = $NIC.Location 
                SubnetId          = $Subnet.Id
                Force             = $True
            }
            if ($NIC.IpConfigurations.PublicIpAddress.Id) {
                $PublicIP = Get-AzResource -ResourceId $NIC.IpConfigurations.PublicIpAddress.Id | Get-AzPublicIpAddress
                $TargetPublicIPName = $PublicIP.Name -replace $CurrentVM.Name, $TargetVMName
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Creating the '$TargetPublicIPName' Public IP ..."
                $TargetPublicIP = New-AzPublicIpAddress -Name $TargetPublicIPName -ResourceGroupName $ResourceGroupName -Location $PublicIP.Location -AllocationMethod Static -DomainNameLabel $($TargetVMName.ToLower() -replace "_") -Force
                $NICParameters["PublicIpAddressId"] = $TargetPublicIP.Id 
            }
            if ($NIC.NetworkSecurityGroup) {
                $NICParameters["NetworkSecurityGroupId"] = $NIC.NetworkSecurityGroup.Id
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Creating the '$TargetNICName' NIC ..."
            $TargetNIC = New-AzNetworkInterface @NICParameters
            #endregion

            #region OS Disk
            # Define VM configuration
            #If the dource VM is a Spot Intance, the target VM will be
            if ($CurrentVM.Priority -eq "Spot") {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] will be a Spot Intance ..."
                $VMConfig = New-AzVMConfig -VMName $TargetVMName -VMSize $CurrentVM.HardwareProfile.VmSize -EncryptionAtHost -Priority "Spot" -MaxPrice -1 -IdentityType SystemAssigned -SecurityType TrustedLaunch
            }
            else {
                $VMConfig = New-AzVMConfig -VMName $TargetVMName -VMSize $CurrentVM.HardwareProfile.VmSize -EncryptionAtHost -IdentityType SystemAssigned -SecurityType TrustedLaunch
            }

            $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Adding the '$TargetNICName' NIC to the VM..."
            $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $TargetNIC.Id

            # Add the OS disk (Windows example)
            $TargetDisk = $VMDiskData["OSDisk"].TargetDisk
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Adding the '$($TargetDisk.Name)' OS Disk to the VM..."
            $VMConfig = Set-AzVMOSDisk -VM $VMConfig -ManagedDiskId $TargetDisk.Id -CreateOption Attach -Windows
            #$VMConfig = Set-AzVMSecurityProfile -VM $VMConfig -SecurityType TrustedLaunch

            # For Linux OS disk, use -Linux instead of -Windows

            # Create the VM with network settings (you'll need to specify your own)
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Creating the VM..."
            $TargetVM = New-AzVM -ResourceGroupName $ResourceGroupName -Location $TargetDisk.Location -VM $VMConfig -OSDiskDeleteOption Delete  -DataDiskDeleteOption Delete #-DisableBginfoExtension
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] New `$TargetVM: $($TargetVM | Out-String)"
            #endregion

            #region Data Disk(s)
            # Get the VM
            $TargetVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $TargetVMName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Get `$TargetVM: $($TargetVM | Out-String)"
            $Lun = 0
            foreach ($CurrentVMDiskData in $VMDiskData["DataDisk"]) {
                $TargetDisk = $CurrentVMDiskData.TargetDisk
                #$SourceDisk = $CurrentVMDiskData.SourceDisk
                # Attach the data disk
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Adding the '$($TargetDisk.Name)' Data Disk to the VM..."
                $TargetVM = Add-AzVMDataDisk -VM $TargetVM -ManagedDiskId $TargetDisk.Id -Lun $Lun -CreateOption Attach
                $Lun++
            }

            # Update the VM
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Updating the VM..."
            $null = Update-AzVM -ResourceGroupName $ResourceGroupName -VM $TargetVM
            #endregion

            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Creating VM (and related resources): $TimeSpan"
            #endregion

            #region Verify and configure the new disks
            $StartTime = Get-Date
            #From https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-migrate?tabs=azurepowershell%2Cazurepowershell2%2Cazurepowershell3%2CCLI4%2CCLI5%2CCLI-cleanup#verify-and-configure-the-new-disks
            $ScriptString = @"
# List all disks and their partitions
Get-Disk | Get-Partition | Format-Table -AutoSize

# Check drive letters
Get-PSDrive -PSProvider FileSystem
"@
            $RunPowerShellScript = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $TargetVMName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Verifying the new disks:`r`n$($RunPowerShellScript | Out-String)"
            #endregion

            #region Verify encryption and cleanup
            #From https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-migrate?tabs=azurepowershell%2Cazurepowershell2%2Cazurepowershell3%2Cazurepowershell4%2CCLI5%2CCLI-cleanup#verify-encryption-and-cleanup
            # Check encryption at host status
            $EncryptionAtHostStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $TargetVMName | Select-Object -ExpandProperty SecurityProfile | Select-Object EncryptionAtHost
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Encryption At Host Status:`r`n$($EncryptionAtHostStatus | Out-String)"

            # Verify disk encryption status
            $DiskEncryptionStatus = foreach ($CurrentDisks in $VMDiskData.Values.TargetDisk) {
                foreach ($CurrentDisk in $CurrentDisks) {
                    Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $CurrentDisk.Name | Select-Object Name, Encryption
                }
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Disk Encryption Status:`r`n$($DiskEncryptionStatus | Select-Object -Property Name -ExpandProperty Encryption | Out-String)"

            #endregion

            <#
            #region Source Cleanup
            # Delete the original VM
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Deleting VM (Resource Group: '$($CurrentVM.ResourceGroupName)') ..."
            $CurrentVM | Remove-AzVM -Force

            # Delete the original disk
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$VMName] Deleting '$($VMSourceDisks.Values.Name -join ', ' )' Disk(s) (Resource Group: '$($CurrentVM.ResourceGroupName)') ..."
            $VMSourceDisks.Values | ForEach-Object -Process { $_ | Remove-AzDisk -AsJob -Force } | Receive-Job -Wait -AutoRemoveJob
            #endregion
            #>

            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Verifying the new disks: $TimeSpan"

            $TargetVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $TargetVMName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] Get `$TargetVM: $($TargetVM | Out-String)"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] `$TargetVM: $($TargetVM | Out-String)"
            $ConvertedVMs += $TargetVM

            $VMEndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $VMStartTime -End $VMEndTime
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] [$TargetVMName] VM - Processing Time: $TimeSpan"
        }
    }
    end {
        $OverallEndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Overall - Processing Time: $TimeSpan"
        return $ConvertedVMs 
    }
}

function ConvertTo-EncryptionAtHostWithThreadJob {
    [CmdletBinding(PositionalBinding = $false)]    
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Alias('SourceVM')]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine[]] $VM
    )

    begin {
        $OverallStartTime = Get-Date
        $ConvertedVMs = @()
        $Jobs = @()
        $ExportedFunctions = [scriptblock]::Create(@"
            Function ConvertTo-EncryptionAtHost { ${Function:ConvertTo-EncryptionAtHost} }
"@)
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ExportedFunctions:`r`n$($ExportedFunctions | Out-String)"
    }
    process {
        foreach ($CurrentVM in $VM) {
            $Job = Start-ThreadJob -ScriptBlock { ConvertTo-EncryptionAtHost -VM $using:CurrentVM } -InitializationScript $ExportedFunctions -StreamingHost $Host
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `Running Job #$($Job.Id) for '$($CurrentVM.Name)' VM"
            $Jobs += $Job
        }
    }
    end {
        $ConvertedVMs = $Jobs | Receive-Job -Wait -AutoRemoveJob
        $OverallEndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Overall - Processing Time: $TimeSpan"
        return $ConvertedVMs 
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

function ConvertTo-EncryptionAtHostWithRunSpace {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [int] $RunspacePoolSize = $([math]::Max(1, (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors / 2)),
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RunspacePoolSize: $RunspacePoolSize"

    #[scriptblock] $scriptblock = Get-Content -Path Function:\ConvertTo-EncryptionAtHost
    [scriptblock] $scriptblock = [Scriptblock]::Create(((Get-Content -Path Function:\ConvertTo-EncryptionAtHost) -replace "Write-Verbose\s+(-Message)?\s*", "Write-Output -InputObject "))

    #region RunSpace Management
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $RunspacePoolSize)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$RunspaceList = @()

    $OverallStartTime = Get-Date

    Foreach ($CurrentVM in $VM) {
        Write-Host -Object "Processing '$($CurrentVM.Name)' VM"
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool

        $null = $PowerShell.AddScript($ScriptBlock)
        $null = $PowerShell.AddParameter("VM", $CurrentVM)

        Write-Host -Object "Invoking RunSpace for '$($CurrentVM.Name)' ..."
        $null = $RunspaceList.Add([PSCustomObject]@{
                VMName      = $CurrentVM.Name
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

    $OverallEndTime = Get-Date

    Write-Host -Object "Runspace Results:`r`n$($RunspaceList.Result | Out-String)"

    $TimeSpan = New-TimeSpan -Start $OverallStartTime -End $OverallEndTime
    Write-Host -Object "[$($MyInvocation.MyCommand)] Overall - Processing Time: $($TimeSpan.ToString())" -ForegroundColor Green
    #endregion
    $ConvertedVMs = $RunspaceList | ForEach-Object -Process { $_.Result[-1] }
    return $ConvertedVMs 
}

function Get-AzVMBitLockerVolume {
    [CmdletBinding(PositionalBinding = $false)]    
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Alias('SourceVM')]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM,
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
                $BitLockerVolume = $Results | ForEach-Object { $_.Value[0].Message } | ConvertFrom-Json | ForEach-Object -Process { $_ }
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
                    $BitLockerVolume | Where-Object -FilterScript { $_.MountPoint -match "^\w:$" } |  Select-Object -Property ComputerName, MountPoint, EncryptionPercentage, @{Name = "VolumeStatus"; Expression = { $VolumeStatus[$_.VolumeStatus] } }
                }
            }
        }
    }
}
#endregion 

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#Finding a VM with ADE Enabled
$ResourceGroups = Get-AzResourceGroup -Name rg-vm-ade* | Where-Object -FilterScript { $_.ProvisioningState -eq "Succeeded" }
$VMs = foreach ($CurrentResourceGroup in $ResourceGroups) {
    foreach ($CurrentVM in Get-AzVM -ResourceGroupName $CurrentResourceGroup.ResourceGroupName) {
        if (((Get-AzVMDiskEncryptionStatus -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name).OsVolumeEncrypted -eq "Encrypted") -and ((Get-AzVMDiskEncryptionStatus -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name).DataVolumesEncrypted -eq "Encrypted")) {
            $CurrentVM
        }
    }
}
if ($VMs) {
    #Randomly getting some VMs
    $VM = $VMs #| Get-Random -Count 3
    #region Conversion
    #region Sequential processing
    #ConvertTo-EncryptionAtHost -VM $VM -Verbose
    #$ConvertedVMs = $VM | ConvertTo-EncryptionAtHost -Verbose
    #endregion

    #region Parallel processing via RunSpace
    $ConvertedVMs = ConvertTo-EncryptionAtHostWithRunSpace -VM $VM -Verbose
    #endregion

    #region Parallel processing via ThreadJob
    #$ConvertedVMs = $VM | ConvertTo-EncryptionAtHostWithThreadJob -Verbose
    #$ConvertedVMs = ConvertTo-EncryptionAtHostWithThreadJob -VM $VM -Verbose
    #endregion
    $ConvertedVMs
    #endregion

    #region Bonus Track
    #region Checking Encryption Status - Useless because normally all disk are not encrypted after ConvertTo-EncryptionAtHost* function call
    $VM = $ConvertedVMs
    Do {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Second 30
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing VM(s): $($VM.Name -join ', ')"
        $BitLockerVolume = $VM | Get-AzVMBitLockerVolume -Verbose
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$BitLockerVolume: $($BitLockerVolume | Out-String)"
        #Keeping only the VMs where the disks are not Fully Decrypted
        $VM = $VM | Where-Object -FilterScript { $_.Name -in $($($BitLockerVolume | Where-Object -FilterScript { $_.VolumeStatus -ne "FullyDecrypted" }).ComputerName | Select-Object -Unique) }
    } While ($VM)
    #endregion

    #region JIT Access Management
    $MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"
    $RDPPort = 3389
    $JITPolicyPorts = $RDPPort
    $JitPolicyTimeInHours = 3
    $JitPolicyName = "Default"
    #ednregion

    foreach ($VM in $ConvertedVMs) {
        #region JIT Access Management
        #region Enabling JIT Access
        $NewJitPolicy = (
            @{
                id    = $VM.Id
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
        $ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $VM.ResourceGroupName -Location $VM.Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
        $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VM.Name
        $UpdatedJITPolicy.Add($NewJitPolicy)
	
        # Enable Access to the VM including management Port, and Time Range in Hours
        Write-Host "Enabling Just in Time VM Access Policy for $($VM.Name) on port number(s) $($JitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours..."
        $JitNetworkAccessPolicy = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $VM.ResourceGroupName -Location $VM.Location -Name $JitPolicyName -Kind "Basic"
        Start-Sleep -Seconds 5
        #endregion

        #region Requesting Temporary Access : 3 hours
        $JitPolicy = (
            @{
                id    = $VM.Id
                ports = 
                foreach ($CurrentJITPolicyPort in $JITPolicyPorts) {
                    @{
                        number                     = $CurrentJITPolicyPort;
                        endTimeUtc                 = (Get-Date).AddHours($JitPolicyTimeInHours).ToUniversalTime()
                        allowedSourceAddressPrefix = @($MyPublicIP) 
                    }
                }
            }
        )
        $ActivationVM = @($JitPolicy)
        Write-Host "Requesting Temporary Acces via Just in Time for $($VM.Name) on port number(s) $($JitPolicy.ports.number -join ', ') for maximum $JitPolicyTimeInHours hours ..."
        $null = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
        #endregion
        #endregion

        #region Enabling auto-shutdown at 11:00 PM in the user time zome
        $SubscriptionId = ($VM.Id).Split('/')[2]
        $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$($VM.ResourceGroupName)/providers/microsoft.devtestlab/schedules/shutdown-computevm-$($VM.Name)"
        $Properties = @{}
        $Properties.Add('status', 'Enabled')
        $Properties.Add('taskType', 'ComputeVmShutdownTask')
        $Properties.Add('dailyRecurrence', @{'time' = "2300" })
        $Properties.Add('timeZoneId', (Get-TimeZone).Id)
        $Properties.Add('targetResourceId', $VM.Id)
        $null = New-AzResource -Location $VM.Location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force -Verbose
        #endregion
    }


    #endregion 
    #endregion
}
else {
    Write-Warning "No Azure VM with Azure Disk Encryption enabled found ..."
}
#endregion