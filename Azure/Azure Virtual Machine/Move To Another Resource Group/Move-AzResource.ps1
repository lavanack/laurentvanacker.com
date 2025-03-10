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
#From https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription#use-azure-powershell
function Move-AzResource {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $SourceResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string] $TargetResourceGroupName,
        [switch] $Start
    )

    $SourceResourceGroup = Get-AzResourceGroup -Name $SourceResourceGroupName
    $TargetResourceGroup = Get-AzResourceGroup -Name $TargetResourceGroupName
    $VM = Get-AzVM -ResourceGroupName $SourceResourceGroupName
    $DataDisks = $VM.StorageProfile.DataDisks.ManagedDisk
    $OsDisk = $VM.StorageProfile.OsDisk.ManagedDisk
    $NetworkInterfaces = $VM.NetworkProfile.NetworkInterfaces
    $PublicIpAddress = foreach ($CurrentVM in $VM) {
        ((Get-AzNetworkInterface -ResourceId $CurrentVM.NetworkProfile.NetworkInterfaces.Id).IpConfigurations).PublicIpAddress
    }

    #Resources to move
    $Resources = @($VM, $DataDisks, $OsDisk, $NetworkInterfaces, $PublicIpAddress)

    $Parameters = @{
        resources           = $Resources.Id; # Wrap in an @() array if providing a single resource ID string.
        targetResourceGroup = $TargetResourceGroup.ResourceId
    }

    #region Stopping the VMs
    $Jobs = $VM | Stop-AzVM -Force -AsJob
    Write-Host -Object "Stopping the VMs to move (As Job) ..."
    $Jobs | Wait-Job | Out-Null
    Write-Host -Object "VMs stopped !"
    #endregion
    
    try {
        #region Validation
        $StartTime = Get-Date
        Invoke-AzResourceAction -Action validateMoveResources -ResourceId $SourceResourceGroup.ResourceId -Parameters $Parameters -Force -ErrorAction Stop
        $EndTime = Get-Date
        Write-Host -Object "Validation completed in $(New-TimeSpan -Start $StartTime -End $EndTime) ..." -ForegroundColor Green
        #endregion

        #region Move (if validation succeeds)
        Write-Host -Object "Starting to move the VMs from '$SourceResourceGroupName' to '$TargetResourceGroupName' ..."
        $StartTime = Get-Date
        Move-AzResource -DestinationResourceGroupName $TargetResourceGroupName -ResourceId $Resources.Id -Force
        $EndTime = Get-Date
        Write-Host -Object "Move completed in $(New-TimeSpan -Start $StartTime -End $EndTime) ..." -ForegroundColor Green
        #endregion

        #region Starting the VMs (if specified)
        if ($Start) {
            $Jobs = Get-AzVM -ResourceGroupName $TargetResourceGroupName | Where-Object -FilterScript { $_.Name -in $VM.Name} | Start-AzVM -AsJob
            Write-Host -Object "Starting the moved VMs (As Job) ..."
            $null = $Jobs | Receive-Job -Wait -AutoRemoveJob
            Write-Host -Object "VMs started !"
        }
        #endregion
    }
    catch {
        throw $_
    }
}
#endregion 