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
    [Parameter(Mandatory = $true)]
    [string] $SourceResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string] $DestinationResourceGroupName
)

Clear-Host
$Error.Clear()

$SourceResourceGroup = Get-AzResourceGroup -Name $SourceResourceGroupName
$DestinationResourceGroup = Get-AzResourceGroup -Name $DestinationResourceGroupName
$VM = Get-AzVM -ResourceGroupName $SourceResourceGroupName
$DataDisks = $VM.StorageProfile.DataDisks.ManagedDisk
$OsDisk = $VM.StorageProfile.OsDisk.ManagedDisk
$NetworkInterfaces = $VM.NetworkProfile.NetworkInterfaces
$PublicIpAddress = foreach ($CurrentVM in $VM) {
    ((Get-AzNetworkInterface -ResourceId $CurrentVM.NetworkProfile.NetworkInterfaces.Id).IpConfigurations).PublicIpAddress
}

#Resources to move
$Resource = @($VM, $DataDisks, $OsDisk, $NetworkInterfaces, $PublicIpAddress)

$Parameters = @{
    resources           = $Resource.Id; # Wrap in an @() array if providing a single resource ID string.
    targetResourceGroup = $DestinationResourceGroup.ResourceId
}
try {
    #Validation
    Invoke-AzResourceAction -Action validateMoveResources -ResourceId $SourceResourceGroup.ResourceId -Parameters $Parameters -Force -ErrorAction Stop
    Write-Host -Object "Validation succeeds ..." -ForegroundColor Green
    Write-Host -Object "Starting to move the VMs from '$SourceResourceGroupName' to '$DestinationResourceGroupName' ..."
    #Move (if validation succeeds)
    $StartTime = Get-Date
    Move-AzResource -DestinationResourceGroupName $DestinationResourceGroupName -ResourceId $Resource.Id -Force
    $EndTime = Get-Date
    Write-Host -Object "Move completed in $(New-TimeSpan -Start $StartTime -End $EndTime) ..." -ForegroundColor Green
}
catch {
    throw $_
}

