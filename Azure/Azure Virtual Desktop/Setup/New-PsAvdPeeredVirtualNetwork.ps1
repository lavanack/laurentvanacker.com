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

#region Function definitions
function Get-AzurePairedRegion {
    [CmdletBinding()]
    Param(
    )
    return (Get-AzLocation -OutVariable locations) | Select-Object -Property Location, PhysicalLocation, @{Name = 'PairedRegion'; Expression = { $_.PairedRegion.Name } }, @{Name = 'PairedRegionPhysicalLocation'; Expression = { ($locations | Where-Object -FilterScript { $_.location -eq $_.PairedRegion.Name }).PhysicalLocation } } | Where-Object -FilterScript { $_.PairedRegion } | Group-Object -Property Location -AsHashTable -AsString
}

function Get-AzureLocationSortName {
    [CmdletBinding()]
    Param(
    )
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    return $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
}

function Add-PsAvdVirtualNetworkPeering {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $RemoteVirtualNetwork
    )
    $VirtualNetworkPeeringName = "$($VirtualNetwork.Name)-$($RemoteVirtualNetwork.Name)"
    if (-not(Get-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetworkName $VirtualNetwork.Name -ResourceGroupName $VirtualNetwork.ResourceGroupName -ErrorAction Ignore)) {
        $vNetPeeringStatus = Add-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetwork $VirtualNetwork -RemoteVirtualNetworkId $RemoteVirtualNetwork.Id -AllowForwardedTraffic
        Write-Verbose -Message "Creating '$VirtualNetworkPeeringName' ..."
        Write-Verbose -Message "`$vNetPeeringStatus: $($vNetPeeringStatus.PeeringState)"
        if ($vNetPeeringStatus.PeeringState -notin 'Initiated' , 'Connected') {
            Write-Error "The '$VirtualNetworkPeeringName' peering state is $($vNetPeeringStatus.PeeringState)" #-ErrorAction Stop
        }
    }
    else {
        Write-Warning "The '$VirtualNetworkPeeringName' peering already exists"
    }
}
#endregion


Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 


$AzurePairedRegionHT = Get-AzurePairedRegion
$AzureLocationSortName = Get-AzureLocationSortName
$Instance = 2
$PrimaryLocation = "EastUS2"
$TargetRegion = $AzurePairedRegionHT[$PrimaryLocation].PairedRegion
$VirtualNetworkTemplateName = "vnet-avd-avd-{0}-{1:D3}"
$VNetAddressTemplateRange = "10.{0}.0.0/16"
$SubnetAddressTemplateRange = "10.{0}.1.0/24"
$ResourceGroupTemplateName = "rg-avd-ad-{0}-{1:D3}"
#$Index =1
$Index = [regex]::Match( ((Get-AzVirtualNetwork -Name vnet-avd-ad-*).AddressSpace.AddressPrefixes | Sort-Object -Descending | Select-Object -First 1), "^10\.(?<BClass>\d+)").Groups["BClass"].Value -as [int]


$VirtualNetwork, $RemoteVirtualNetwork = foreach ($Location in $PrimaryLocation, $TargetRegion) {
    $Index++
    $LocationShortName = $AzureLocationSortName[$Location].shortName
    $VirtualNetworkName = $VirtualNetworkTemplateName -f $LocationShortName, $Instance
    $subnetName = $VirtualNetworkName -replace "^vnet", "snet"
    $VNetAddressRange = $VNetAddressTemplateRange -f $Index
    $SubnetAddressRange = $SubnetAddressTemplateRange -f $Index
    $ResourceGroupName = $ResourceGroupTemplateName -f $LocationShortName, $Instance
    $NetworkSecurityGroupName = $ResourceGroupName -replace "^rg", "nsg"

    Write-Verbose -Message "`$LocationShortName: $LocationShortName"
    Write-Verbose -Message "`$VirtualNetworkName: $VirtualNetworkName"
    Write-Verbose -Message "`$subnetName: $subnetName"
    Write-Verbose -Message "`$VNetAddressRange: $VNetAddressRange"
    Write-Verbose -Message "`$SubnetAddressRange: $SubnetAddressRange"
    Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    $NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -Force
    $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $SubnetAddressRange -NetworkSecurityGroup $NetworkSecurityGroup
    $AzVirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VNetAddressRange -Location $Location -Subnet $Subnet -Force
    $AzVirtualNetwork
}

$ADVirtualNetwork, $ADRemoteVirtualNetwork = foreach ($CurrentVirtualNetwork in $VirtualNetwork, $RemoteVirtualNetwork) {
    $VirtualNetworkName = $CurrentVirtualNetwork.Name -replace "avd-avd", "avd-ad"
    $AzVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $CurrentVirtualNetwork.ResourceGroupName -Name $VirtualNetworkName
    $AzVirtualNetwork
}

#region Local AVD - Remote AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $VirtualNetwork -RemoteVirtualNetwork $RemoteVirtualNetwork -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $RemoteVirtualNetwork -RemoteVirtualNetwork $VirtualNetwork -Verbose
#endregion

#region Local AD - Remote AD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork -RemoteVirtualNetwork $ADRemoteVirtualNetwork -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADRemoteVirtualNetwork -RemoteVirtualNetwork $ADVirtualNetwork -Verbose
#endregion

#region Local AD - Local AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork -RemoteVirtualNetwork $VirtualNetwork -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $VirtualNetwork -RemoteVirtualNetwork $ADVirtualNetwork -Verbose
#endregion

#region Remote AD - Remote AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADRemoteVirtualNetwork -RemoteVirtualNetwork $RemoteVirtualNetwork -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $RemoteVirtualNetwork -RemoteVirtualNetwork $ADRemoteVirtualNetwork -Verbose
#endregion


