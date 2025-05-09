﻿<#
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

function Get-AzureLocationShortName {
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
    #$VirtualNetworkPeeringName = "$($VirtualNetwork.Name)-$($RemoteVirtualNetwork.Name)"
    $VirtualNetworkPeeringName = "peer-{0}-{1}" -f $VirtualNetwork.Name, $RemoteVirtualNetwork.Name
    if (-not(Get-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetworkName $VirtualNetwork.Name -ResourceGroupName $VirtualNetwork.ResourceGroupName -ErrorAction Ignore)) {
        $vNetPeeringStatus = Add-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetwork $VirtualNetwork -RemoteVirtualNetworkId $RemoteVirtualNetwork.Id -AllowForwardedTraffic
        Write-Verbose -Message "Creating '$VirtualNetworkPeeringName': '$($VirtualNetwork.Name)' <==> '$($RemoteVirtualNetwork.Name)'"
        Write-Verbose -Message "`$vNetPeeringStatus: $($vNetPeeringStatus.PeeringState)"
        if ($vNetPeeringStatus.PeeringState -notin 'Initiated' , 'Connected') {
            Write-Error "The '$VirtualNetworkPeeringName' peering state is '$($vNetPeeringStatus.PeeringState)'" #-ErrorAction Stop
        }
    }
    else {
        Write-Warning "The '$VirtualNetworkPeeringName' peering already exists"
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


$AzurePairedRegionHT = Get-AzurePairedRegion
$AzureLocationShortName = Get-AzureLocationShortName
$Instance = 1
$PrimaryLocation = "EastUS2"
$SecondaryLocation = $AzurePairedRegionHT[$PrimaryLocation].PairedRegion
#$SecondaryLocation = "WestUS2"
$VirtualNetworkTemplateName = "vnet-avd-ad-{0}-{1:D3}"
$VNetAddressTemplateRange = "10.{0}.0.0/16"
$SubnetAddressTemplateRange = "10.{0}.1.0/24"
$ResourceGroupTemplateName = "rg-avd-ad-{0}-{1:D3}"
#$BClassIndex =1
$BClassIndex = [regex]::Match(((Get-AzVirtualNetwork -Name vnet-avd-ad-*).AddressSpace.AddressPrefixes | Sort-Object -Descending | Select-Object -First 1), "^10\.(?<BClass>\d+)").Groups["BClass"].Value -as [int]


$ADVirtualNetwork = @{}
foreach ($Location in $PrimaryLocation, $SecondaryLocation) {
    $LocationShortName = $AzureLocationShortName[$Location].shortName
    $VirtualNetworkName = $VirtualNetworkTemplateName -f $LocationShortName, $Instance
    $ResourceGroupName = $ResourceGroupTemplateName -f $LocationShortName, $Instance
    $AzVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName
    $ADVirtualNetwork[$Location] = $AzVirtualNetwork
}


$AVDVirtualNetwork = @{}
foreach ($CurrentItem in $ADVirtualNetwork.GetEnumerator()) {
    $Location = $CurrentItem.Name
    $CurrentVirtualNetwork = $CurrentItem.Value
    $LocationShortName = $AzureLocationShortName[$Location].shortName
    $VirtualNetworkName = $CurrentVirtualNetwork.Name -replace "avd-ad", "avd-avd"
    $subnetName = $VirtualNetworkName -replace "^vnet", "snet"
    $BClassIndex++
    $VNetAddressRange = $VNetAddressTemplateRange -f $BClassIndex
    $SubnetAddressRange = $SubnetAddressTemplateRange -f $BClassIndex
    $ResourceGroupName = $ResourceGroupTemplateName -f $LocationShortName, $Instance
    $NetworkSecurityGroupName = $ResourceGroupName -replace "^rg", "nsg"

    Write-Verbose -Message "`$Location: $Location"
    Write-Verbose -Message "`$LocationShortName: $LocationShortName"
    Write-Verbose -Message "`$VirtualNetworkName: $VirtualNetworkName"
    Write-Verbose -Message "`$subnetName: $subnetName"
    Write-Verbose -Message "`$VNetAddressRange: $VNetAddressRange"
    Write-Verbose -Message "`$SubnetAddressRange: $SubnetAddressRange"
    Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"
    $AzVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -ErrorAction Ignore
    if ($null -eq $AzVirtualNetwork) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
        $NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -Force
        $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $SubnetAddressRange -NetworkSecurityGroup $NetworkSecurityGroup
        $AzVirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -AddressPrefix $VNetAddressRange -Location $Location -Subnet $Subnet -DnsServer $ADVirtualNetwork[$Location].DhcpOptions.DnsServers -Force
    }
    $AVDVirtualNetwork[$Location] = $AzVirtualNetwork
}


#region Primary Location AVD <-> Secondary Location AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -Verbose
#endregion

#region Primary Location AD <-> Secondary Location AD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -Verbose
#endregion

#region Primary Location AD <-> Primary Location AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -Verbose
#endregion

#region Primary Location AD <-> Secondary Location AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$PrimaryLocation] -Verbose
#endregion

#region Secondary Location AD <-> Secondary Location AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -Verbose
#endregion

#region Secondary Location AD <-> Primary Location AVD vNet Peering
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -RemoteVirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -Verbose
Add-PsAvdVirtualNetworkPeering -VirtualNetwork $AVDVirtualNetwork[$PrimaryLocation] -RemoteVirtualNetwork $ADVirtualNetwork[$SecondaryLocation] -Verbose
#endregion
#endregion
