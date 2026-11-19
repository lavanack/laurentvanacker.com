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
<#
.SYNOPSIS
Creates a NAT gateway and associates it with an existing or new subnet.

.DESCRIPTION
Creates a Standard static public IP and a Standard NAT gateway with a ten-minute
idle timeout in the virtual network's resource group and region. With SubnetConfig,
associates the gateway with that existing subnet. With VirtualNetwork, creates a
subnet and a dedicated network security group, then associates the gateway.
Persists the subnet changes by updating the virtual network.

Downloads region and resource abbreviations from the Azure Naming Tool repository
to derive resource names from the virtual network name.

.PARAMETER VirtualNetwork
Specifies the existing virtual network in which to create a dedicated NAT-enabled
subnet and network security group. Accepts a PSVirtualNetwork from the pipeline.
Cannot be combined with SubnetConfig.

.PARAMETER SubnetConfig
Specifies an existing subnet to associate with the new NAT gateway. Accepts a
PSSubnet from the pipeline and supports the alias Subnet. Resolves the parent
virtual network from the subnet resource ID. Does not create a subnet or NSG.
Cannot be combined with VirtualNetwork.

.PARAMETER Force
Passes Force to public IP and NAT gateway creation to suppress confirmation
prompts for those operations.

.EXAMPLE
$Subnet | New-PsAvdNatGatewaySetup -Force

Creates a public IP and NAT gateway and associates the gateway with $Subnet.

.EXAMPLE
New-PsAvdNatGatewaySetup -VirtualNetwork $VirtualNetwork -Verbose

Creates a dedicated subnet, NSG, public IP, and NAT gateway in the virtual network.

.INPUTS
Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork
Microsoft.Azure.Commands.Network.Models.PSSubnet

.OUTPUTS
None. Updates Azure resources without returning an object.

.NOTES
Requires an authenticated Azure context and access to raw.githubusercontent.com.
Names assume Azure Naming Tool prefixes and a hyphen-separated virtual network
naming convention. Existing resources are not checked before creation.

For a new subnet, sorts existing address-prefix strings in descending order,
increments the third octet of the first prefix, and uses a /24 mask. This is not
an address-space allocator: verify that the proposed range is valid, lies within
the virtual network, and does not overlap another subnet before using this mode.

.LINK
https://learn.microsoft.com/azure/nat-gateway/quickstart-create-nat-gateway?tabs=powershell
#>
function New-PsAvdNatGatewaySetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName= 'VirtualNetwork')]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName= 'Subnet')]
        [Alias('Subnet')]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet] $SubnetConfig,

        [Switch] $Force
    )

    begin {
        #region Defining variables 
        #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
        $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
        $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
        $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
        #endregion

        #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
        $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
        $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
        #endregion

        $PublicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
        $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
        $NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
        $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
        #endregion
    }
    process {
        #region Defining variables 
        if ($SubnetConfig) {
            $VirtualNetworkId = $SubnetConfig.Id -replace "/subnets/.*"
            $VirtualNetwork = Get-AzResource -ResourceId $VirtualNetworkId | Get-AzVirtualNetwork

            $ResourceGroupName = $VirtualNetwork.ResourceGroupName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
            $Location = $VirtualNetwork.Location
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
            $LocationShortName = $shortNameHT[$Location].shortName
        }
        else {
            $ResourceGroupName = $VirtualNetwork.ResourceGroupName
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
            $Location = $VirtualNetwork.Location
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
            $LocationShortName = $shortNameHT[$Location].shortName

            #If we create a dedicated subnet we also create a dedicated NSG.
            $NetworkSecurityGroupName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NetworkSecurityGroupPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NetworkSecurityGroupName: $NetworkSecurityGroupName"
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location
        }
        $NatGatewayPrefix = "natgw"
        $NatGatewayName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NatGatewayPrefix
        $SubnetName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $SubnetPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
        $NatGatewayPublicIpName = "{0}-{1}" -f $PublicIPAddressPrefix, $NatGatewayName

        #region NatGateway Subnet Address Prefix Calculation by taking the Subnet with the Highest Address Prefix incrementing the third octect to 1 (10.0.0.0 ==> 10.0.1.0)
        $RegExpPattern = "(\d+)\.(\d+).(\d+).(\d+)/(\d{1,2})"
        $HighestAddressPrefix = ((Get-AzVirtualNetwork -Name $VirtualNetwork.Name).Subnets.AddressPrefix) | Sort-Object -Descending | Select-Object -First 1
        [int]$Octet3 = ([regex]::match($HighestAddressPrefix, $RegExpPattern).Groups[3].Value)
        $Octet3++
        $NatGatewaySubnetAddressPrefix = $HighestAddressPrefix -replace $RegExpPattern, "`$1.`$2.$Octet3.`$4/24"

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewayName: $NatGatewayName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewayPublicIpName: $NatGatewayPublicIpName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NatGatewaySubnetAddressPrefix: $NatGatewaySubnetAddressPrefix"
        #endregion

        #endregion
 
        #region Create the NAT gateway
        #From https://learn.microsoft.com/en-us/azure/nat-gateway/quickstart-create-nat-gateway?tabs=powershell
        #region Create public IP address for NAT gateway 
        $IP = @{
            Name              = $NatGatewayPublicIpName
            ResourceGroupName = $ResourceGroupName
            Location          = $Location
            Sku               = 'Standard'
            AllocationMethod  = 'Static'
            Force             = $Force.IsPresent
            #Zone = 1,2,3
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating Public IP: $NatGatewayPublicIpName"
        $PublicIp = New-AzPublicIpAddress @IP
        #endregion 

        #region Create NAT gateway resource 
        $Nat = @{
            ResourceGroupName    = $ResourceGroupName
            Name                 = $NatGatewayName
            IdleTimeoutInMinutes = '10'
            Sku                  = 'Standard'
            Location             = $Location
            PublicIpAddress      = $PublicIp
            Force                = $Force.IsPresent
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating NatGateway: $NatGatewayName"
        $NatGateway = New-AzNatGateway @Nat
        #endregion 

        if ($SubnetConfig) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating SubNet: $($SubnetConfig.Name)"
            ($VirtualNetwork.Subnets | Where-Object -FilterScript {$_.Id -eq $SubnetConfig.Id}).NatGateway = $NatGateway
        }
        else
        {
            #region Create subnet config and associate NAT gateway to subnet
            $Parameters = @{
                Name                 = $SubnetName
                AddressPrefix        = $NatGatewaySubnetAddressPrefix
                NatGateway           = $NatGateway
                NetworkSecurityGroup = $NetworkSecurityGroup
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating SubNet: $SubnetName"
            $SubnetConfig = New-AzVirtualNetworkSubnetConfig @Parameters 
            #endregion 
        
            #region Add the NatGateway subnet to vnet
            $VirtualNetwork.Subnets += $SubnetConfig
            #endregion
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating vNet: $($VirtualNetwork.Name)"
        $null = $VirtualNetwork | Set-AzVirtualNetwork
        #endregion
    }
    end {}
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region VirtualNetwork
$VirtualNetworkName = "vnet-avd-avd-usc-002"
Get-AzVirtualNetwork -Name $VirtualNetworkName | New-PsAvdNatGatewaySetup -Force -Verbose
#endregion

<#
#region SubNet
$VirtualNetworkName = "vnet-avd-avd-bec-002"
$SubnetName = "snet-avd-pe-bec-001"
Get-AzVirtualNetwork -Name $VirtualNetworkName | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName | New-PsAvdNatGatewaySetup -Force -Verbose
#endregion
#>
#endregion