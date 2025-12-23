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
    }
    process {
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
        $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName

        if ($SubnetConfig) {
            $VirtualNetworkId = $SubnetConfig.Id -replace "/subnets/.*"
            $VirtualNetwork = Get-AzResource -ResourceId $VirtualNetworkId | Get-AzVirtualNetwork
        }
        $NatGatewayPrefix = "natgw"
        $NatGatewayName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NatGatewayPrefix
        $SubnetName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $SubnetPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
        $ResourceGroupName = $VirtualNetwork.ResourceGroupName
        $Location = $VirtualNetwork.Location
        $NatGatewayPublicIpName = "{0}-{1}" -f $PublicIPAddressPrefix, $NatGatewayName

        $NetworkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName

        #region NatGateway Subnet Address Prefix Calculation by taking the Subnet with the Highest Address Prefix incrementing the third octect to 1 (10.0.0.0 ==> 10.0.1.0)
        $RegExpPattern = "(\d+)\.(\d+).(\d+).(\d+)"
        $HighestAddressPrefix = ((Get-AzVirtualNetwork -Name $VirtualNetwork.Name).Subnets.AddressPrefix) | Sort-Object -Descending | Select-Object -First 1
        [int]$Octet3 = ([regex]::match($HighestAddressPrefix, $RegExpPattern).Groups[3].Value)
        $Octet3++
        $NatGatewaySubnetAddressPrefix = $HighestAddressPrefix -replace $RegExpPattern, "`$1.`$2.$Octet3.`$4"

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
            $Subnet = @{
                Name                 = $SubnetName
                AddressPrefix        = $NatGatewaySubnetAddressPrefix
                NatGateway           = $NatGateway
                NetworkSecurityGroup = $NetworkSecurityGroup
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating SubNet: $SubnetName"
            $SubnetConfig = New-AzVirtualNetworkSubnetConfig @subnet 
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
$VirtualNetworkName = "vnet-avd-avd-use2-002"
#Get-AzVirtualNetwork -Name $VirtualNetworkName | New-PsAvdNatGatewaySetup -Verbose
#endregion

#region SubNet
$VirtualNetworkName = "vnet-avd-avd-use2-002"
$SubnetName = "snet-avd-pe-use2-002"
Get-AzVirtualNetwork -Name $VirtualNetworkName | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName | New-PsAvdNatGatewaySetup -Force -Verbose
#endregion

#endregion