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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Security, Az.Storage

#region Function definition
<#
.SYNOPSIS
    Creates an Azure Virtual Network dedicated to Azure Virtual Desktop (AVD) with two subnets (AVD and Private Endpoint) and their associated Network Security Groups.
.DESCRIPTION
    Builds resource names using the Azure Naming Tool convention, provisions a resource group if needed, and creates an AVD subnet (with the AVD-specific NSG outbound rules) plus a Private Endpoint subnet. Subnet address prefixes are derived automatically from the supplied virtual network address range.
#>
function New-PsAvdVirtualNetwork {
    [CmdletBinding(PositionalBinding = $false)]
    Param( 
        [Parameter(Mandatory = $false, HelpMessage = 'The Azure location for your Virtual Network.')]
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })] 
        [string] $Location = "CentralUS",
        [parameter(Mandatory = $false, HelpMessage = 'The instance number for your deployment.')]
        [ValidateScript({ $_ -in 0..999 })] 
        [int] $Instance = $(Get-Random -Minimum 0 -Maximum 1000),
        [parameter(Mandatory = $false, HelpMessage = 'The address range of the new virtual network in CIDR format')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{2}")] 
        [string] $AddressRange = '10.5.0.0/16',
        [parameter(Mandatory = $false, HelpMessage = 'The Resource Group Name of the new virtual network')]
        [string] $ResourceGroupName,
        [switch] $Force
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

        #Resolving the short name for the target Azure location and the standardized prefixes for each resource type
        $LocationShortName = $shortNameHT[$Location].shortName
        $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
        $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
        $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
        $NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
        #Project and role tokens used to build the resource names
        $Project = "avd"
        $Role = "avd"

        $VirtualNetworkName = '{0}-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
        $VirtualNetworkName = $VirtualNetworkName.ToLower()
        if ([string]::IsNullOrEmpty($ResourceGroupName)) {
            $ResourceGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
            $ResourceGroupName = $ResourceGroupName.ToLower()
        }

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkName: $VirtualNetworkName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"

        #Reusing the resource group if it already exists, otherwise creating it
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
        if ($ResourceGroup) {
            if ($Force.IsPresent) {
                Write-Warning -Message "-Force was specified. We will remove the '$ResourceGroupName' ResourceGroup and recreate it ..."
                Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the resource group '$ResourceGroupName' in the '$($ResourceGroup.Location)' location ..." -ForegroundColor Cyan
                $ResourceGroup | Remove-AzResourceGroup -Force
                Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The resource group '$ResourceGroupName' has been Removed." -ForegroundColor Green

                Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the resource group '$ResourceGroupName' in the '$Location' location ..." -ForegroundColor Cyan
                $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
                Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The resource group '$ResourceGroupName' has been created." -ForegroundColor Green
            }
            else {
            }
            Write-Warning -Message "The '$ResourceGroupName' ResourceGroup already exists. We won't recreate or modify it ..."
        }
        else {
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the resource group '$ResourceGroupName' in the '$Location' location ..." -ForegroundColor Cyan
            $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The resource group '$ResourceGroupName' has been created." -ForegroundColor Green
        }

        #Bailing out early if the virtual network already exists to avoid overwriting it
        $VirtualNetwork = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore 
        if ($VirtualNetwork) {
            Write-Warning -Message "The '$VirtualNetworkPrefix' VirtualNetwork already exists. Exiting ..."
            return
        }
        else {
            #region AVD Subnet
            #region AVD Subnet Name
            $SubnetName = '{0}-{1}-{2}-{3}-{4:D3}' -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
            $SubnetName = $SubnetName.ToLower()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"
            #endregion

            #region AVD Subnet Address Prefix Calculation by taking the Subnet with the Highest Address Prefix incrementing the third octect to 1 (10.0.0.0 ==> 10.0.1.0)
            $RegExpPattern = "(\d+)\.(\d+).(\d+).(\d+)/(\d{2})"
            [int]$Octet3 = ([regex]::match($AddressRange, $RegExpPattern).Groups[3].Value)
            $Octet3++
            $SubnetAddressPrefix = $AddressRange -replace $RegExpPattern, "`$1.`$2.$Octet3.`$4/24"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetAddressPrefix: $SubnetAddressPrefix"
            #endregion

            #Building the AVD-recommended outbound/inbound NSG rules (control plane, Azure services, monitoring, KMS activation, RDP Shortpath, etc.)
            $NSGRuleAVDServiceTraffic = New-AzNetworkSecurityRuleConfig -Name "AVDServiceTraffic" -Description "Session host traffic to AVD control plane" -Access Allow -Protocol Tcp -Direction Outbound -Priority 100 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "WindowsVirtualDesktop" -DestinationPortRange "443"
            $NSGRuleAzureCloud = New-AzNetworkSecurityRuleConfig -Name "AzureCloud" -Description "Session host traffic to Azure cloud services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 110 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureCloud" -DestinationPortRange "8443"
            $NSGRuleAzureMonitor = New-AzNetworkSecurityRuleConfig -Name "AzureMonitor" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureMonitor" -DestinationPortRange "443"
            $NSGRuleAzureMarketPlace = New-AzNetworkSecurityRuleConfig -Name "AzureMarketPlace" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureFrontDoor.Frontend" -DestinationPortRange "443"
            $NSGRuleWindowsActivationKMS = New-AzNetworkSecurityRuleConfig -Name "WindowsActivationKMS" -Description "Session host traffic to Windows license activation services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 140 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix @("20.118.99.224", "40.83.235.53", "23.102.135.246") -DestinationPortRange "1688"
            $NSGRuleAzureInstanceMetadata = New-AzNetworkSecurityRuleConfig -Name "AzureInstanceMetadata" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Tcp -Direction Outbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "169.254.169.254" -DestinationPortRange "80"
            $NSGRuleRDPShortpath = New-AzNetworkSecurityRuleConfig -Name "RDPShortpath" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Udp -Direction Inbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "VirtualNetwork" -DestinationPortRange "3390"
            $NSGRuleRDPShortpathTurnStun = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnStun" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 160 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "20.202.0.0/16" -DestinationPortRange "3478"
            $NSGRuleRDPShortpathTurnRelay = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnRelay" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 170 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "51.5.0.0/16" -DestinationPortRange "3478"

            #Aggregating all the AVD NSG rules into a single collection
            $NSGRules = @(
                $NSGRuleAVDServiceTraffic,
                $NSGRuleAzureCloud,
                $NSGRuleAzureMonitor,
                $NSGRuleAzureMarketPlace,
                $NSGRuleWindowsActivationKMS,
                $NSGRuleAzureInstanceMetadata,
                $NSGRuleRDPShortpath,
                $NSGRuleRDPShortpathTurnStun,
                $NSGRuleRDPShortpathTurnRelay
            )

            # --- Create NSG with all rules ---
            #Creating the AVD NSG, the AVD subnet (attaching the NSG) and finally the virtual network hosting that subnet
            $NetworkSecurityGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Network Security Group '$NetworkSecurityGroupName' with the AVD security rules ..." -ForegroundColor Cyan
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location -SecurityRules $NSGRules
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Network Security Group '$NetworkSecurityGroupName' has been created." -ForegroundColor Green
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the virtual network '$VirtualNetworkName' with the AVD subnet '$SubnetName' ('$SubnetAddressPrefix') ..." -ForegroundColor Cyan
            $Subnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetAddressPrefix -NetworkSecurityGroup $NetworkSecurityGroup -DefaultOutboundAccess $true
            $VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -AddressPrefix $AddressRange -Location $Location -Subnet $Subnet
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The virtual network '$VirtualNetworkName' has been created." -ForegroundColor Green
            #endregion

            #region PE Subnet
            #Creating a dedicated subnet (with its own empty NSG) for Private Endpoints
            #region PE Subnet Name
            $Role = "pe"
            $SubnetName = '{0}-{1}-{2}-{3}-{4:D3}' -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
            $SubnetName = $SubnetName.ToLower()
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"
            #endregion

            #region PE Subnet Address Prefix Calculation by taking the Subnet with the Highest Address Prefix incrementing the third octect to 1 (10.0.0.0 ==> 10.0.1.0)
            $Octet3++
            $SubnetAddressPrefix = $AddressRange -replace $RegExpPattern, "`$1.`$2.$Octet3.`$4/27"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetAddressPrefix: $SubnetAddressPrefix"
            #endregion

            # --- Create NSG ---
            $NetworkSecurityGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Private Endpoint Network Security Group '$NetworkSecurityGroupName' ..." -ForegroundColor Cyan
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Private Endpoint Network Security Group '$NetworkSecurityGroupName' has been created." -ForegroundColor Green
            $Subnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetAddressPrefix -NetworkSecurityGroup $NetworkSecurityGroup -DefaultOutboundAccess $true

            #region Add the PE subnet to vnet
            $VirtualNetwork.Subnets += $Subnet
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating vNet: $($VirtualNetwork.Name)"
            #$null = $VirtualNetwork | Set-AzVirtualNetwork
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the Private Endpoint subnet '$SubnetName' ('$SubnetAddressPrefix') to the virtual network '$($VirtualNetwork.Name)' ..." -ForegroundColor Cyan
            $VirtualNetwork | Set-AzVirtualNetwork
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Private Endpoint subnet '$SubnetName' has been added to '$($VirtualNetwork.Name)'." -ForegroundColor Green
            #endregion

            #endregion
        }
        #endregion
    }
    end {}
}

<#
.SYNOPSIS
    Establishes a one-way virtual network peering between two Azure virtual networks.
.DESCRIPTION
    Creates the peering (allowing forwarded traffic) only when it does not already exist, and verifies the resulting peering state is either Initiated or Connected. Call it twice (swapping the arguments) to obtain a bidirectional peering.
#>
function Add-PsAvdVirtualNetworkPeering {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $RemoteVirtualNetwork
    )
    #$VirtualNetworkPeeringName = "$($VirtualNetwork.Name)-$($RemoteVirtualNetwork.Name)"
    #Building the peering name from both virtual network names
    $VirtualNetworkPeeringName = "peer-{0}-{1}" -f $VirtualNetwork.Name, $RemoteVirtualNetwork.Name
    if (-not(Get-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetworkName $VirtualNetwork.Name -ResourceGroupName $VirtualNetwork.ResourceGroupName -ErrorAction Ignore)) {
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the virtual network peering '$VirtualNetworkPeeringName' from '$($VirtualNetwork.Name)' to '$($RemoteVirtualNetwork.Name)' ..." -ForegroundColor Cyan
        $vNetPeeringStatus = Add-AzVirtualNetworkPeering -Name $VirtualNetworkPeeringName -VirtualNetwork $VirtualNetwork -RemoteVirtualNetworkId $RemoteVirtualNetwork.Id -AllowForwardedTraffic
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The virtual network peering '$VirtualNetworkPeeringName' has been created (state: $($vNetPeeringStatus.PeeringState))." -ForegroundColor Green
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$VirtualNetworkPeeringName': '$($VirtualNetwork.Name)' <==> '$($RemoteVirtualNetwork.Name)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$vNetPeeringStatus: $($vNetPeeringStatus.PeeringState)"
        if ($vNetPeeringStatus.PeeringState -notin 'Initiated' , 'Connected') {
            Write-Error "The '$VirtualNetworkPeeringName' peering state is '$($vNetPeeringStatus.PeeringState)'" #-ErrorAction Stop
        }
    }
    else {
        Write-Warning "The '$VirtualNetworkPeeringName' peering already exists"
    }
}

<#
.SYNOPSIS
    Provisions an Azure NAT Gateway and associates it with a subnet to provide outbound internet connectivity.
.DESCRIPTION
    Depending on the parameter set, the NAT Gateway is either attached to an existing subnet (Subnet parameter set) or a brand new dedicated subnet is created and attached (VirtualNetwork parameter set). A Standard static public IP address is created for the gateway and the virtual network is updated accordingly.
#>
function New-PsAvdNatGatewaySetup {
    [CmdletBinding(PositionalBinding = $false)]
    Param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'VirtualNetwork')]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Subnet')]
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
        $ResourceGroupName = $VirtualNetwork.ResourceGroupName
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
        $Location = $VirtualNetwork.Location
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
        $LocationShortName = $shortNameHT[$Location].shortName

        if ($SubnetConfig) {
            #A subnet was supplied: resolve its parent virtual network so we can update it later
            $VirtualNetworkId = $SubnetConfig.Id -replace "/subnets/.*"
            $VirtualNetwork = Get-AzResource -ResourceId $VirtualNetworkId | Get-AzVirtualNetwork
        }
        else {
            #If we create a dedicated subnet we also create a dedicated NSG.
            $NetworkSecurityGroupName = $VirtualNetwork.Name -replace $VirtualNetworkPrefix, $NetworkSecurityGroupPrefix -replace "(\w+)-(\w+)-(\w+)-(\w+)-(\d+)", '$1-$2-natgw-$4-$5'
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NetworkSecurityGroupName: $NetworkSecurityGroupName"
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Network Security Group '$NetworkSecurityGroupName' for the NAT Gateway subnet ..." -ForegroundColor Cyan
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location -Force
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Network Security Group '$NetworkSecurityGroupName' has been created." -ForegroundColor Green
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
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Standard static public IP address '$NatGatewayPublicIpName' ..." -ForegroundColor Cyan
        $PublicIp = New-AzPublicIpAddress @IP
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The public IP address '$NatGatewayPublicIpName' has been created." -ForegroundColor Green
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
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the NAT Gateway '$NatGatewayName' ..." -ForegroundColor Cyan
        $NatGateway = New-AzNatGateway @Nat
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The NAT Gateway '$NatGatewayName' has been created." -ForegroundColor Green
        #endregion 

        if ($SubnetConfig) {
            #Attaching the NAT Gateway to the existing subnet passed in
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating SubNet: $($SubnetConfig.Name)"
            ($VirtualNetwork.Subnets | Where-Object -FilterScript { $_.Id -eq $SubnetConfig.Id }).NatGateway = $NatGateway
        }
        else {
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
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Associating the NAT Gateway '$NatGatewayName' with the virtual network '$($VirtualNetwork.Name)' ..." -ForegroundColor Cyan
        $null = $VirtualNetwork | Set-AzVirtualNetwork
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The NAT Gateway '$NatGatewayName' has been associated with '$($VirtualNetwork.Name)'." -ForegroundColor Green
        #endregion
    }
    end {}
}

<#
.SYNOPSIS
    Deploys a self-contained Active Directory Domain Services lab in Azure used as the identity backbone for an Azure Virtual Desktop (AVD) hybrid environment.
.DESCRIPTION
    Creates the resource group, storage account, networking (AD VNet + AVD VNet with NAT Gateways and peering, optional Azure Bastion), and a domain controller VM. The VM is promoted to a domain controller (and seeded with sample users) through a DSC extension downloaded from GitHub. The function also configures Just-In-Time (JIT) access, an auto-shutdown schedule, and finally opens an RDP session to the new domain controller.
#>
function New-AAD-Hybrid-Lab {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [parameter(Mandatory = $true, HelpMessage = 'Please specify the administrator credential. The Username cannot be "Administrator", "root" and possibly other such common account names.')]
        [PSCredential] $AdminCredential,
        [parameter(Mandatory = $true, HelpMessage = 'Enter the password that will be applied to each user account to be created in AD.')]
        [PSCredential] $UserCredential,
        [parameter(Mandatory = $false, HelpMessage = 'Select a VM SKU (please ensure the SKU is available in your selected region).')]
        [string] $VMSize = "Standard_D4s_v7",
        [parameter(Mandatory = $false, HelpMessage = 'Select an OS Disk Type')]
        [ValidateSet("StandardSSD_LRS", "Premium_LRS")] 
        [string] $OSDiskType = "StandardSSD_LRS",
        [parameter(Mandatory = $false, HelpMessage = 'Please specify the project')]
        [ValidateLength(2, 4)] 
        [string] $Project = "avd",
        [parameter(Mandatory = $false, HelpMessage = 'Please specify the role')]
        [ValidateLength(2, 4)] 
        [string] $Role = "ad",
        [parameter(Mandatory = $false, HelpMessage = 'IMPORTANT: Two-part internal AD name - short/NB name will be first part ("contoso"). The short name will be reused and should be unique when deploying this template in your selected region. If a name is reused, DNS name collisions may occur.')]
        [ValidatePattern("\w+\.\w+")] 
        [string] $ADDomainName = "contoso.local",
        [parameter(Mandatory = $false, HelpMessage = 'This needs to be specified in order to have a uniform logon experience within AVD')]
        [ValidatePattern("\w+\.\w+")] 
        [string] $CustomUPNSuffix = $((Get-AzTenant).DefaultDomain),
        [parameter(Mandatory = $false, HelpMessage = 'The address range of the new virtual network in CIDR format')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{2}")] 
        [string] $VNetAddressRange = '10.0.0.0/16',
        [parameter(Mandatory = $false, HelpMessage = 'The address range of the desired subnet for Active Directory.')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{2}")] 
        [string] $ADSubnetAddressRange = '10.0.1.0/24',
        [parameter(Mandatory = $false, HelpMessage = 'The IP Addresses assigned to the domain controllers (a, b). Remember the first IP in a subnet is .4 e.g. 10.0.0.0/16 reserves 10.0.0.0-3. Specify one IP per server - must match numberofVMInstances or deployment will fail.')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}")] 
        [string] $DomainControllerIP = '10.0.1.4',
        [parameter(Mandatory = $false, HelpMessage = 'The instance number for your deployment.')]
        [ValidateScript({ $_ -in 0..999 })] 
        [int] $Instance = $(Get-Random -Minimum 0 -Maximum 1000),
        [parameter(Mandatory = $false, HelpMessage = 'The Azure location where you want to deploy your ressources.')]
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })] 
        [string] $Location = "CentralUS",
        [switch] $Spot,
        [switch] $Bastion
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMSize: $VMSize"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Project: $Project"         
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Role: $Role"         
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ADDomainName: $ADDomainName"       
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CustomUPNSuffix: $CustomUPNSuffix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VNetAddressRange: $VNetAddressRange"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ADSubnetAddressRange: $ADSubnetAddressRange"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DomainControllerIP: $DomainControllerIP"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Instance: $Instance"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Spot: $Spot"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Bastion: $Bastion"

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    $AzureVMNameMaxLength = 15
    $RDPPort = 3389
    #JIT (Just-In-Time) access settings: how long temporary RDP access is granted and the policy name
    $JitPolicyTimeInHours = 3
    $JitPolicyName = "Default"
    $LocationShortName = $shortNameHT[$Location].shortName
    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $ResourceGroupPrefix = "rg"
    $StorageAccountPrefix = "sa"
    $VirtualMachinePrefix = "vm"
    $NetworkSecurityGroupPrefix = "nsg"
    $VirtualNetworkPrefix = "vnet"
    $SubnetPrefix = "snet"

    #Building the standardized resource names from the prefixes, project, role, location short name and instance number
    $StorageAccountName = '{0}{1}{2}{3}{4:D3}' -f $StorageAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VMName = '{0}{1}{2}{3}{4:D3}' -f $VirtualMachinePrefix, $Project, $Role, $LocationShortName, $Instance                       
    $NetworkSecurityGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VirtualNetworkName = '{0}-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $SubnetName = '{0}-{1}-{2}-{3}-{4:D3}' -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $ResourceGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       


    $StorageAccountName = $StorageAccountName.ToLower()
    $VMName = $VMName.ToLower()
    $NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
    $VirtualNetworkName = $VirtualNetworkName.ToLower()
    $SubnetName = $SubnetName.ToLower()
    $ResourceGroupName = $ResourceGroupName.ToLower()

    $UserArray = @(
        #Sample AD user accounts created in the lab domain by the DSC configuration
        @{"FName" = "Bob"; "LName" = "Jones"; "SAM" = "bjones" }
        @{"FName" = "Bill"; "LName" = "Smith"; "SAM" = "bsmith" }
        @{"FName" = "Mary"; "LName" = "Phillips"; "SAM" = "mphillips" }
        @{"FName" = "Sue"; "LName" = "Jackson"; "SAM" = "sjackson" }
        @{"FName" = "Jack"; "LName" = "Petersen"; "SAM" = "jpetersen" }
        @{"FName" = "Julia"; "LName" = "Williams"; "SAM" = "jwilliams" }
    )


    $FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()

    #Deleting any pre-existing resource group with the same name so we start from a clean slate
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($ResourceGroup) {
        #Remove previously existing Azure Resource Group with the same name
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing the pre-existing resource group '$ResourceGroupName' (and all its resources) ..." -ForegroundColor Yellow
        $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The pre-existing resource group '$ResourceGroupName' has been removed." -ForegroundColor Green
    }
    #Retrieving the caller's public IP address to scope inbound RDP firewall rules
    $MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"

    #region Define Variables needed for Virtual Machine
    $Image = @{
        Publisher = 'MicrosoftWindowsServer'
        Offer     = 'WindowsServer'    
        Sku       = '2025-datacenter-azure-edition'  
        Version   = 'latest'
    }

    $PublicIPName = "pip-$VMName" 
    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName          = "$VMName-DataDisk01"
    $OSDiskSize = "127"
    $StorageAccountSkuName = "Standard_LRS"
    $DSCZipFileUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell/DSC/adDSC.zip"
    $DSCConfigurationName = "DomainController"

    #Arguments passed to the DSC configuration to promote the VM as a domain controller and seed users
    $DSCConfigurationArguments = @{ 
        ADDomainName    = $ADDomainName
        customupnsuffix = $CustomUPNSuffix
        AdminCreds      = $AdminCredential
        usersArray      = $UserArray
        UserCreds       = $UserCredential
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VMName: $VMName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkName: $VirtualNetworkName"         
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubnetName: $SubnetName"       
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$PublicIPName: $PublicIPName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$NICName: $NICName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OSDiskName: $OSDiskName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$FQDN: $FQDN"
    #endregion
    #endregion


    if ($VMName.Length -gt $AzureVMNameMaxLength) {
        #Pre-flight validation: name length, location short name, storage account name availability, DNS label availability and VM size availability
        Write-Error "'$VMName' exceeds $AzureVMNameMaxLength characters" -ErrorAction Stop
    }
    elseif (-not($LocationShortName)) {
        Write-Error "No location short name found for '$Location'" -ErrorAction Stop
    }
    elseif (-not(Get-AzStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable) {
        Write-Error "The storage account name '$StorageAccountName' is NOT available" -ErrorAction Stop
    }
    elseif (-not(Test-AzDnsAvailability -DomainNameLabel $VMName -Location $Location)) {
        Write-Error "$FQDN is NOT available" -ErrorAction Stop
    }
    elseif ($null -eq (Get-AzComputeResourceSku -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
    }

    #Create Azure Resource Group
    # Create Resource Groups
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the resource group '$ResourceGroupName' in the '$Location' location ..." -ForegroundColor Cyan
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The resource group '$ResourceGroupName' has been created." -ForegroundColor Green

    #Create Azure Storage Account
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the storage account '$StorageAccountName' (used to publish the DSC configuration) ..." -ForegroundColor Cyan
    $StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl = "Ignore" }
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The storage account '$StorageAccountName' has been created." -ForegroundColor Green

    #Create Azure Network Security Group
    #RDP only for my public IP address
    #Shared parameters reused across all the AD-related inbound rules
    $CommonParameters = @{
        'SourceAddressPrefix'      = 'VirtualNetwork'
        'SourcePortRange'          = '*'
        'DestinationAddressPrefix' = $ADSubnetAddressRange
        'Access'                   = 'Allow'
        'Direction'                = 'Inbound' 
    }
    $SecurityRules = @(
        #region Inbound
        New-AzNetworkSecurityRuleConfig -Name allow_AD_RDP -Description "Allow RDP Communication" -Protocol Tcp -SourcePortRange * -DestinationPortRange $RDPPort -SourceAddressPrefix $MyPublicIp -DestinationAddressPrefix $ADSubnetAddressRange -Access Allow  -Priority 120 -Direction Inbound 
        New-AzNetworkSecurityRuleConfig -Name allow_AD_SMTP -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 25 -Priority 121 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_WINS -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 42 -Priority 122 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_Repl -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 135 -Priority 123 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_NetBIOS -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 137 -Priority 124 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_netlogin -Description 'Allow AD Communication - DFSN, NetBIOS Session, NetLogon' -Protocol Tcp -DestinationPortRange 139 -Priority 125 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_LDAP -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 389 -Priority 126 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_LDAP_udp -Description 'Allow AD Communication' -Protocol Udp -DestinationPortRange 389 -Priority 127 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_LDAPS -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 636 -Priority 128 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_LDAP_GC -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 3268-3269 -Priority 129 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_KRB -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 88 -Priority 130 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_KRB_udp -Description 'Allow AD Communication' -Protocol Udp -DestinationPortRange 88 -Priority 131 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_DNS -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 53 -Priority 132 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_DNS_udp -Description 'Allow AD Communication' -Protocol Udp -DestinationPortRange 53 -Priority 133 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_445 -Description 'Allow AD Communication - SMB, CIFS,SMB2, DFSN, LSARPC, NbtSS, NetLogonR, SamR, SrvSvc' -Protocol Tcp -DestinationPortRange 445 -Priority 134 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_445_udp -Description 'Allow AD Communication - SMB, CIFS,SMB2, DFSN, LSARPC, NbtSS, NetLogonR, SamR, SrvSvc' -Protocol Udp -DestinationPortRange 445 -Priority 135 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_SOAP -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 9389 -Priority 136 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_DFSR -Description 'Allow AD Communication - DFSR/Sysvol' -Protocol Tcp -DestinationPortRange 5722 -Priority 137 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_KRB2 -Description 'Allow AD Communication - Kerberos change/set password' -Protocol Tcp -DestinationPortRange 464 -Priority 138 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_KRB2_udp -Description 'Allow AD Communication - Kerberos change/set password' -Protocol Udp -DestinationPortRange 464 -Priority 139 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_time -Description 'Allow AD Communication - Windows Time Protocol' -Protocol Udp -DestinationPortRange 123 -Priority 140 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_auth -Description 'Allow AD Communication' -Protocol Udp -DestinationPortRange 137-138 -Priority 141 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_ephemeral -Description 'Allow AD Communication' -Protocol Tcp -DestinationPortRange 49152-65535 -Priority 142 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_AD_ephemeral_udp -Description 'Allow AD Communication' -Protocol Udp -DestinationPortRange 49152-65535 -Priority 143 @CommonParameters
        New-AzNetworkSecurityRuleConfig -Name allow_WinRM_vNet -Description 'Allow WinRM sessions within the vNet' -Protocol Tcp -DestinationPortRange 5985-5986 -Priority 198 @CommonParameters
        #endregion
        <#
        #region Outbound
        #Only Allow AVD OutBound traffic
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/safe-url-list?tabs=azure#session-host-virtual-machines
        New-AzNetworkSecurityRuleConfig -Name Allow_AVD_OutBound -Description 'Allow AVD OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "WindowsVirtualDesktop" -DestinationPortRange 443 -Protocol Tcp -Access Allow -Priority 1000  -Direction Outbound 
        New-AzNetworkSecurityRuleConfig -Name Allow_AzureCloud_OutBound -Description 'Allow AzureCloud OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "AzureCloud" -DestinationPortRange 443 -Protocol Tcp -Access Allow -Priority 1010  -Direction Outbound 
        New-AzNetworkSecurityRuleConfig -Name Allow_KMS_OutBound -Description 'Allow KMS OutBound to kms.core.windows.net' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "Internet" -DestinationPortRange 1688 -Protocol Tcp -Access Allow -Priority 1020  -Direction Outbound 
        New-AzNetworkSecurityRuleConfig -Name Allow_AzureFrontDoor_OutBound -Description 'Allow AzureFrontDoor OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "AzureFrontDoor.FrontEnd" -DestinationPortRange 443 -Protocol Tcp -Access Allow -Priority 1030  -Direction Outbound 
        New-AzNetworkSecurityRuleConfig -Name Allow_AzureMonitor_OutBound -Description 'Allow AzureMonitor OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "AzureMonitor" -DestinationPortRange 443 -Protocol Tcp -Access Allow -Priority 1040  -Direction Outbound 
        New-AzNetworkSecurityRuleConfig -Name Allow_HTTP_HTTPS_OutBound -Description 'Allow HTTP/HTTPS OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix "Internet" -DestinationPortRange 80,443 -Protocol Tcp -Access Allow -Priority 1050  -Direction Outbound 
        #To be continued ...
        #endregion
        #>
    )

    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Network Security Group '$NetworkSecurityGroupName' with the Active Directory security rules ..." -ForegroundColor Cyan
    $NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Network Security Group '$NetworkSecurityGroupName' has been created." -ForegroundColor Green

    #Create Azure Virtual network using the virtual network subnet configuration
    #Creating the AD subnet, then the AD virtual network hosting it
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the AD virtual network '$VirtualNetworkName' with the subnet '$SubnetName' ('$ADSubnetAddressRange') ..." -ForegroundColor Cyan
    $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $ADSubnetAddressRange -NetworkSecurityGroup $NetworkSecurityGroup -DefaultOutboundAccess $true
    $vNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VNetAddressRange -Location $Location -Subnet $Subnet
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The AD virtual network '$VirtualNetworkName' has been created." -ForegroundColor Green
    #Adding a NAT Gateway
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding a NAT Gateway to the AD virtual network '$VirtualNetworkName' ..." -ForegroundColor Cyan
    $vNetwork | New-PsAvdNatGatewaySetup -Force -Verbose
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The NAT Gateway has been added to the AD virtual network '$VirtualNetworkName'." -ForegroundColor Green

    #Adding an AVD Vnet
    #Creating the separate AVD virtual network and giving it its own NAT Gateway
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the dedicated AVD virtual network ..." -ForegroundColor Cyan
    $vAVDNetwork = New-PsAvdVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Instance $Instance -Verbose
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The dedicated AVD virtual network '$($vAVDNetwork.Name)' has been created." -ForegroundColor Green
    #Adding a NAT Gateway
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding a NAT Gateway to the AVD virtual network '$($vAVDNetwork.Name)' ..." -ForegroundColor Cyan
    $vAVDNetwork | New-PsAvdNatGatewaySetup -Force -Verbose
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The NAT Gateway has been added to the AVD virtual network '$($vAVDNetwork.Name)'." -ForegroundColor Green

    #VNet Peering
    #Peering the AD and AVD virtual networks in both directions
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the bidirectional peering between the AD and AVD virtual networks ..." -ForegroundColor Cyan
    Add-PsAvdVirtualNetworkPeering -VirtualNetwork $vNetwork -RemoteVirtualNetwork $vAVDNetwork -Verbose
    Add-PsAvdVirtualNetworkPeering -VirtualNetwork $vAVDNetwork -RemoteVirtualNetwork $vNetwork -Verbose
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The bidirectional peering between the AD and AVD virtual networks has been created." -ForegroundColor Green

    <#
    $vNetwork = Set-AzVirtualNetwork -VirtualNetwork $vNetwork
    $Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNetwork
    #>
    if ($Bastion) {
        #Optionally deploying Azure Bastion (dedicated subnet, NSG, public IP and Bastion host) for secure RDP/SSH access without exposing public IPs
        
        #Generation Bastion Subnet Address Range by getting the subnets and finding the third token available in the IP.
        $ThirdToken = (Get-AzVirtualNetwork -Name $VirtualNetworkName).Subnets.AddressPrefix -replace "\d+\.\d+\.(\d+)\.\d\/.*", '$1' | Sort-Object
        $ThirdTokenAvailable = 1..254 | Where-Object -FilterScript { $_ -notin $ThirdToken }
        $BastionSubnetAddressRange = (Get-AzVirtualNetwork -Name $VirtualNetworkName).Subnets.AddressPrefix | Sort-Object | Select-Object -Last 1
        $BastionSubnetAddressRange -match '(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)'
        #$BastionSubnetAddressRange = "{0}.{1}.{2}.0/26" -f $Matches[1], $Matches[2], ([int]$Matches[3]+1)
        $BastionSubnetAddressRange = "{0}.{1}.{2}.0/26" -f $Matches[1], $Matches[2], $ThirdTokenAvailable[0]

        $BastionSecurityRules = @(
            #From https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg#apply
            #region Inbound
            New-AzNetworkSecurityRuleConfig -Name AllowHttpsInBound -Description "Allow Https InBound" -Protocol Tcp -SourcePortRange * -DestinationPortRange 443 -SourceAddressPrefix 'Internet' -DestinationAddressPrefix * -Access Allow  -Priority 120 -Direction Inbound 
            New-AzNetworkSecurityRuleConfig -Name AllowGatewayManagerInBound -Description "Allow Gateway Manager InBound" -Protocol Tcp -SourcePortRange * -DestinationPortRange 443 -SourceAddressPrefix 'GatewayManager' -DestinationAddressPrefix * -Access Allow  -Priority 130 -Direction Inbound 
            New-AzNetworkSecurityRuleConfig -Name AllowAzureLoadBalancerInBound -Description "AllowAzureLoad Balancer InBound" -Protocol Tcp -SourcePortRange * -DestinationPortRange 443 -SourceAddressPrefix 'AzureLoadBalancer' -DestinationAddressPrefix * -Access Allow  -Priority 140 -Direction Inbound 
            New-AzNetworkSecurityRuleConfig -Name AllowBastionHostcommunication -Description "Allow Azure LoadBalancer" -Protocol * -SourcePortRange * -DestinationPortRange 8080, 5701 -SourceAddressPrefix 'VirtualNetwork' -DestinationAddressPrefix 'VirtualNetwork' -Access Allow  -Priority 150 -Direction Inbound 
            #endregion
            #region Outbound
            New-AzNetworkSecurityRuleConfig -Name AllowSshRdpOutBound -Description 'Allow Ssh Rdp OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange 22, 3389 -Protocol * -Access Allow -Priority 100 -Direction Outbound 
            New-AzNetworkSecurityRuleConfig -Name AllowAzureCloudOutBound -Description 'Allow Azure Cloud OutBound' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix 'AzureCloud' -DestinationPortRange 443 -Protocol Tcp -Access Allow -Priority 110 -Direction Outbound 
            New-AzNetworkSecurityRuleConfig -Name AllowBastionCommunication -Description 'Allow Bastion Communication' -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange * -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange 8080, 5071 -Protocol * -Access Allow -Priority 120 -Direction Outbound 
            New-AzNetworkSecurityRuleConfig -Name AllowGetSessionInformation -Description 'Allow Get Session Information' -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix 'Internet' -DestinationPortRange 80 -Protocol * -Access Allow -Priority 130 -Direction Outbound 
            #endregion
            #>
        )
        $BastionNetworkSecurityGroupName = '{0}-bastion-{1}-{2}-{3}-{4:D3}' -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$BastionNetworkSecurityGroupName: $BastionNetworkSecurityGroupName"         

        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Bastion Network Security Group '$BastionNetworkSecurityGroupName' ..." -ForegroundColor Cyan
        $BastionNetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $BastionNetworkSecurityGroupName -SecurityRules $BastionSecurityRules -Force
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Bastion Network Security Group '$BastionNetworkSecurityGroupName' has been created." -ForegroundColor Green

        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the 'AzureBastionSubnet' ('$BastionSubnetAddressRange') to the virtual network '$VirtualNetworkName' ..." -ForegroundColor Cyan
        Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vNetwork -AddressPrefix $BastionSubnetAddressRange -NetworkSecurityGroupId $BastionNetworkSecurityGroup.Id | Set-AzVirtualNetwork
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The 'AzureBastionSubnet' has been added." -ForegroundColor Green
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Bastion public IP address '$VirtualNetworkName-ip' ..." -ForegroundColor Cyan
        $publicip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$VirtualNetworkName-ip" -Location $Location -AllocationMethod Static -Sku Standard
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Bastion public IP address '$VirtualNetworkName-ip' has been created." -ForegroundColor Green
        $BastionVirtualNetworkName = '{0}-bastion-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
        $BastionVirtualNetworkName = $BastionVirtualNetworkName.ToLower()
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting the (asynchronous) deployment of the Bastion host '$BastionVirtualNetworkName' ..." -ForegroundColor Cyan
        $BastionJob = New-AzBastion -ResourceGroupName $ResourceGroupName -Name $BastionVirtualNetworkName -PublicIpAddressRgName $ResourceGroupName -PublicIpAddressName "$VirtualNetworkName-ip" -VirtualNetworkRgName $ResourceGroupName -VirtualNetworkName $VirtualNetworkName -Sku "Basic" -AsJob
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Bastion host '$BastionVirtualNetworkName' deployment has been started (running in the background)." -ForegroundColor Green

        #Adding Security Rules for allowing connection from Bastion
        #RDP
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the RDP and SSH inbound rules from the Bastion subnet to the AD Network Security Group '$NetworkSecurityGroupName' ..." -ForegroundColor Cyan
        Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NetworkSecurityGroupName | `
            Add-AzNetworkSecurityRuleConfig -Name allow_Bastion_RDP -Description "Allow RDP Communication from Bastion" -Protocol Tcp -SourcePortRange * -DestinationPortRange $RDPPort -SourceAddressPrefix $BastionSubnetAddressRange -DestinationAddressPrefix 'VirtualNetwork' -Access Allow  -Priority 101 -Direction Inbound | Set-AzNetworkSecurityGroup
        #SSH
        Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NetworkSecurityGroupName | `
            Add-AzNetworkSecurityRuleConfig -Name allow_Bastion_SSH -Description "Allow SSH Communication from Bastion" -Protocol Tcp -SourcePortRange * -DestinationPortRange 22 -SourceAddressPrefix $BastionSubnetAddressRange -DestinationAddressPrefix 'VirtualNetwork' -Access Allow  -Priority 102 -Direction Inbound | Set-AzNetworkSecurityGroup
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The RDP and SSH inbound rules from the Bastion subnet have been added." -ForegroundColor Green
    }

    #Create Azure Public Address
    #Public IP (with DNS label) attached to the domain controller VM
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the public IP address '$PublicIPName' for the domain controller VM ..." -ForegroundColor Cyan
    $PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -DomainNameLabel $VMName.ToLower()
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The public IP address '$PublicIPName' has been created." -ForegroundColor Green
    #Setting up the DNS Name
    #$PublicIP.DnsSettings.Fqdn = $FQDN

    #Create Network Interface Card 
    #NIC pinned to the static domain controller IP address on the AD subnet
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the network interface card '$NICName' (static private IP '$DomainControllerIP') ..." -ForegroundColor Cyan
    $subnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $vNetwork
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $Subnet.Id -PublicIpAddressId $PublicIP.Id -PrivateIpAddress $DomainControllerIP
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The network interface card '$NICName' has been created." -ForegroundColor Green

    # Create a virtual machine configuration file (As a Spot Intance)
    #Using a Spot instance (cheaper, evictable) when -Spot is specified, otherwise a regular VM
    if ($Spot) {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1
    }
    else {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    }

    $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    #Set VM operating system parameters
    $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $AdminCredential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

    #Set boot diagnostic storage account
    #Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
    #Set boot diagnostic to managed storage account
    $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    #Set virtual machine source image
    Set-AzVMSourceImage -VM $VMConfig -PublisherName $Image.Publisher -Offer $Image.Offer -Skus $Image.Sku -Version $Image.Version

    #Set OsDisk configuration
    $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

    #region Adding Data Disk
    <#
    $VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
    $VMDataDisk01       = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
    $VM                 = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
    #>
    #endregion

    #Create Azure Virtual Machine
    #Provisioning the domain controller VM from the assembled configuration
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the domain controller virtual machine '$VMName' (size '$VMSize') ..." -ForegroundColor Cyan
    $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig #-DisableBginfoExtension
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The domain controller virtual machine '$VMName' has been created." -ForegroundColor Green

    #Updating the DNS Servers of the VNet to point to the DC.
    #Pointing both virtual networks DNS to the new domain controller so joined machines can resolve the domain
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating the DNS servers of both virtual networks to point to the domain controller ('$DomainControllerIP') ..." -ForegroundColor Cyan
    $vNetwork.DhcpOptions = [PSCustomObject]@{"DnsServers" = $DomainControllerIP }
    $null = $vNetwork | Set-AzVirtualNetwork
    $vAVDNetwork.DhcpOptions = [PSCustomObject]@{"DnsServers" = $DomainControllerIP }
    $null = $vAVDNetwork | Set-AzVirtualNetwork
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The DNS servers of both virtual networks now point to '$DomainControllerIP'." -ForegroundColor Green

    $VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
    #region JIT Access Management
    #region Enabling JIT Access
    $NewJitPolicy = (@{
            id    = $VM.Id
            ports = (@{
                    number                     = $RDPPort;
                    protocol                   = "*";
                    allowedSourceAddressPrefix = "*";
                    maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
                })   
        })


    Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
    $ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
    $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
    $UpdatedJITPolicy.Add($NewJitPolicy)
	
    #! Enable Access to the VM including management Port, and Time Range in Hours
    Write-Host "Enabling Just in Time VM Access Policy for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
    $null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
    #endregion

    #region Requesting Temporary Access : 3 hours
    #Immediately requesting temporary JIT RDP access (3 hours) from the caller's public IP
    $JitPolicy = (@{
            id    = $VM.Id
            ports = (@{
                    number                     = $RDPPort;
                    endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                    allowedSourceAddressPrefix = @($MyPublicIP) 
                })
        })
    $ActivationVM = @($JitPolicy)
    Write-Host "Requesting Temporary Acces via Just in Time for ($VMName) on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
    $null = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
    #endregion

    #endregion

    #region Enabling auto-shutdown at 11:00 PM in the user time zome
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Enabling the daily auto-shutdown schedule (23:00 $((Get-TimeZone).Id)) for the VM '$VMName' ..." -ForegroundColor Cyan
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
    $Properties = @{}
    $Properties.Add('status', 'Enabled')
    $Properties.Add('taskType', 'ComputeVmShutdownTask')
    $Properties.Add('dailyRecurrence', @{'time' = "2300" })
    $Properties.Add('timeZoneId', (Get-TimeZone).Id)
    $Properties.Add('targetResourceId', $VM.Id)
    $null = New-AzResource -Location $location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force -ErrorAction Ignore
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The daily auto-shutdown schedule for '$VMName' has been enabled." -ForegroundColor Green
    #endregion
    #Start Azure Virtual Machine
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting the virtual machine '$VMName' ..." -ForegroundColor Cyan
    $null = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The virtual machine '$VMName' has been started." -ForegroundColor Green

    #region Setting up the DSC extension
    # Publishing DSC Configuration 
    #Downloading, extracting and publishing the DSC package, then applying it via the DSC VM extension to promote the domain controller
    $DSCZipFileName = Split-Path -Path $DSCZipFileUri -Leaf
    $DSCZipLocalFilePath = Join-Path -Path $env:TEMP -ChildPath $DSCZipFileName
    #Downloading the zip file from the Gitbub repository (We use the same Zip file that the one use for the ARM template deployment to avoid content duplication)
    Invoke-RestMethod -Uri $DSCZipFileUri -OutFile $DSCZipLocalFilePath -Verbose
    if (Test-Path -Path $DSCZipLocalFilePath) {
        $DestinationFolder = Join-Path -Path $env:TEMP -ChildPath $((Get-Item -Path $DSCZipLocalFilePath).BaseName)
        #Extracting the files from the downoaded zip file
        Expand-Archive -Path $DSCZipLocalFilePath -DestinationPath $DestinationFolder -Verbose -Force 
        #Getting only the .ps1 file
        $DSCConfigurationFile = (Get-ChildItem -Path $DestinationFolder -Filter *.ps1 -File | Select-Object -First 1).Fullname
        #Getting only the module folders
        #$ModuleFolders = (Get-ChildItem -Path $DestinationFolder -Directory).FullName
        #Copying the module folders locally to avoid an error when using the Publish-AzVMDscConfiguration cmdlet
        #Copy-Item -Path $ModuleFolders -Destination $env:ProgramFiles\WindowsPowerShell\Modules -Recurse -Force -Verbose
        #Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl="Ignore" }
        $null = $StorageAccount | Set-AzStorageAccount -PublicNetworkAccess Enabled -AllowBlobPublicAccess $true -AllowSharedKeyAccess $true -Tag @{ SecurityControl = "Ignore" }
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Publishing the DSC configuration to the storage account '$StorageAccountName' ..." -ForegroundColor Cyan
        $DSCConfigurationZipFileURI = Publish-AzVMDscConfiguration $DSCConfigurationFile -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The DSC configuration has been published." -ForegroundColor Green
        Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Applying the DSC extension to '$VMName' to promote it as a domain controller (this can take a while) ..." -ForegroundColor Cyan
        try {
            $null = Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$(Split-Path -Path $DSCConfigurationZipFileURI -Leaf)" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $DSCConfigurationName -ConfigurationArgument $DSCConfigurationArguments -Version "2.80" -Location $Location -AutoUpdate -Verbose #-ErrorAction Ignore
            Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The DSC extension has been applied to '$VMName'." -ForegroundColor Green
        }
        catch {
            Write-Warning -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The DSC extension application on '$VMName' reported an error:`r`n$($_.Exception.Message)"
        }
        $null = $VM | Update-AzVM -Verbose
        Remove-Item -Path $DSCZipLocalFilePath -Force
        Remove-Item -Path $DestinationFolder -Recurse -Force
    }
    else {
        Write-Error -Exception "Unable to download $DSCZipFileUri ..." -ErrorAction Continue
    }
    #endregion

    if ($null -ne $BastionJob) {
        #Waiting for the asynchronous Bastion deployment (if any) to finish before returning
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Waiting the creation of the Bastion completes ..."
        $BastionJob | Wait-Job | Out-Null
    }

    # Adding Credentials to the Credential Manager (and escaping the password)
    #Pre-populating Windows Credential Manager so the RDP session connects without prompting
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($AdminCredential.UserName) /pass:$($AdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

    Start-Sleep -Seconds 15

    #Start RDP Session
    #Opening an RDP session to the freshly created domain controller
    #mstsc /v $PublicIP.IpAddress
    mstsc /v $FQDN
    Write-Host -Object "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Your RDP credentials (login/password) are $($AdminCredential.UserName)/$($AdminCredential.GetNetworkCredential().Password)" -ForegroundColor Green
}
#endregion

#Main script execution starts here
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Verbose -Message "Account : $((Get-AzContext).Account)"
    Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
}
#endregion

$scriptBlock = { (Get-AzLocation).Location }
#Enabling tab-completion of the -Location parameter with the list of available Azure locations
Register-ArgumentCompleter -CommandName New-AAD-Hybrid-Lab -ParameterName Location -ScriptBlock $scriptBlock

#region Example #1
#Ensuring the NuGet package provider and the DSC modules required by the domain controller configuration are installed
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
$null = Get-PackageProvider -Name NuGet -Force -Verbose
$RequiredModules = 'ActiveDirectoryDSC', 'NetworkingDSC', 'ComputerManagementDSC'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule))) {
    $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject (Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore).Name).InputObject
}
else {
    $MissingModules = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules))) {
    Install-Module -Name $MissingModules -Force -Verbose
}

$AdminCredential = Get-Credential -Credential $env:USERNAME
$UserCredential = Get-Credential -Credential "Only password is required"

#Fixed instance number so resource names are deterministic across runs
#$Instance = Get-Random -Minimum 1 -Maximum 1000
$Instance = 1

#Splatted parameters passed to the lab deployment function
$Parameters = @{
    "AdminCredential"      = $AdminCredential
    "UserCredential"       = $UserCredential
    "VMSize"               = "Standard_D4s_v7"
    "OSDiskType"           = "StandardSSD_LRS"
    "Project"              = "avd"
    "Role"                 = "ad"
    "ADDomainName"         = "csa.fr"
    "CustomUPNSuffix"      = "cloudsolutionarchitect.fr"
    "VNetAddressRange"     = '10.0.0.0/16'
    "ADSubnetAddressRange" = '10.0.1.0/24'
    "DomainControllerIP"   = '10.0.1.4'
    "Instance"             = $Instance
    "Location"             = "CentralUS"
    "Spot"                 = $false
    "Bastion"              = $false
    "Verbose"              = $true
}

New-AAD-Hybrid-Lab @Parameters
#endregion