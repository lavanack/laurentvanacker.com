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
function New-PsAvdVirtualNetwork {
    [CmdletBinding(PositionalBinding = $false)]
    Param( 
        [Parameter(Mandatory = $false, HelpMessage = 'The Azure location for your Virtual Network.')]
        [ValidateScript({ $_ -in $((Get-AzLocation).Location) })] 
        [string] $Location = "eastus2",
        [parameter(Mandatory = $false, HelpMessage = 'The instance number for your deployment.')]
        [ValidateScript({ $_ -in 0..999 })] 
        [int] $Instance = $(Get-Random -Minimum 0 -Maximum 1000),
        [parameter(Mandatory = $false, HelpMessage = 'The address range of the new virtual network in CIDR format')]
        [ValidatePattern("\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{2}")] 
        [string] $AddressRange = '10.5.0.0/16'
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

        $LocationShortName = $shortNameHT[$Location].shortName
        $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
        $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
        $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
        $NetworkSecurityGroupPrefix = $ResourceTypeShortNameHT["Network/networkSecurityGroups"].ShortName
        $Project = "avd"
        $Role = "avd"

        $VirtualNetworkName = '{0}-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
        $ResourceGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
        $VirtualNetworkName = $VirtualNetworkName.ToLower()
        $ResourceGroupName = $ResourceGroupName.ToLower()

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkName: $VirtualNetworkName"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"

        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
        if ($ResourceGroup) {
            Write-Warning -Message "The '$ResourceGroupName' ResourceGroup already exists. We won't recreate or modify it ..."
        }
        else {
            $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
        }

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

            $NSGRuleAVDServiceTraffic = New-AzNetworkSecurityRuleConfig -Name "AVDServiceTraffic" -Description "Session host traffic to AVD control plane" -Access Allow -Protocol Tcp -Direction Outbound -Priority 100 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "WindowsVirtualDesktop" -DestinationPortRange "443"
            $NSGRuleAzureCloud = New-AzNetworkSecurityRuleConfig -Name "AzureCloud" -Description "Session host traffic to Azure cloud services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 110 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureCloud" -DestinationPortRange "8443"
            $NSGRuleAzureMonitor = New-AzNetworkSecurityRuleConfig -Name "AzureMonitor" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureMonitor" -DestinationPortRange "443"
            $NSGRuleAzureMarketPlace = New-AzNetworkSecurityRuleConfig -Name "AzureMarketPlace" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureFrontDoor.Frontend" -DestinationPortRange "443"
            $NSGRuleWindowsActivationKMS = New-AzNetworkSecurityRuleConfig -Name "WindowsActivationKMS" -Description "Session host traffic to Windows license activation services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 140 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix @("20.118.99.224","40.83.235.53","23.102.135.246") -DestinationPortRange "1688"
            $NSGRuleAzureInstanceMetadata = New-AzNetworkSecurityRuleConfig -Name "AzureInstanceMetadata" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Tcp -Direction Outbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "169.254.169.254" -DestinationPortRange "80"
            $NSGRuleRDPShortpath = New-AzNetworkSecurityRuleConfig -Name "RDPShortpath" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Udp -Direction Inbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "VirtualNetwork" -DestinationPortRange "3390"
            $NSGRuleRDPShortpathTurnStun = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnStun" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 160 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "20.202.0.0/16" -DestinationPortRange "3478"
            $NSGRuleRDPShortpathTurnRelay = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnRelay" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 170 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "51.5.0.0/16" -DestinationPortRange "3478"

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
            $NetworkSecurityGroupName = '{0}-{1}-{2}-{3}-{4:D3}' -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location -SecurityRules $NSGRules
            $Subnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetAddressPrefix -NetworkSecurityGroup $NetworkSecurityGroup -DefaultOutboundAccess $true
            $VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -AddressPrefix $AddressRange -Location $Location -Subnet $Subnet
            #endregion

            #region PE Subnet
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
            $NetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location
            $Subnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetAddressPrefix -NetworkSecurityGroup $NetworkSecurityGroup -DefaultOutboundAccess $true

            #region Add the NatGateway subnet to vnet
            $VirtualNetwork.Subnets += $Subnet
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating vNet: $($VirtualNetwork.Name)"
            $null = $VirtualNetwork | Set-AzVirtualNetwork
            #endregion

            #endregion
        }
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

#region SubNet
New-PsAvdVirtualNetwork -Location BelgiumCentral -Instance 2 -Verbose
#endregion

#endregion