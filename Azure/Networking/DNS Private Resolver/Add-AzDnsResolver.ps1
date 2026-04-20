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
#requires -Version 5 -Modules Az.Accounts, Az.DnsResolver, Az.Network, Az.Resources


#region function definitions
function Add-AzDnsResolver {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $False)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork
    )

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $ResourceLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Variables

    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
    $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName

    $ResourceGroupName = $VirtualNetwork.ResourceGroupName
    $VirtualNetworkName = $VirtualNetwork.Name
    $Location = $VirtualNetwork.Location
    $LocationShortName = $ResourceLocationShortNameHT[$Location].shortName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VirtualNetworkName: $VirtualNetworkName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Location: $Location"

    if ($VirtualNetworkName -match $("{0}-(?<Prefix>\w+)-(?<Environment>\w+)-(?<LocationShortName>\w+)-(?<Instance>\d+)" -f $VirtualNetworkPrefix)) {
        $Prefix = $Matches["Prefix"]
        $Environment = $Matches["Environment"]
        #$LocationShortName = $Matches["LocationShortName"]
        $Instance = $Matches["Instance"]
        $DigitNumber = $Instance.Length
    } 
    else {
        $Prefix = "poc"
        $Environment = "test"
        #$DigitNumber = 4
        $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Prefix + $Environment + $LocationShortName).Length
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Prefix: $Prefix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Environment: $Environment"

    $InboundSubnetName = "{0}-dns-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Prefix, "inbound", $LocationShortName, $Instance                       
    $OutboundSubnetName = "{0}-dns-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Prefix, "outbound", $LocationShortName, $Instance                       
    $InboundSubnetName = $InboundSubnetName.ToLower()
    $OutboundSubnetName = $OutboundSubnetName.ToLower()

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$InboundSubnetName: $InboundSubnetName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OutboundSubnetName: $OutboundSubnetName"


    #Taking the 2 first tokens vNet adress prefix and adding a *.254.0/28 subnet mask for the subnet
    $InboundSubnetPrefix = $VirtualNetwork.AddressSpace.AddressPrefixes -replace "(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", '$1.$2.254.0/28'
    $OutboundSubnetPrefix = $VirtualNetwork.AddressSpace.AddressPrefixes -replace "(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", '$1.$2.254.16/28'
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$InboundSubnetPrefix: $InboundSubnetPrefix"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OutboundSubnetPrefix: $OutboundSubnetPrefix"


    $DnsResolverName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f "dnspr", $Prefix, $Environment, $LocationShortName, $Instance                       
    $DnsResolverName = $DnsResolverName.ToLower()
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$DnsResolverName: $DnsResolverName"

    $InboundEndpointName  = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f "inbound", $Prefix, $Environment, $LocationShortName, $Instance                       
    $OutboundEndpointName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f "outbound", $Prefix, $Environment, $LocationShortName, $Instance                       
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$InboundEndpointName: $InboundEndpointName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$OutboundEndpointName: $OutboundEndpointName"

    $RulesetName          = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f "ruleset", $Prefix, $Environment, $LocationShortName, $Instance                       
    $RulesetVnetLinkName  = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f "vnetlink", $Prefix, $Environment, $LocationShortName, $Instance                       
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RulesetName: $RulesetName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RulesetVnetLinkName: $RulesetVnetLinkName"
    #endregion
    #ednregion

    #region Subnet Setup
    $InboundSubnet  = $VirtualNetwork.Subnets | Where-Object -FilterScript { $_.Name -eq $InboundSubnetName }
    $OutboundSubnet = $VirtualNetwork.Subnets | Where-Object -FilterScript { $_.Name -eq $OutboundSubnetName }

    if (-not $InboundSubnet) {
        $InboundSubnet = Add-AzVirtualNetworkSubnetConfig -Name $InboundSubnetName -AddressPrefix $InboundSubnetPrefix -VirtualNetwork $VirtualNetwork
        $VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
    }

    if (-not $OutboundSubnet) {
        $OutboundSubnet = Add-AzVirtualNetworkSubnetConfig -Name $OutboundSubnetName -AddressPrefix $OutboundSubnetPrefix -VirtualNetwork $VirtualNetwork
        $VirtualNetwork = Set-AzVirtualNetwork -VirtualNetwork $VirtualNetwork
    }

    # Refresh VNet/subnets
    $VirtualNetwork = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName
    $InboundSubnet  = $VirtualNetwork.Subnets | Where-Object -FilterScript { $_.Name -eq $InboundSubnetName }
    $OutboundSubnet = $VirtualNetwork.Subnets | Where-Object -FilterScript { $_.Name -eq $OutboundSubnetName }
    #endregion

    #region DNS Private Resolver
    $dnspr = Get-AzDnsResolver -Name $DnsResolverName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $dnspr) {
        $dnspr = New-AzDnsResolver -Name $DnsResolverName -ResourceGroupName $ResourceGroupName -Location $Location -VirtualNetworkId $VirtualNetwork.Id
    }
    #endregion

    #region Inbound Endpoint
    $inEp = Get-AzDnsResolverInboundEndpoint -DnsResolverName $DnsResolverName -Name $InboundEndpointName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $inEp) {
        $ipConfigIn = New-AzDnsResolverIPConfigurationObject -PrivateIPAllocationMethod Dynamic -SubnetId $InboundSubnet.Id
        $inEp = New-AzDnsResolverInboundEndpoint -DnsResolverName $DnsResolverName -Name $InboundEndpointName -ResourceGroupName $ResourceGroupName -Location $Location -IPConfiguration $ipConfigIn
    }

    # Refresh to get the inbound IP 
    $inEp = Get-AzDnsResolverInboundEndpoint -DnsResolverName $DnsResolverName -Name $InboundEndpointName -ResourceGroupName $ResourceGroupName
    $InboundIp = $inEp.IPConfiguration[0].PrivateIPAddress
    #endregion

    #region Inbound Endpoint
    $outEp = Get-AzDnsResolverOutboundEndpoint -DnsResolverName $DnsResolverName -Name $OutboundEndpointName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $outEp) {
        $outEp = New-AzDnsResolverOutboundEndpoint -DnsResolverName $DnsResolverName -Name $OutboundEndpointName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $OutboundSubnet.Id
    }
    #endregion

    #region Fowarding Ruleset + Vnet Link
    $ruleset = Get-AzDnsForwardingRuleset -Name $RulesetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $ruleset) {
        $ruleset = New-AzDnsForwardingRuleset -Name $RulesetName -ResourceGroupName $ResourceGroupName -Location $Location -DnsResolverOutboundEndpoint @(@{ Id = $outEp.Id })
    }

    $link = Get-AzDnsForwardingRulesetVirtualNetworkLink -DnsForwardingRulesetName $RulesetName -Name $RulesetVnetLinkName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue

    if (-not $link) {
        $link = New-AzDnsForwardingRulesetVirtualNetworkLink -DnsForwardingRulesetName $RulesetName -Name $RulesetVnetLinkName -ResourceGroupName $ResourceGroupName -VirtualNetworkId $VirtualNetwork.Id
    }
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] 👉 Use the inbound IP ($InboundIp) as DNS server for your P2S clients (Azure VPN Client) and/or as Custom DNS for the VNets that must resolve the Private Endpoints."

}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion

#region Updating an existing Virtual Network by adding a P2S VPN Gateway
#Taking a Virtual Network without a Gateway Subnet
Get-AzVirtualNetwork -Name "vnet-poc-test-usc-001" | Select-Object -First 1 | Add-AzDnsResolver -Verbose
#endregion

#endregion