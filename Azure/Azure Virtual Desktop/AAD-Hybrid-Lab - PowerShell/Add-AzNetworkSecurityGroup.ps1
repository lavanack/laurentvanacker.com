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


#region Function Definitions
Function New-AzAvdPrivateEndPointNetworkSecurityGroup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True)]
        [string] $NetworkSecurityGroupName,
        [Parameter(Mandatory = $True)]
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location,
        [Parameter(Mandatory = $True)]
        [string] $ResourceGroupName
    )
    New-AzNetworkSecurityGroup -Name $NetworkSecurityGroupName -ResourceGroupName $ResourceGroupName -Location $Location
}

Function New-AzAvdSessionHostNetworkSecurityGroup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True)]
        [string] $NetworkSecurityGroupName,
        [Parameter(Mandatory = $True)]
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location,
        [Parameter(Mandatory = $True)]
        [string] $ResourceGroupName
    )

    $rule_AVDServiceTraffic = New-AzNetworkSecurityRuleConfig -Name "AVDServiceTraffic" -Description "Session host traffic to AVD control plane" -Access Allow -Protocol Tcp -Direction Outbound -Priority 100 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "WindowsVirtualDesktop" -DestinationPortRange "443"
    $rule_AzureCloud = New-AzNetworkSecurityRuleConfig -Name "AzureCloud" -Description "Session host traffic to Azure cloud services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 110 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureCloud" -DestinationPortRange "8443"
    $rule_AzureMonitor = New-AzNetworkSecurityRuleConfig -Name "AzureMonitor" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 120 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureMonitor" -DestinationPortRange "443"
    $rule_AzureMarketPlace = New-AzNetworkSecurityRuleConfig -Name "AzureMarketPlace" -Description "Session host traffic to Azure Monitor" -Access Allow -Protocol Tcp -Direction Outbound -Priority 130 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "AzureFrontDoor.Frontend" -DestinationPortRange "443"
    $rule_WindowsActivationKMS = New-AzNetworkSecurityRuleConfig -Name "WindowsActivationKMS" -Description "Session host traffic to Windows license activation services" -Access Allow -Protocol Tcp -Direction Outbound -Priority 140 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix @("20.118.99.224","40.83.235.53","23.102.135.246") -DestinationPortRange "1688"
    $rule_AzureInstanceMetadata = New-AzNetworkSecurityRuleConfig -Name "AzureInstanceMetadata" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Tcp -Direction Outbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "169.254.169.254" -DestinationPortRange "80"
    $rule_RDPShortpath = New-AzNetworkSecurityRuleConfig -Name "RDPShortpath" -Description "Session host traffic to Azure instance metadata" -Access Allow -Protocol Udp -Direction Inbound -Priority 150 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "VirtualNetwork" -DestinationPortRange "3390"
    $rule_RDPShortpathTurnStun = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnStun" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 160 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "20.202.0.0/16" -DestinationPortRange "3478"
    $rule_RDPShortpathTurnRelay = New-AzNetworkSecurityRuleConfig -Name "RDPShortpathTurnRelay" -Description "Session host traffic to RDP shortpath STUN/TURN" -Access Allow -Protocol Udp -Direction Outbound -Priority 170 -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "51.5.0.0/16" -DestinationPortRange "3478"

    $SecurityRules = @(
        $rule_AVDServiceTraffic,
        $rule_AzureCloud,
        $rule_AzureMonitor,
        $rule_AzureMarketPlace,
        $rule_WindowsActivationKMS,
        $rule_AzureInstanceMetadata,
        $rule_RDPShortpath,
        $rule_RDPShortpathTurnStun,
        $rule_RDPShortpathTurnRelay
    )

    # --- Create NSG with all rules ---
    New-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName -Location $Location -SecurityRules $SecurityRules$rule_RDPShortpathTurnRelay
}
#endregion


#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

$Parameters = @{
    $NetworkSecurityGroupName = "nsg-avd-avd-use2-002"
    $Location = "EastUS2"
    $ResourceGroupName = "rg-avd-ad-use2-002"
}
New-AzAvdSessionHostNetworkSecurityGroup @Parameters -Verbose

$Parameters = @{
    $NetworkSecurityGroupName = "nsg-avd-pe-use2-002"
    $Location = "EastUS2"
    $ResourceGroupName = "rg-avd-ad-use2-002"
}
New-AzAvdPrivateEndPointNetworkSecurityGroup @Parameters -Verbose
#endregion
