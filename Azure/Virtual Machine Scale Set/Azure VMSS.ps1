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
#requires -Version 5 -Modules Az.Compute, Az.Network, Az.Storage, Az.Resources

[CmdletBinding()]
param
(
)


#region function definitions 
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}


#From https://learn.microsoft.com/en-us/powershell/module/az.compute/set-azvmssosprofile?view=azps-13.0.0#example-2-set-the-operating-system-profile-properties-for-a-vmss-in-flexible-mode-with-hotpatching-enabled
# Setup variables.
$RDPPort = 3389
$AzureVMNameMaxLength = 15
$location = "eastus2"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$NetworkSecurityGroupPrefix = "nsg"
$ResourceGroupPrefix = "rg"
$Project = "vmss"
$Role = "test"
$DigitNumber = $AzureVMNameMaxLength-($VirtualMachinePrefix+$Project+$Role+$LocationShortName).Length
$MyPublicIp = Invoke-RestMethod -Uri "https://ipv4.seeip.org"

$Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
$vmssName = "myVmssSlb-{0:D$DigitNumber}" -f $Instance
$vmNamePrefix = "vmSlb"
$vmssInstanceCount = 3
$vmssSku = "Standard_DS1_v2"
$vnetname = "myVnet"
$vnetAddress = "10.0.0.0/16"
$subnetname = "default-slb"
$subnetAddress = "10.0.2.0/24"

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$ResourceGroupName = $ResourceGroupName.ToLower()
$NetworkSecurityGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $NetworkSecurityGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$NetworkSecurityGroupName = $NetworkSecurityGroupName.ToLower()
$FQDN = "$vmssName.$Location.cloudapp.azure.com".ToLower()

#region Defining credential(s)
$Username = $env:USERNAME
#$ClearTextPassword = 'P@ssw0rd'
#$ClearTextPassword = New-RandomPassword -ClipBoard -Verbose
#$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$SecurePassword = New-RandomPassword -ClipBoard -AsSecureString -Verbose
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
#endregion


$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

$SecurityRules = @(
    #region Inbound
    #RDP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name RDPRule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $RDPPort
    #HTTP only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPRule -Description "Allow HTTP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 301 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 80
    #HTTPS only for my public IP address
    New-AzNetworkSecurityRuleConfig -Name HTTPSRule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 302 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
    #endregion
)

$NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

# VMSS Flex requires explicit outbound access.
# Create a virtual network.
$frontendSubnet = New-AzVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix $subnetAddress -NetworkSecurityGroupId $NetworkSecurityGroup.Id
$virtualNetwork = New-AzVirtualNetwork -Name $vnetname -ResourceGroupName $ResourceGroupName -Location $location -AddressPrefix $vnetAddress -Subnet $frontendSubnet

# Create a public IP address.
$publicIP = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Location $location -AllocationMethod Static -Sku "Standard" -IpAddressVersion "IPv4" -Name "myLBPublicIP" -DomainNameLabel $vmssName.ToLower()

# Create a frontend and backend IP pool.
$frontendIP = New-AzLoadBalancerFrontendIpConfig -Name "myFrontEndPool" -PublicIpAddress $publicIP

$backendPool = New-AzLoadBalancerBackendAddressPoolConfig -Name "myBackEndPool" 

# Create the load balancer.
$lb = New-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name "myLoadBalancer" -Sku "Standard" -Tier "Regional" -Location $location -FrontendIpConfiguration $frontendIP -BackendAddressPool $backendPool

# Create a load balancer health probe for TCP port 80.
Add-AzLoadBalancerProbeConfig -Name "myHealthProbe" -LoadBalancer $lb -Protocol TCP -Port $RDPPort -IntervalInSeconds 15 -ProbeCount 3

# Create a load balancer rule to distribute traffic on port TCP 80.
# The health probe from the previous step is used to make sure that traffic is
# only directed to healthy VM instances.
Add-AzLoadBalancerRuleConfig -Name "myLoadBalancerRule" -LoadBalancer $lb -FrontendIpConfiguration $lb.FrontendIpConfigurations[0] -BackendAddressPool $lb.BackendAddressPools[0] -Protocol TCP -FrontendPort 80 -BackendPort 80 -DisableOutboundSNAT -Probe (Get-AzLoadBalancerProbeConfig -Name "myHealthProbe" -LoadBalancer $lb)

# Add outbound connectivity rule.
Add-AzLoadBalancerOutboundRuleConfig -Name "myOnboundRule" -LoadBalancer $lb -AllocatedOutboundPort '10000' -Protocol 'All' -IdleTimeoutInMinutes '15' -FrontendIpConfiguration $lb.FrontendIpConfigurations[0] -BackendAddressPool $lb.BackendAddressPools[0]

# Add inbound connectivity rule.
Add-AzLoadBalancerInboundNatRuleConfig -Name "myRDPInboundNATRule" -LoadBalancer $lb -FrontendIPConfiguration $lb.FrontendIpConfigurations[0] -Protocol "Tcp" -IdleTimeoutInMinutes 10 -FrontendPortRangeStart 50000 -FrontendPortRangeEnd 50099 -BackendAddressPool $lb.BackendAddressPools[0] -BackendPort $RDPPort

<#
$FrontendPortRangeStart = 5001
## Create the multiple virtual machines inbound NAT rule. ##
$rule = @{
    Name = 'myRDPInboundNATrule'
    Protocol = 'Tcp'
    BackendPort = $RDPPort
    FrontendIpConfiguration = $lb.FrontendIpConfigurations[0]
    FrontendPortRangeStart = $FrontendPortRangeStart
    FrontendPortRangeEnd = $FrontendPortRangeStart + $vmssInstanceCount - 1
    BackendAddressPool = $lb.BackendAddressPools[0]
}
$lb | Add-AzLoadBalancerInboundNatRuleConfig @rule

$lb | Set-AzLoadBalancer
#>


# Update the load balancer configuration.
Set-AzLoadBalancer -LoadBalancer $lb -Verbose

# Create IP address configurations.
# Instances will require explicit outbound connectivity, for example
#   - NAT Gateway on the subnet (recommended)
#   - Instances in backend pool of Standard LB with outbound connectivity rules
#   - Public IP address on each instance
# See aka.ms/defaultoutboundaccess for more info.
$ipConfig = New-AzVmssIpConfig -Name "myIPConfig" -SubnetId $virtualNetwork.Subnets[0].Id -LoadBalancerBackendAddressPoolsId $lb.BackendAddressPools[0].Id -Primary

# Create a config object.
# The Vmss config object stores the core information for creating a scale set.
$vmssConfig = New-AzVmssConfig -Location $location -SkuCapacity $vmssInstanceCount -SkuName $vmssSku -OrchestrationMode 'Flexible' -PlatformFaultDomainCount 1

# Reference a virtual machine image from the gallery.
Set-AzVmssStorageProfile $vmssConfig -OsDiskCreateOption "FromImage" -ImageReferencePublisher "MicrosoftWindowsServer" -ImageReferenceOffer "WindowsServer" -ImageReferenceSku "2022-datacenter-azure-edition-core-smalldisk" -ImageReferenceVersion "latest"

# Set up information for authenticating with the virtual machine.
Set-AzVmssOsProfile $vmssConfig -AdminUsername $Credential.UserName -AdminPassword $Credential.Password -ComputerNamePrefix $vmNamePrefix -WindowsConfigurationProvisionVMAgent $true -WindowsConfigurationPatchMode "AutomaticByPlatform" -EnableHotpatching

# Attach the virtual network to the config object.
Add-AzVmssNetworkInterfaceConfiguration -VirtualMachineScaleSet $vmssConfig -Name "network-config" -Primary $true -IPConfiguration $ipConfig -NetworkApiVersion '2020-11-01'

# Define the Application Health extension properties.
$publicConfig = @{"protocol" = "tcp"; "port" = $RDPPort}
$extensionName = "myHealthExtension"
$extensionType = "ApplicationHealthWindows"
$publisher = "Microsoft.ManagedServices"
# Add the Application Health extension to the scale set model.
Add-AzVmssExtension -VirtualMachineScaleSet $vmssConfig -Name $extensionName -Publisher $publisher -Setting $publicConfig -Type $extensionType -TypeHandlerVersion "1.0" -AutoUpgradeMinorVersion $True

# Create the virtual machine scale set.
$vmss = New-AzVmss -ResourceGroupName $ResourceGroupName -Name $vmssName -VirtualMachineScaleSet $vmssConfig


#region JIT Access Management
$JitPolicyTimeInHours = 3
$JitPolicyName = "Default"

foreach ($VM in ($vmss | Get-AzVmssVM | Get-AzVM)) {
    #region Enabling JIT Access
    $NewJitPolicy = (@{
            id    = $VM.Id
            ports = (@{
                    number                     = $RDPPort
                    protocol                   = "*"
                    allowedSourceAddressPrefix = "*"
                    maxRequestAccessDuration   = "PT$($JitPolicyTimeInHours)H"
                })   
        })


    Write-Host "Get Existing JIT Policy. You can Ignore the error if not found."
    $ExistingJITPolicy = (Get-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -ErrorAction Ignore).VirtualMachines
    $UpdatedJITPolicy = $ExistingJITPolicy.Where{ $_.id -ne "$($VM.Id)" } # Exclude existing policy for $VMName
    $UpdatedJITPolicy.Add($NewJitPolicy)
	
    # Enable Access to the VM including management Port, and Time Range in Hours
    Write-Host "Enabling Just in Time VM Access Policy for '$($VM.Name)' on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
    $null = Set-AzJitNetworkAccessPolicy -VirtualMachine $UpdatedJITPolicy -ResourceGroupName $ResourceGroupName -Location $Location -Name $JitPolicyName -Kind "Basic"
    #endregion

    Start-Sleep -Seconds 15

    #region Requesting Temporary Access : 3 hours
    $JitPolicy = (@{
            id    = $VM.Id
            ports = (@{
                    number                     = $RDPPort
                    endTimeUtc                 = (Get-Date).AddHours(3).ToUniversalTime()
                    allowedSourceAddressPrefix = @($MyPublicIP) 
                })
        })
    $ActivationVM = @($JitPolicy)
    Write-Host "Requesting Temporary Acces via Just in Time for '$($VM.Name)' on port number $RDPPort for maximum $JitPolicyTimeInHours hours..."
    Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
    #endregion
}
#endregion


# Adding Credentials to the Credential Manager (and escaping the password)
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($Credential.UserName) /pass:$($Credential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

Start-Sleep -Seconds 15

#Step 12: Start RDP Session
#mstsc /v $PublicIP.IpAddress
mstsc /v $("{0}:50000" -f $FQDN)
mstsc /v $("{0}:50001" -f $FQDN)
mstsc /v $("{0}:50002" -f $FQDN)
Write-Host -Object "Your RDP credentials (login/password) are $($Credential.UserName)/$($Credential.GetNetworkCredential().Password)" -ForegroundColor Green
