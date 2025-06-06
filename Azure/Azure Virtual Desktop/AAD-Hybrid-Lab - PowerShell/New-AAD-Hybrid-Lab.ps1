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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Security, Az.Storage  -RunAsAdministrator 

#region Function definition
function New-AAD-Hybrid-Lab {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true, HelpMessage = 'Please specify the administrator credential. The Username cannot be "Administrator", "root" and possibly other such common account names.')]
        [PSCredential] $AdminCredential,
        [parameter(Mandatory = $true, HelpMessage = 'Enter the password that will be applied to each user account to be created in AD.')]
        [PSCredential] $UserCredential,
        [parameter(Mandatory = $false, HelpMessage = 'Select a VM SKU (please ensure the SKU is available in your selected region).')]
        [string] $VMSize = "Standard_D2s_v5",
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
        [string] $Location = "eastus",
        [switch] $Spot,
        [switch] $Bastion
    )

    Write-Verbose "`$VMSize: $VMSize"
    Write-Verbose "`$Project: $Project"         
    Write-Verbose "`$Role: $Role"         
    Write-Verbose "`$ADDomainName: $ADDomainName"       
    Write-Verbose "`$CustomUPNSuffix: $CustomUPNSuffix"
    Write-Verbose "`$VNetAddressRange: $VNetAddressRange"
    Write-Verbose "`$ADSubnetAddressRange: $ADSubnetAddressRange"
    Write-Verbose "`$DomainControllerIP: $DomainControllerIP"
    Write-Verbose "`$Instance: $Instance"
    Write-Verbose "`$Location: $Location"
    Write-Verbose "`$Spot: $Spot"
    Write-Verbose "`$Bastion: $Bastion"

    #region Defining variables 
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    $AzureVMNameMaxLength = 15
    $RDPPort = 3389
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
        @{"FName" = "Bob"; "LName" = "Jones"; "SAM" = "bjones" }
        @{"FName" = "Bill"; "LName" = "Smith"; "SAM" = "bsmith" }
        @{"FName" = "Mary"; "LName" = "Phillips"; "SAM" = "mphillips" }
        @{"FName" = "Sue"; "LName" = "Jackson"; "SAM" = "sjackson" }
        @{"FName" = "Jack"; "LName" = "Petersen"; "SAM" = "jpetersen" }
        @{"FName" = "Julia"; "LName" = "Williams"; "SAM" = "jwilliams" }
    )


    $FQDN = "$VMName.$Location.cloudapp.azure.com".ToLower()

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($ResourceGroup) {
        #Step 0: Remove previously existing Azure Resource Group with the same name
        $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
    }
    $MyPublicIp = (Invoke-WebRequest -Uri "https://ipv4.seeip.org").Content

    #region Define Variables needed for Virtual Machine
    $ImagePublisherName = "MicrosoftWindowsServer"
    $ImageOffer = "WindowsServer"
    $ImageSku = "2022-datacenter-g2"
    $PublicIPName = "pip-$VMName" 
    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName          = "$VMName-DataDisk01"
    $OSDiskSize = "127"
    $StorageAccountSkuName = "Standard_LRS"
    #$OSDiskType = "StandardSSD_LRS"
    $DSCZipFileUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab/DSC/adDSC.zip"
    $DSCConfigurationName = "DomainController"

    $DSCConfigurationArguments = @{ 
        ADDomainName    = $ADDomainName
        customupnsuffix = $CustomUPNSuffix
        AdminCreds      = $AdminCredential
        usersArray      = $UserArray
        UserCreds       = $UserCredential
    }

    Write-Verbose "`$VMName: $VMName"
    Write-Verbose "`$NetworkSecurityGroupName: $NetworkSecurityGroupName"         
    Write-Verbose "`$VirtualNetworkName: $VirtualNetworkName"         
    Write-Verbose "`$SubnetName: $SubnetName"       
    Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
    Write-Verbose "`$PublicIPName: $PublicIPName"
    Write-Verbose "`$NICName: $NICName"
    Write-Verbose "`$OSDiskName: $OSDiskName"
    Write-Verbose "`$FQDN: $FQDN"
    #endregion
    #endregion


    if ($VMName.Length -gt $AzureVMNameMaxLength) {
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
    elseif ($null -eq (Get-AzVMSize -Location $Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' is not available in the '$Location' location ..." -ErrorAction Stop
    }

    #Step 1: Create Azure Resource Group
    # Create Resource Groups
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force

    #Step 2: Create Azure Storage Account
    $StorageAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $Location -SkuName $StorageAccountSkuName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true

    #Step 3: Create Azure Network Security Group
    #RDP only for my public IP address
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
    
    $NetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $NetworkSecurityGroupName -SecurityRules $SecurityRules -Force

    #Steps 4 + 5: Create Azure Virtual network using the virtual network subnet configuration
    $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $ADSubnetAddressRange -NetworkSecurityGroup $NetworkSecurityGroup
    $vNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName  -AddressPrefix $VNetAddressRange -Location $Location -Subnet $Subnet
    <#
    $vNetwork = Set-AzVirtualNetwork -VirtualNetwork $vNetwork
    $Subnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNetwork
    #>
    if ($Bastion) {
        
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
        Write-Verbose "`$BastionNetworkSecurityGroupName: $BastionNetworkSecurityGroupName"         

        $BastionNetworkSecurityGroup = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $BastionNetworkSecurityGroupName -SecurityRules $BastionSecurityRules -Force

        Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vNetwork -AddressPrefix $BastionSubnetAddressRange -NetworkSecurityGroupId $BastionNetworkSecurityGroup.Id | Set-AzVirtualNetwork
        $publicip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$VirtualNetworkName-ip" -Location "EastUS" -AllocationMethod Static -Sku Standard
        $BastionVirtualNetworkName = '{0}-bastion-{1}-{2}-{3}-{4:D3}' -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
        $BastionVirtualNetworkName = $BastionVirtualNetworkName.ToLower()
        $BastionJob = New-AzBastion -ResourceGroupName $ResourceGroupName -Name $BastionVirtualNetworkName -PublicIpAddressRgName $ResourceGroupName -PublicIpAddressName "$VirtualNetworkName-ip" -VirtualNetworkRgName $ResourceGroupName -VirtualNetworkName $VirtualNetworkName -Sku "Basic" -AsJob

        #Adding Security Rules for allowing connection from Bastion
        #RDP
        Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NetworkSecurityGroupName | `
            Add-AzNetworkSecurityRuleConfig -Name allow_Bastion_RDP -Description "Allow RDP Communication from Bastion" -Protocol Tcp -SourcePortRange * -DestinationPortRange $RDPPort -SourceAddressPrefix $BastionSubnetAddressRange -DestinationAddressPrefix 'VirtualNetwork' -Access Allow  -Priority 101 -Direction Inbound | `
            Set-AzNetworkSecurityGroup
        #SSH
        Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NetworkSecurityGroupName | `
            Add-AzNetworkSecurityRuleConfig -Name allow_Bastion_SSH -Description "Allow SSH Communication from Bastion" -Protocol Tcp -SourcePortRange * -DestinationPortRange 22 -SourceAddressPrefix $BastionSubnetAddressRange -DestinationAddressPrefix 'VirtualNetwork' -Access Allow  -Priority 102 -Direction Inbound | `
            Set-AzNetworkSecurityGroup
    }
    
    #Step 6: Create Azure Public Address
    $PublicIP = New-AzPublicIpAddress -Name $PublicIPName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -DomainNameLabel $VMName.ToLower()
    #Setting up the DNS Name
    #$PublicIP.DnsSettings.Fqdn = $FQDN

    #Step 7: Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $(Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vNetwork).Id -PublicIpAddressId $PublicIP.Id -PrivateIpAddress $DomainControllerIP #-NetworkSecurityGroupId $NetworkSecurityGroup.Id

    <# Optional : Step 8: Get Virtual Machine publisher, Image Offer, Sku and Image
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq "MicrosoftWindowsDesktop"}
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq "Windows-11"}
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq "win11-21h2-pro"}
    $image = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1
    #>

    # Step 9: Create a virtual machine configuration file (As a Spot Intance)
    if ($Spot) {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -Priority "Spot" -MaxPrice -1
    }
    else {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    }

    Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    # Set VM operating system parameters
    Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $AdminCredential -ProvisionVMAgent -EnableAutoUpdate -PatchMode "AutomaticByPlatform"

    # Set boot diagnostic storage account
    #Set-AzVMBootDiagnostic -Enable -ResourceGroupName $ResourceGroupName -VM $VMConfig -StorageAccountName $StorageAccountName    
    # Set boot diagnostic to managed storage account
    Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    # The line below replaces Step #8 : Set virtual machine source image
    Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'

    # Set OsDisk configuration
    Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

    #region Adding Data Disk
    <#
    $VMDataDisk01Config = New-AzDiskConfig -SkuName $OSDiskType -Location $Location -CreateOption Empty -DiskSizeGB 512
    $VMDataDisk01       = New-AzDisk -DiskName $DataDiskName -Disk $VMDataDisk01Config -ResourceGroupName $ResourceGroupName
    $VM                 = Add-AzVMDataDisk -VM $VMConfig -Name $DataDiskName -Caching 'ReadWrite' -CreateOption Attach -ManagedDiskId $VMDataDisk01.Id -Lun 0
    #>
    #endregion

    #Step 10: Create Azure Virtual Machine
    New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VMConfig #-DisableBginfoExtension

    #Step 11: Updating the DNS Servers of the VNet to point to the DC.
    $vNetwork.DhcpOptions = [PSCustomObject]@{"DnsServers" = $DomainControllerIP }
    $vNetwork | Set-AzVirtualNetwork


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
    Start-AzJitNetworkAccessPolicy -ResourceGroupName $($VM.ResourceGroupName) -Location $VM.Location -Name $JitPolicyName -VirtualMachine $ActivationVM
    #endregion

    #endregion

    #region Enabling auto-shutdown at 11:00 PM in the user time zome
    $SubscriptionId = ($VM.Id).Split('/')[2]
    $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VMName"
    $Properties = @{}
    $Properties.Add('status', 'Enabled')
    $Properties.Add('taskType', 'ComputeVmShutdownTask')
    $Properties.Add('dailyRecurrence', @{'time' = "2300" })
    $Properties.Add('timeZoneId', (Get-TimeZone).Id)
    $Properties.Add('targetResourceId', $VM.Id)
    New-AzResource -Location $location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
    #endregion
    #Step 12: Start Azure Virtual Machine
    Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

    #region Setting up the DSC extension
    # Publishing DSC Configuration 
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
        $DSCConfigurationZipFileURI = Publish-AzVMDscConfiguration $DSCConfigurationFile -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose
        try {
            Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$(Split-Path -Path $DSCConfigurationZipFileURI -Leaf)" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $DSCConfigurationName -ConfigurationArgument $DSCConfigurationArguments -Version "2.80" -Location $Location -AutoUpdate -Verbose #-ErrorAction Ignore
        }
        catch {
        }
        $VM | Update-AzVM -Verbose
        Remove-Item -Path $DSCZipLocalFilePath -Force
        Remove-Item -Path $DestinationFolder -Recurse -Force
    }
    else {
        Write-Error -Exception "Unable to download $DSCZipFileUri ..." -ErrorAction Continue
    }
    #endregion

    if ($null -ne $BastionJob) {
        Write-Verbose -Message "Waiting the creation of the Bastion completes ..."
        $BastionJob | Wait-Job | Out-Null
    }
    # Adding Credentials to the Credential Manager (and escaping the password)
    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$FQDN /user:$($AdminCredential.UserName) /pass:$($AdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait

    Start-Sleep -Seconds 15

    #Step 13: Start RDP Session
    #mstsc /v $PublicIP.IpAddress
    mstsc /v $FQDN
    Write-Host -Object "Your RDP credentials (login/password) are $($AdminCredential.UserName)/$($AdminCredential.GetNetworkCredential().Password)" -ForegroundColor Green
}
#endregion

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
Register-ArgumentCompleter -CommandName New-AAD-Hybrid-Lab -ParameterName Location -ScriptBlock $scriptBlock

#region Example #1
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

#$Instance = Get-Random -Minimum 1 -Maximum 1000
$Instance = 1

$Parameters = @{
    "AdminCredential"      = $AdminCredential
    "UserCredential"       = $UserCredential
    "VMSize"               = "Standard_D2s_v5"
    "OSDiskType"           = "StandardSSD_LRS"
    "Project"              = "avd"
    "Role"                 = "ad"
    "ADDomainName"         = "csa.fr"
    #"CustomUPNSuffix"      = "cloudsolutionarchitect.fr"
    "VNetAddressRange"     = '10.0.0.0/16'
    "ADSubnetAddressRange" = '10.0.1.0/24'
    "DomainControllerIP"   = '10.0.1.4'
    "Instance"             = $Instance
    "Location"             = "eastus2"
    "Spot"                 = $false
    "Bastion"              = $false
    "Verbose"              = $true
}

New-AAD-Hybrid-Lab @Parameters
#endregion