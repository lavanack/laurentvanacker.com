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
#requires -Version 5 -Modules Az.Accounts, Az.Network, Az.Resources

#From https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-rm-ps

#region function definitions
function New-AzP2SVPN {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "eastus2",
        [switch] $Connect
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
    $LocationShortName = $ResourceLocationShortNameHT[$Location].shortName
    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
    $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
    $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $Project = "p2s"
    $Role = "vpn"
    #$DigitNumber = 4
    $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $ResourceGroupName = $ResourceGroupName.ToLower()
    $VirtualNetworkName = $VirtualNetworkName.ToLower()
    $SubnetName = $SubnetName.ToLower()

    #$SubnetConfigFrontendName = "Frontend"
    $SubnetConfigFrontendName = $SubnetName
    $vnetAddressPrefix = "10.1.0.0/16"
    $SubnetConfigFrontendAddressPrefix = "10.1.0.0/24"
    #endregion

    #region Create a VNet
    $null = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore | Remove-AzResourceGroup -Force
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    $VirtualNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Name $VirtualNetworkName -AddressPrefix $vnetAddressPrefix
    $SubnetConfigFrontend = Add-AzVirtualNetworkSubnetConfig -Name $SubnetConfigFrontendName -AddressPrefix $SubnetConfigFrontendAddressPrefix -VirtualNetwork $VirtualNetwork
    $VirtualNetwork | Set-AzVirtualNetwork
    #endregion

    Add-AzP2SVPN -VirtualNetwork $VirtualNetwork -Connect:$Connect
    #endregion
}

function Add-AzP2SVPN {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $False)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork] $VirtualNetwork,
        [switch] $Connect
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
    $TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)

    $LocationShortName = $ResourceLocationShortNameHT[$Location].shortName
    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
    $VirtualNetworkGatewayPrefix = $ResourceTypeShortNameHT["Network/virtualNetworkGateways"].ShortName
    $publicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName

    $ResourceGroupName = $VirtualNetwork.ResourceGroupName
    $VirtualNetworkName = $VirtualNetwork.Name
    $Location = $VirtualNetwork.Location

    if ($VirtualNetworkName -match $("{0}-(?<Project>\w+)-(?<Role>\w+)-(?<LocationShortName>\w+)-(?<Instance>\d+)" -f $VirtualNetworkPrefix)) {
        $Project = $Matches["Project"]
        $Role = $Matches["Role"]
        #$LocationShortName = $Matches["LocationShortName"]
        $Instance = $Matches["Instance"]
        $DigitNumber = $Instance.Length
        #Taking the 2 first tokens vNet adress prefix and adding a *.255.0/27 subnet mask for the gateway subnet
        $SubnetConfigGatewayAddressPrefix = $VirtualNetwork.AddressSpace.AddressPrefixes -replace "(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", '$1.$2.255.0/27'
    } 
    else {
        $Project = "p2s"
        $Role = "vpn"
        #$DigitNumber = 4
        $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    }

    $VirtualNetworkGatewayName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkGatewayPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $GatewayIpConfigName = "{0}-ipconfig-{1:D$DigitNumber}" -f $VirtualNetworkGatewayPrefix, $Instance         
    $PublicIpAddressName = "{0}-{1}" -f $publicIPAddressPrefix, $GatewayIpConfigName
    $VirtualNetworkGatewayName = $VirtualNetworkGatewayName.ToLower()
    $GatewayIpConfigName = $GatewayIpConfigName.ToLower()
    $PublicIpAddressName = $PublicIpAddressName.ToLower()

    $VPNClientAddressPool = "172.16.201.0/24"
    #$SubnetConfigFrontendName = "Frontend"
    #We take the first subnet as Frontend subnet
    $SubnetConfigGatewayName = "GatewaySubnet"
    $SubnetConfigGatewayAddressPrefix = $VirtualNetwork.AddressSpace.AddressPrefixes -replace "(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", '$1.$2.255.0/27'
    $ClearTextPassword = 'P@ssw0rd'
    $SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
    #endregion

    $DestinationFolder = New-Item -Path $(Join-Path -Path $CurrentDir -ChildPath $TimeStamp) -ItemType Directory -Force

    #region Create the Subnet
    $SubnetConfigGateway = Add-AzVirtualNetworkSubnetConfig -Name $SubnetConfigGatewayName -AddressPrefix $SubnetConfigGatewayAddressPrefix -VirtualNetwork $VirtualNetwork
    $null = $VirtualNetwork | Set-AzVirtualNetwork
    #endregion

    #region Create the VPN gateway
    $GatewayPIP = New-AzPublicIpAddress -Name $PublicIpAddressName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -Sku Standard
    $VirtualNetwork = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName
    $GatewaySubnet = Get-AzVirtualNetworkSubnetConfig -Name $SubnetConfigGatewayName -VirtualNetwork $VirtualNetwork
    $GatewayIPConfig = New-AzVirtualNetworkGatewayIpConfig -Name $GatewayIpConfigName -SubnetId $GatewaySubnet.Id -PublicIpAddressId $GatewayPIP.Id
    #$Gateway = New-AzVirtualNetworkGateway -Name $VirtualNetworkGatewayName -ResourceGroupName $ResourceGroupName -Location $Location -IpConfigurations $GatewayIPConfig -GatewayType Vpn -VpnType RouteBased -EnableBgp $false -GatewaySku VpnGw2 -VpnGatewayGeneration "Generation2" -VpnClientProtocol IkeV2,OpenVPN -VpnClientAddressPool $VPNClientAddressPool
    $Gateway = New-AzVirtualNetworkGateway -Name $VirtualNetworkGatewayName -ResourceGroupName $ResourceGroupName -Location $Location -IpConfigurations $GatewayIPConfig -GatewayType Vpn -VpnType RouteBased -EnableBgp $false -GatewaySku VpnGw1 -VpnGatewayGeneration "Generation1" -VpnClientProtocol IkeV2, OpenVPN -VpnClientAddressPool $VPNClientAddressPool
    #endregion

    #region Generate certificates
    #region Root certificate
    $params = @{
        Type              = 'Custom'
        Subject           = 'CN=P2SRootCert'
        KeySpec           = 'Signature'
        KeyExportPolicy   = 'Exportable'
        KeyUsage          = 'CertSign'
        KeyUsageProperty  = 'Sign'
        KeyLength         = 2048
        HashAlgorithm     = 'sha256'
        NotAfter          = (Get-Date).AddMonths(24)
        CertStoreLocation = 'Cert:\CurrentUser\My'
    }
    $RootCert = New-SelfSignedCertificate @params
    #region Exporting Certificate
    $RootCertFilePath = Join-Path -Path $DestinationFolder -ChildPath $("{0}_{1}.cer" -f $($params.Subject -replace "CN="), $TimeStamp)
    $content = @(
        '-----BEGIN CERTIFICATE-----'
        [System.Convert]::ToBase64String($RootCert.RawData, 'InsertLineBreaks')
        '-----END CERTIFICATE-----'
    )
    $content | Out-File -FilePath $RootCertFilePath -Encoding ascii
    #endregion
    #region Exporting Certificate with Private Key
    $RootCertPFXFilePath = Join-Path -Path $DestinationFolder -ChildPath $("{0}_{1}.pfx" -f $($params.Subject -replace "CN="), $TimeStamp)
    $RootCert | Export-PfxCertificate -FilePath $RootCertPFXFilePath -Password $SecurePassword -Force
    #endregion
    #endregion

    #region Client certificate
    $params = @{
        Type              = 'Custom'
        Subject           = 'CN=P2SChildCert'
        DnsName           = 'P2SChildCert'
        KeySpec           = 'Signature'
        KeyExportPolicy   = 'Exportable'
        KeyLength         = 2048
        HashAlgorithm     = 'sha256'
        NotAfter          = (Get-Date).AddMonths(18)
        CertStoreLocation = 'Cert:\CurrentUser\My'
        Signer            = $RootCert
        TextExtension     = @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')
    }
    $ClientCert = New-SelfSignedCertificate @params
    #region Exporting Certificate with Private Key
    $ClientCertPFXFilePath = Join-Path -Path $DestinationFolder -ChildPath $("{0}_{1}.pfx" -f $($params.Subject -replace "CN="), $TimeStamp)
    $ClientCert | Export-PfxCertificate -FilePath $ClientCertPFXFilePath -Password $SecurePassword -Force
    #endregion

    #endregion
    #endregion

    #region Upload root certificate public key information
    $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2($RootCertFilePath)
    $CertBase64 = [system.convert]::ToBase64String($cert.RawData)

    $P2SRootCertName = Split-Path -Path $RootCertFilePath -Leaf
    Add-AzVpnClientRootCertificate -VpnClientRootCertificateName $P2SRootCertName -VirtualNetworkGatewayname $VirtualNetworkGatewayName -ResourceGroupName $ResourceGroupName -PublicCertData $CertBase64
    #endregion

    #region Generate and download the VPN client profile configuration package
    $profile = New-AzVpnClientConfiguration -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkGatewayName -AuthenticationMethod "EapTls"
    #Removing the query string
    $DestinationFile = Join-Path -Path $DestinationFolder -ChildPath $((Split-Path $profile.VPNProfileSASUrl -Leaf) -replace "\?.*$")
    #Adding a timestamp to the filename
    $DestinationFile = $DestinationFile -replace "(\.\w*)$", $('_{0}$1' -f $TimeStamp)
    #Creating a dedicater folder with the same name that the filename above but without the extension (for extracting the files from the downloaded zip file)
    $DestinationPath = $DestinationFile -replace "(\.\w*)$", $('_{0}' -f $TimeStamp)

    Start-BitsTransfer -Source $profile.VPNProfileSASUrl -Destination $DestinationFile
    Expand-Archive -Path $DestinationFile -DestinationPath $DestinationPath
    $VpnProfileSetupPowerShellScript = (Get-ChildItem -Path $DestinationPath -Filter VpnProfileSetup.ps1 -Recurse).FullName
    #Return an error if the VpnConnection doesn't exist (around line 61 - an -ErrorAction Ignore could solve this)
    & $VpnProfileSetupPowerShellScript -Force 2>&1 | Out-Null
    #endregion

    if ($Connect) {
        #region VPN connection
        rasdial $VirtualNetworkName
        #endregion

        #region VPN disconnection
        #rasdial $VirtualNetworkName /DISCONNECT
        #endregion
    }
    #endregion
}

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Creating a new Virtual Network with P2S VPN Gateway
New-AzP2SVPN -Connect -Verbose

Get-NetIPConfiguration -InterfaceAlias vnet-p2s*
#endregion

#region Updating an existing Virtual Network by adding a P2S VPN Gateway
#Taking a Virtual Network without a Gateway Subnet
#Get-AzVirtualNetwork -Name "vnet-p2s-vpn-*" | Where-Object -FilterScript { "GatewaySubnet" -notin $_.Subnets.Name } | Select-Object -First 1 | Add-AzP2SVPN -Connect -Verbose
#endregion

<#
#region Cleaning
#Cleaning Up the local VPN Connections
Get-VpnConnection  | Where-Object -FilterScript { $_.Name -match "^vnet-p2s-vpn" } | Remove-VpnConnection -Force -AsJob
#Cleaning Up the Resource Groups
Get-AzResourceGroup rg-p2s-vpn-* | Remove-AzResourceGroup -AsJob -Force
#endregion
Get-ChildItem Cert:\CurrentUser\My\ | Where-Object { $_.Subject -match "^CN=P2S"} | Remove-Item
#>
#endregion
