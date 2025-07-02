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
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows')} | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Variables
    $TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
    $LocationShortName = $ResourceLocationShortNameHT[$Location].shortName
    #Naming convention based on https://github.com/mspnp/AzureNamingTool/blob/main/src/repository/resourcetypes.json
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $VirtualMachinePrefix = $ResourceTypeShortNameHT["Compute/virtualMachines"].ShortName
    $VirtualNetworkPrefix = $ResourceTypeShortNameHT["Network/virtualNetworks"].ShortName
    $SubnetPrefix = $ResourceTypeShortNameHT["Network/virtualnetworks/subnets"].ShortName
    $VirtualNetworkGatewaysPrefix = $ResourceTypeShortNameHT["Network/virtualNetworkGateways"].ShortName
    $ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $publicIPAddressPrefix = $ResourceTypeShortNameHT["Network/publicIPAddresses"].ShortName
    $Project = "p2s"
    $Role = "vpn"
    #$DigitNumber = 4
    $DigitNumber = $AzureVMNameMaxLength - ($VirtualMachinePrefix + $Project + $Role + $LocationShortName).Length
    $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VirtualNetworkName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $SubnetName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $SubnetPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $VirtualNetworkGatewaysName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $VirtualNetworkGatewaysPrefix, $Project, $Role, $LocationShortName, $Instance                       
    $GatewayIpConfigName = "{0}-ipconfig-{1:D$DigitNumber}" -f $VirtualNetworkGatewaysPrefix, $Instance         
    $PublicIpAddressName = "{0}-{1}" -f $publicIPAddressPrefix, $GatewayIpConfigName
    $ResourceGroupName = $ResourceGroupName.ToLower()
    $VirtualNetworkName = $VirtualNetworkName.ToLower()
    $SubnetName = $SubnetName.ToLower()
    $VirtualNetworkGatewaysName = $VirtualNetworkGatewaysName.ToLower()
    $GatewayIpConfigName = $GatewayIpConfigName.ToLower()
    $PublicIpAddressName = $PublicIpAddressName.ToLower()

    $VPNClientAddressPool = "172.16.201.0/24"
    $subnetConfigFrontendName = "Frontend"
    #$subnetConfigFrontendName = $SubnetName
    $subnetConfigGWName = "GatewaySubnet"
    $vnetAddressPrefix = "10.1.0.0/16"
    $subnetConfigFrontendAddressPrefix = "10.1.0.0/24"
    $subnetConfigGWAddressPrefix = "10.1.255.0/27"
    $ClearTextPassword = 'P@ssw0rd'
    $SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
    #endregion

    $DestinationFolder = New-Item -Path $(Join-Path -Path $CurrentDir -ChildPath $TimeStamp) -ItemType Directory -Force

    #region Create a VNet
    Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore | Remove-AzResourceGroup -Force
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Name $VirtualNetworkName -AddressPrefix $vnetAddressPrefix
    $subnetConfigFrontend = Add-AzVirtualNetworkSubnetConfig -Name $subnetConfigFrontendName -AddressPrefix $subnetConfigFrontendAddressPrefix -VirtualNetwork $vnet
    $subnetConfigGW = Add-AzVirtualNetworkSubnetConfig -Name $subnetConfigGWName -AddressPrefix $subnetConfigGWAddressPrefix -VirtualNetwork $vnet
    $vnet | Set-AzVirtualNetwork
    #endregion

    #region Create the VPN gateway
    $gwpip = New-AzPublicIpAddress -Name $PublicIpAddressName -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Static -Sku Standard
    $vnet = Get-AzVirtualNetwork -Name $VirtualNetworkName -ResourceGroupName $ResourceGroupName
    $gwsubnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetConfigGWName -VirtualNetwork $vnet
    $gwipconfig = New-AzVirtualNetworkGatewayIpConfig -Name $GatewayIpConfigName -SubnetId $gwsubnet.Id -PublicIpAddressId $gwpip.Id
    $Gateway = New-AzVirtualNetworkGateway -Name $VirtualNetworkGatewaysName -ResourceGroupName $ResourceGroupName -Location $Location -IpConfigurations $gwipconfig -GatewayType Vpn -VpnType RouteBased -EnableBgp $false -GatewaySku VpnGw2 -VpnGatewayGeneration "Generation2" -VpnClientProtocol IkeV2,OpenVPN
    #endregion

    #region Add the VPN client address pool
    $Gateway = Get-AzVirtualNetworkGateway -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkGatewaysName
    Set-AzVirtualNetworkGateway -VirtualNetworkGateway $Gateway -VpnClientAddressPool $VPNClientAddressPool
    #endregion

    #region Generate certificates
    #region Root certificate
    $params = @{
        Type = 'Custom'
        Subject = 'CN=P2SRootCert'
        KeySpec = 'Signature'
        KeyExportPolicy = 'Exportable'
        KeyUsage = 'CertSign'
        KeyUsageProperty = 'Sign'
        KeyLength = 2048
        HashAlgorithm = 'sha256'
        NotAfter = (Get-Date).AddMonths(24)
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
           Type = 'Custom'
           Subject = 'CN=P2SChildCert'
           DnsName = 'P2SChildCert'
           KeySpec = 'Signature'
           KeyExportPolicy = 'Exportable'
           KeyLength = 2048
           HashAlgorithm = 'sha256'
           NotAfter = (Get-Date).AddMonths(18)
           CertStoreLocation = 'Cert:\CurrentUser\My'
           Signer = $RootCert
           TextExtension = @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')
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
    Add-AzVpnClientRootCertificate -VpnClientRootCertificateName $P2SRootCertName -VirtualNetworkGatewayname $VirtualNetworkGatewaysName -ResourceGroupName $ResourceGroupName -PublicCertData $CertBase64
    #endregion

    #region Generate and download the VPN client profile configuration package
    $profile = New-AzVpnClientConfiguration -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkGatewaysName -AuthenticationMethod "EapTls"
    $DestinationFile = Join-Path -Path $DestinationFolder -ChildPath $((Split-Path $profile.VPNProfileSASUrl -Leaf) -replace "\?.*$")
    $DestinationFile = $DestinationFile -replace "(\.\w*)$", $('_{0}$1' -f $TimeStamp)
    $DestinationPath = $DestinationFile -replace "(\.\w*)$", $('_{0}' -f $TimeStamp)

    Start-BitsTransfer -Source $profile.VPNProfileSASUrl -Destination $DestinationFile
    Expand-Archive -Path $DestinationFile -DestinationPath $DestinationPath
    $VpnProfileSetupPowerShellScript = (Get-ChildItem -Path $DestinationPath -Filter VpnProfileSetup.ps1 -Recurse).FullName
    & $VpnProfileSetupPowerShellScript -Force
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
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

New-AzP2SVPN -Connect -Verbose
#endregion