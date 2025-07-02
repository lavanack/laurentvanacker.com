param(
	[switch]$Force,
	[switch]$MachineCertAuth
)
$EAP = '<EapHostConfig
	xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
	<EapMethod>
		<Type
			xmlns="http://www.microsoft.com/provisioning/EapCommon">13
		</Type>
		<VendorId
			xmlns="http://www.microsoft.com/provisioning/EapCommon">0
		</VendorId>
		<VendorType
			xmlns="http://www.microsoft.com/provisioning/EapCommon">0
		</VendorType>
		<AuthorId
			xmlns="http://www.microsoft.com/provisioning/EapCommon">0
		</AuthorId>
	</EapMethod>
	<Config
		xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
		<Eap
			xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
			<Type>13</Type>
			<EapType
				xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
				<CredentialsSource>
					<CertificateStore>
						<SimpleCertSelection>true</SimpleCertSelection>
					</CertificateStore>
				</CredentialsSource>
				<ServerValidation>
					<DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
					<ServerNames></ServerNames>
					<TrustedRootCA>DF 3C 24 F9 BF D6 66 76 1B 26 80 73 FE 06 D1 CC 8D 4F 82 A4 </TrustedRootCA>

				</ServerValidation>
				<DifferentUsername>false</DifferentUsername>
				<PerformServerValidation
					xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true
				</PerformServerValidation>
				<AcceptServerName
					xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">false
				</AcceptServerName>
				<TLSExtensions
					xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">
					<FilteringInfo
						xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3">
						<CAHashList Enabled="true">
							<IssuerHash>B7 53 84 A6 09 B6 64 E5 8E 71 7E 79 A4 14 75 51 E5 37 0E 93 </IssuerHash>

						</CAHashList>
					</FilteringInfo>
				</TLSExtensions>
			</EapType>
		</Eap>
	</Config>
</EapHostConfig>'

$Connection = Get-VpnConnection -Name vnet-p2s-vpn-use2-060
if($connection -ne $null)
{
	try
    {
     if ($Force -eq $false) {
            $title = 'Confirm VPN update'
            $question = 'There is a VPN connection with same name already present, do you want to rewrite it?'
            $choices = '&Yes', '&No'
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 1) {
	            Write-Host "Exiting as update was rejected."
	            exit
	        }
        }
	    Remove-VpnConnection -Name vnet-p2s-vpn-use2-060 -Force -ErrorAction Stop
		Write-Host "Removed older version of the VPN connection"
	}
	catch
	{
		Write-Error "Error while Removing old connection: $_"
		exit
	}
}
try
{
    if ($MachineCertAuth -eq $false)
    {
        Add-VpnConnection -Name vnet-p2s-vpn-use2-060 -ServerAddress azuregateway-e5d50078-7cbf-4cf2-8cce-0b6ce7044648-4170ece24e08.vpn.azure.com -TunnelType Ikev2 -AuthenticationMethod Eap -SplitTunneling:$True -RememberCredential -EncryptionLevel Optional -EapConfigXmlStream $EAP -PassThru
    } else {
        Add-VpnConnection -Name vnet-p2s-vpn-use2-060 -ServerAddress azuregateway-e5d50078-7cbf-4cf2-8cce-0b6ce7044648-4170ece24e08.vpn.azure.com -TunnelType Ikev2 -AuthenticationMethod MachineCertificate -SplitTunneling:$True -RememberCredential -EncryptionLevel Optional -PassThru
    }
}
catch
{
	Write-Error "Error while creating new connection: $_"
	exit
}

try
{
	((Get-Content -Raw -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk') -replace "(?s)(.*)DisableClassBasedDefaultRoute=0(.*)","`$1DisableClassBasedDefaultRoute=1`$2") | Set-Content -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk'
	((Get-Content -Raw -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk') -replace "(?s)(.*)PlumbIKEv2TSAsRoutes=0(.*)","`$1PlumbIKEv2TSAsRoutes=1`$2") | Set-Content -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk'
	((Get-Content -Raw -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk') -replace "(?s)(.*)AutoTiggerCapable=0(.*)","`$1AutoTiggerCapable=1`$2") | Set-Content -path '~\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk'
    Write-Host "Edited pbk file with required changes"
}
catch
{
	Write-Host "Error while editing the PBK file: $_"
}

Add-VpnConnectionRoute -ConnectionName vnet-p2s-vpn-use2-060 -DestinationPrefix 10.1.0.0/16
Add-VpnConnectionRoute -ConnectionName vnet-p2s-vpn-use2-060 -DestinationPrefix 172.16.201.0/24
