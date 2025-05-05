Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

$Global:MaximumFunctionCount = 32768
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -Force
Connect-MgGraph -NoWelcome

#region Creating Host Pools

#region Getting Current Azure location (based on the Subnet location of this DC) to deploy the Azure compute Gallery in the same location that the other resources
$ThisDomainControllerSubnet = Get-AzVMSubnet
#endregion

#region ADJoin User
$AdJoinUserName = 'adjoin'
$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$AdJoinPassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
#endregion

#region Azure Key Vault for storing ADJoin Credentials
$HostPoolSessionCredentialKeyVault = $null
$VaultName = $null

#region Reusing existing Keyvault for credential management : Comment this for using a new Keyvault at every run
#Returns a PSKeyVault object
$VaultName = (Get-AzKeyVault | Where-Object -FilterScript { $_.VaultName -match "^kvavdhpcred" }).VaultName | Select-Object -First 1
#Doesn't return a PSKeyVault object but a PSKeyVaultIdentityItem
#$HostPoolSessionCredentialKeyVault = Get-AzKeyVault -Name kvavdhpcred* | Select-Object -First 1
#endregion

if (-not([string]::IsNullOrEmpty($VaultName))) {
    $HostPoolSessionCredentialKeyVault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Ignore
}
if ($null -eq $HostPoolSessionCredentialKeyVault) {
    #region ADJoin User
    $AdJoinUserName = 'adjoin'
    $AdJoinUserClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
    $AdJoinUserPassword = ConvertTo-SecureString -String $AdJoinUserClearTextPassword -AsPlainText -Force
    $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinUserPassword)
    #endregion
    $HostPoolSessionCredentialKeyVault = New-PsAvdHostPoolSessionHostCredentialKeyVault -ADJoinCredential $ADJoinCredential -Subnet $ThisDomainControllerSubnet
}
else {
    Write-Warning -Message "We are reusing '$($HostPoolSessionCredentialKeyVault.VaultName)' the KeyVault"
    #Creating a Private EndPoint for this KeyVault on this Subnet
    #New-PsAvdPrivateEndpointSetup -SubnetId $ThisDomainControllerSubnet.Id -KeyVault $HostPoolSessionCredentialKeyVault
}
#endregion

#region AVD Dedicated VNets and Subnets
#region Primary Region
$PrimaryRegionResourceGroupName = "rg-avd-ad-use2-002"
$PrimaryRegionVNetName          = "vnet-avd-avd-use2-002"
$PrimaryRegionSubnetName        = "snet-avd-avd-use2-002"
$PrimaryRegionVNet              = Get-AzVirtualNetwork -Name $PrimaryRegionVNetName -ResourceGroupName $PrimaryRegionResourceGroupName
$PrimaryRegionSubnet            = $PrimaryRegionVNet  | Get-AzVirtualNetworkSubnetConfig -Name $PrimaryRegionSubnetName
$PrimaryRegion                  = $PrimaryRegionVNet.Location
#$PrimaryRegion                  = (Get-AzVMCompute).Location
#endregion

#region Secondary Region (for ASR and FSLogix Cloud Cache)
$SecondaryRegionResourceGroupName = "rg-avd-ad-use2-002"
$SecondaryRegionVNetName          = "vnet-avd-avd-use2-002"
$SecondaryRegionSubnetName        = "snet-avd-avd-use2-002"
$SecondaryRegionVNet              = Get-AzVirtualNetwork -Name $SecondaryRegionVNetName -ResourceGroupName $SecondaryRegionResourceGroupName
$SecondaryRegionSubnet            = $SecondaryRegionVNet  | Get-AzVirtualNetworkSubnetConfig -Name $SecondaryRegionSubnetName
$SecondaryRegion                  = $SecondaryRegionVNet.Location
#$SecondaryRegion                  = [HostPool]::GetAzurePairedRegion($PrimaryRegion)
#endregion
#endregion

#[int] $RandomNumber = ((Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -match "^hp-pd|np-ad|ei-poc-mp|cg-\w{3,4}-\d{3}$"}).Name -replace ".*-(\d+)$", '$1' | Sort-Object | Select-Object -First 1)-1
[int] $RandomNumber = ((Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -match "^hp-pd|np-ad|ei-poc-mp|cg-\w+-\d+$"}).Name -replace ".*-(\d+)$", '$1' | Sort-Object | Select-Object -First 1)-1
[PooledHostPool]::ResetIndex()
[PersonalHostPool]::ResetIndex()

[PooledHostPool]::SetIndex($RandomNumber, $PrimaryRegion)
[PersonalHostPool]::SetIndex($RandomNumber, $PrimaryRegion)

[PooledHostPool]::SetIndex($RandomNumber, $SecondaryRegion)
[PersonalHostPool]::SetIndex($RandomNumber, $SecondaryRegion)

[PooledHostPool]::AppAttachStorageAccountNameHT[$PrimaryRegion] = $(Get-AzStorageAccount | Where-Object -FilterScript { $_.PrimaryLocation -eq $PrimaryRegion -and $_.StorageAccountName -match "saavdappattachpoc"} | Select-Object -First 1)
[PooledHostPool]::AppAttachStorageAccountNameHT[$SecondaryRegion] = $(Get-AzStorageAccount | Where-Object -FilterScript { $_.PrimaryLocation -eq $SecondaryRegion -and $_.StorageAccountName -match "saavdappattachpoc"} | Select-Object -First 1)

#Uncomment the best scenario for your usage or create your own
#$HostPools = & "..\Scenarios\2 Azure Regions\2_Pooled_AD_FSLogixCloudCache_Watermarking.ps1"
#$HostPools = & "..\Scenarios\2 Azure Regions\3_Pooled_2_Personal_AD_Misc..ps1"
#$HostPools = & "..\Scenarios\2 Azure Regions\4_Pooled_AD_AzureAppAttach..ps1"
#$HostPools = & "..\Scenarios\2 Azure Regions\4_Pooled_EntraID_FSLogixCloudCache..ps1"
#$HostPools = & "..\Scenarios\2 Azure Regions\4_Pooled_EntraID_Intune_AD_FSLogixCloudCache_Watermarking_SpotInstance..ps1"
#$HostPools = & "..\Scenarios\2 Azure Regions\8_Pooled_EntraID_AD_AzureAppAttach..ps1"

$HostPools = & "..\Scenarios\1 Azure Region\1_Pooled_AD.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\1_Personal_AD_Win10.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\1_Pooled_AD_FSLogix_AzureAppAttach.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\1_Pooled_EntraID_FSLogixCloudCache_AzureAppAttach.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\2_Pooled_2_Personal_AD_Misc.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\2_Pooled_EntraID_AD_AzureAppAttach.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\2_Pooled_EntraID_Intune_AD_FSLogixCloudCache_Watermarking_SpotInstance.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\3_Pooled_EntraID_AD_Misc.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\6_Pooled_2_Personal_EntraID_AD_Misc.ps1"
#$HostPools = & "..\Scenarios\1 Azure Region\X_Pooled_AD_ACG_NoFSLogix_NoMSIX.ps1"
#endregion

#region AMBA
$PooledHostPools = $HostPools | Where-Object -FilterScript { ($null -ne $_ ) -and ($_.Type -eq [HostPoolType]::Pooled) }
#endregion

Add-PsAvdAzureAppAttach -HostPool $PooledHostPools -Verbose
#endregion
