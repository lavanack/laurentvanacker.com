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

$HostPool = $HostPools
$ModuleBase = (Get-Module -Name PSAzureVirtualDesktop -ListAvailable).ModuleBase
$PesterDirectory = Join-Path -Path $ModuleBase -ChildPath 'Pester'

#region Pester Tests
$HostPoolClassPesterTests    = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Class.Tests.ps1'
$Container = New-PesterContainer -Path $HostPoolClassPesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$HostPoolAzurePesterTests    = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $HostPoolAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$ScalingPlanAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ScalingPlan.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $ScalingPlanAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$FSLogixAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'FSLogix.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $FSLogixAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$AppAttachAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'AppAttach.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $AppAttachAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$MicrosoftEntraIDHostPools = $HostPool | Where-Object -FilterScript {$_.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID}
if ($MicrosoftEntraIDHostPools) {
    $MFAAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'MFA.Azure.Tests.ps1'
    $Container = New-PesterContainer -Path $MFAAzurePesterTests
    Invoke-Pester -Container $Container -Output Detailed #-Verbose

    $ConditionalAccessPolicyAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'ConditionalAccessPolicy.Azure.Tests.ps1'
    $Container = New-PesterContainer -Path $ConditionalAccessPolicyAzurePesterTests
    Invoke-Pester -Container $Container -Output Detailed #-Verbose
}
else {
    Write-Warning -Message "No EntraID Host Pool"
}

$CurrentLogDir = Get-ChildItem -Path .. -Filter HostPool_* -Directory -Recurse | Sort-Object -Property Name -Descending | Select-Object -First 1
$ErrorLogFilePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'Error.LogFile.Tests.ps1'
$Container = New-PesterContainer -Path $ErrorLogFilePesterTests -Data @{ LogDir = $CurrentLogDir.FullName }
Invoke-Pester -Container $Container -Output Detailed #-Verbose

$WorkBooks = @{
    #Feom https://github.com/Azure/avdaccelerator/tree/main/workload/workbooks/deepInsightsWorkbook
    "Deep Insights Workbook - AVD Accelerator" = "https://raw.githubusercontent.com/Azure/avdaccelerator/main/workload/workbooks/deepInsightsWorkbook/deepInsights.workbook"
    #From https://github.com/scautomation/Azure-Inventory-Workbook/tree/master/galleryTemplate
    "Windows Virtual Desktop Workbook - Billy York" = "https://raw.githubusercontent.com/scautomation/WVD-Workbook/master/galleryTemplate/template.json"
    #From https://github.com/microsoft/Application-Insights-Workbooks/tree/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights
    "AVD Insights - Application-Insights-Workbooks" = "https://raw.githubusercontent.com/microsoft/Application-Insights-Workbooks/master/Workbooks/Windows%20Virtual%20Desktop/AVD%20Insights/AVDWorkbookV2.workbook"
}
$WorkbookAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'WorkBook.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $WorkbookAzurePesterTests -Data @{ WorkBookName = $WorkBooks.Keys }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$WorkBookTemplates = @{
    #From https://blog.itprocloud.de/AVD-Azure-Virtual-Desktop-Error-Drill-Down-Workbook/
    #Sometimes ==> Invoke-RestMethod : The remote name could not be resolved: 'blog.itprocloud.de' raised an error so I'm hosting a copy on my own github as fallback
    "750ec0fd-74d1-4e80-be97-3001485303e8"          = "https://blog.itprocloud.de/assets/files/AzureDeployments/Workbook-AVD-Error-Logging.json", "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Virtual%20Desktop/Workbook/Workbook-AVD-Error-Logging.json"
}
$ResourceGroupName = "rg-avd-workbook-poc-{0}-001" -f [HostPool]::AzLocationShortNameHT[$PrimaryRegion].shortName
$WorkBookTemplateAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'WorkbookTemplate.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $WorkBookTemplateAzurePesterTests -Data @{ WorkBookTemplateName = $WorkBookTemplates.Keys; ResourceGroupName = $ResourceGroupName }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$WorkBookName = foreach ($CurrentResourceGroupName in $HostPool.GetResourceGroupName()) {
    (Get-AzApplicationInsightsWorkbook -Category 'workbook' -ResourceGroupName $HostPool.GetResourceGroupName()).DisplayName
}
$WorkbookAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'WorkBook.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $WorkbookAzurePesterTests -Data @{ WorkBookName = $WorkBookName }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$OSEphemeralDiskAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OSEphemeralDisk.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $OSEphemeralDiskAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed -Verbose

$OperationalInsightsQueryAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'OperationalInsightsQuery.Azure.Tests.ps1'
$Container = New-PesterContainer -Path $OperationalInsightsQueryAzurePesterTests -Data @{ HostPool = $HostPool }
Invoke-Pester -Container $Container -Output Detailed -Verbose


$HostPoolSessionHostAzurePesterTests = Join-Path -Path $PesterDirectory -ChildPath 'HostPool.SessionHost.Azure.Tests.ps1'
foreach ($CurrentHostPool in $HostPools) {
    $SessionHostName = (Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).ResourceId -replace ".*/"
    $Container = New-PesterContainer -Path $HostPoolSessionHostAzurePesterTests -Data @{ HostPool = $CurrentHostPool; SessionHostName = $SessionHostName }
    Invoke-Pester -Container $Container -Output Detailed #-Verbose
}
#endregion