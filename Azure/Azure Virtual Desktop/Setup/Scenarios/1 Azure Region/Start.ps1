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

#requires -Version 5 -RunAsAdministrator 

[CmdletBinding()]
Param (
    [switch] $AsJob,
    [string] $LogDir
)

#region Main code
Clear-Host
$Error.Clear()
$PSDefaultParameterValues = @{
    #To avoid warning message like: WARNING: The names of some imported commands from the module 'Microsoft.Azure.PowerShell.Cmdlets.Network' include unapproved verbs that might make them less discoverable
    'Import-Module:DisableNameChecking' = $true
}
#From https://helloitsliam.com/2021/10/25/powershell-function-and-variable-issue/
$Global:MaximumFunctionCount = 32768
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -DisableNameChecking -Force -Verbose

$StartTime = Get-Date
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$CurrentFileName = Split-Path -Path $CurrentScript -Leaf
if ([string]::IsNullOrEmpty($LogDir)) {
    $CurrentLogDir = Join-Path -Path $CurrentDir -ChildPath $("HostPool_{0:yyyyMMddHHmmss}" -f $StartTime)
}
else {
    $CurrentLogDir = Join-Path -Path $LogDir -ChildPath $("HostPool_{0:yyyyMMddHHmmss}" -f $StartTime)
}
$BackupDir = Join-Path -Path $CurrentDir -ChildPath "Backup"
$null = New-Item -Path $CurrentLogDir, $BackupDir -ItemType Directory -Force
Set-Location -Path $CurrentDir
#$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f $StartTime).txt"
$TranscriptFile = Join-Path -Path $CurrentLogDir -ChildPath $($CurrentFileName -replace ".ps1$", $("_{0:yyyyMMddHHmmss}.txt" -f $StartTime))
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader #-Verbose

#region function calls
#region Prerequisites
if (-not(Test-DomainController)) {
    Write-Error -Message "The '$env:COMPUTERNAME' is NOT an ADDS Domain Controller" -ErrorAction Stop
    Stop-Transcript
}

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
#$null = Update-AzConfig -DisplayBreakingChangeWarning $false

Connect-PsAvdAzure
Register-PsAvdRequiredResourceProvider
Install-PsAvdFSLogixGpoSettings #-Force
Install-PsAvdAvdGpoSettings #-Force
#endregion

#region Getting Current Azure location (based on the Subnet location of this DC) to deploy the Azure compute Gallery in the same location that the other resources
$ThisDomainControllerSubnet = Get-AzVMSubnet
#endregion

#region AVD Dedicated VNets and Subnets
#region Primary Region
$PrimaryRegionResourceGroupName = "rg-avd-ad-use2-002"
$PrimaryRegionVNetName = "vnet-avd-avd-use2-002"
$PrimaryRegionSubnetName = "snet-avd-avd-use2-002"
$PrimaryRegionVNet = Get-AzVirtualNetwork -Name $PrimaryRegionVNetName -ResourceGroupName $PrimaryRegionResourceGroupName
$PrimaryRegionSubnet = $PrimaryRegionVNet  | Get-AzVirtualNetworkSubnetConfig -Name $PrimaryRegionSubnetName
$PrimaryRegion = $PrimaryRegionVNet.Location
#$PrimaryRegion                  = (Get-AzVMCompute).Location
#endregion
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
    New-PsAvdPrivateEndpointSetup -SubnetId $ThisDomainControllerSubnet.Id -KeyVault $HostPoolSessionCredentialKeyVault
}
#endregion
#endregion


#region Listing Azure VMs with Ephemeral OS Disk
$PrimaryRegionAzureEphemeralOsDiskSku = [HostPool]::GetAzureEphemeralOsDiskSku($PrimaryRegion)
#endregion


#region Creating Host Pools
#Reset Index (starting at 1) for automatic numbering (every instantiation will increment the Index)
[PooledHostPool]::ResetIndex()
[PersonalHostPool]::ResetIndex()
#We don't go to 1000 to keep 10 values to be sure that we can provide at leat 10 hostpools (adjust this limit if needed)
$RandomNumber = Get-Random -Minimum 1 -Maximum 990
[PooledHostPool]::SetIndex($RandomNumber, $PrimaryRegion)
[PersonalHostPool]::SetIndex($RandomNumber, $PrimaryRegion)

#Uncomment the best scenario for your usage or create your own
#$HostPools = & "..\1 Azure Region\1_Personal_AD_Win10.ps1"
$HostPools = & "..\1 Azure Region\1_Pooled_AD.ps1"
#$HostPools = & "..\1 Azure Region\1_Pooled_AD_FSLogix_AzureAppAttach.ps1"
#$HostPools = & "..\1 Azure Region\1_Pooled_EntraID_FSLogixCloudCache_AzureAppAttach.ps1"
#$HostPools = & "..\1 Azure Region\2_Pooled_2_Personal_AD_Misc.ps1"
#$HostPools = & "..\1 Azure Region\2_Pooled_EntraID_AD_AzureAppAttach.ps1"
#$HostPools = & "..\1 Azure Region\2_Pooled_EntraID_Intune_AD_FSLogixCloudCache_Watermarking_SpotInstance.ps1"
#$HostPools = & "..\1 Azure Region\3_Pooled_EntraID_AD_Misc.ps1"
#$HostPools = & "..\1 Azure Region\6_Pooled_2_Personal_EntraID_AD_Misc.ps1"
#$HostPools = & "..\1 Azure Region\X_Pooled_ACG_NoFSLogix_NoMSIX.ps1".ps1"
#$HostPools = & "..\1 Azure Region\X_Pooled_AD_ACG_NoFSLogix_NoMSIX.ps1".ps1"
#endregion

#Removing $null object(s) if any.
$HostPools = $HostPools | Where-Object -FilterScript { $null -ne $_ }
#endregion

#region Removing previously existing resources
#$LatestHostPoolJSONFile = Get-ChildItem -Path $CurrentDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending | Select-Object -First 1
$LatestHostPoolJSONFile = Get-ChildItem -Path $BackupDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending
if ($LatestHostPoolJSONFile) {
    Remove-PsAvdHostPoolSetup -FullName $LatestHostPoolJSONFile.FullName #-KeepAzureAppAttachStorage
}
else {
    Remove-PsAvdHostPoolSetup -HostPool $HostPools #-KeepAzureAppAttachStorage
}
#endregion

#region Checking  Storage Account and Key Vault Name Availability
if (-not(Test-PsAvdStorageAccountNameAvailability -HostPool $HostPools)) {
    Stop-Transcript
    Write-Error -Message "Storage Account Name(s) NOT available" -ErrorAction Stop 
}

if (-not(Test-PsAvdKeyVaultNameAvailability -HostPool $HostPools)) {
    Stop-Transcript
    Write-Error -Message "Key Vault Name(s) NOT available" -ErrorAction Stop 
}
#endregion

#region Backing up the configuration (can be used for a future cleanup)
$HostPoolBackup = New-PsAvdHostPoolBackup -HostPool $HostPools -Directory $BackupDir
#endregion

#region Setting up
#Setting up the hostpool(s)
$NoMFAEntraIDGroupName = "No-MFA Users"
New-PsAvdHostPoolSetup -HostPool $HostPools -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -LogDir $CurrentLogDir  -AMBA -WorkBook -Restart -RDCMan -AsJob:$AsJob
#Or pipeline processing call
#$HostPools | New-PsAvdHostPoolSetup #-AsJob 

#Starting a Windows Explorer instance per FSLogix profiles share
Get-PsAvdFSLogixProfileShare -HostPool $HostPools

#Starting a Windows Explorer instance per MSIX profiles share
Get-PsAvdAppAttachProfileShare -HostPool $HostPools

#region Adding Test Users (under the OrgUsers OU) as HostPool Users (for all HostPools)
$AVDUserGroupName = 'AVD Users'
Get-ADGroup -Filter "Name -like 'hp*-*Application Group Users'" | Add-ADGroupMember -Members $AVDUserGroupName
Start-MicrosoftEntraIDConnectSync
#endregion

<#
#region Adding Test Users (under the OrgUsers OU) as Memebers of the "No-MFA Users" group (if any)
$NoMFAEntraIDGroup = Get-MgBetaGroup -Filter "DisplayName eq '$NoMFAEntraIDGroupName'"
$AVDUserGroup = Get-MgBetaGroup -Filter "DisplayName eq '$AVDUserGroupName'"
if (($null -ne $NoMFAEntraIDGroup) -and (-not((Get-MgBetaGroupMember -GroupId $NoMFAEntraIDGroup.Id).Id -contains $AVDUserGroup.Id))) {
    New-MgBetaGroupMember -GroupId $NoMFAEntraIDGroup.Id -DirectoryObjectId $AVDUserGroup.Id
}
#endregion
#>
#endregion

#region Updating the UsageLocation to France for all users (Adjust depending on your needs and from which country you will connect from)
<#
#Updating the UsageLocation to the current machine location for all users
$UsageLocation = (Invoke-RestMethod -Uri http://ip-api.com/json/?fields=countryCode).countryCode

#Updating the UsageLocation to the current RDP client location for all users
$UsageLocation = (Invoke-RestMethod -Uri $("http://ip-api.com/json/{0}?fields=countryCode" -f (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore | Select-Object -First 1).RemoteAddress)).CountryCode
#>

$UsageLocation = "FR"
Update-PsAvdMgBetaUserUsageLocation -UsageLocation $UsageLocation -Force -Verbose
#endregion

#region Assigning E5 licenses (if available) to the 'AVD Users' Entra ID Group
$SkuPartNumber = 'Microsoft_365_E5_(no_Teams)'
#https://developer.microsoft.com/en-us/graph/known-issues/?search=20454
#$SubscribedSku = Get-MgBetaSubscribedSku -All -Search "SkuPartNumber:'$SkuPartNumber'"
$SubscribedSku = Get-MgBetaSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $SkuPartNumber }
$SubscribedSkuAvailableLicenses = $SubscribedSku.PrepaidUnits.Enabled - $SubscribedSku.ConsumedUnits
Write-Verbose -Message "'$SkuPartNumber' Available License Number: $SubscribedSkuAvailableLicenses"
if ($SubscribedSkuAvailableLicenses -gt 0) {
    Set-PsAvdMgBetaUsersGroupLicense -GroupDisplayName $AVDUserGroupName -SkuPartNumber $SkuPartNumber -Verbose
}
else {
    Write-Verbose -Message "No more licenses availables for '$SkuPartNumber'"
    $AssignedLicenses = Get-MgBetaUser -Filter "assignedLicenses/any(x:x/skuId eq $($SubscribedSku.SkuId) )" -ConsistencyLevel eventual -CountVariable e5licensedUserCount -All
    Write-Verbose -Message "Assigned Licenses for '$SkuPartNumber': $($AssignedLicenses.DisplayName -join ', ')"
    $AVDUserGroupMembersWithoutAssignedLicenses = Get-MgBetaUser -Filter "not(assignedLicenses/any(x:x/skuId eq $($SubscribedSku.SkuId))) and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable e5licensedUserCount -All | Where-Object -FilterScript { $_.Id -in $((Get-MgBetaGroupMember -GroupId $(Get-MgBetaGroup -Filter "DisplayName eq '$AVDUserGroupName'").Id).Id) }
    Write-Verbose -Message "AVD User Group Members Without Assigned Licenses for '$SkuPartNumber': $($AVDUserGroupMembersWithoutAssignedLicenses.DisplayName -join ', ')"
}
#endregion

$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Overall Processing Time: $($TimeSpan.ToString())"

#$VerbosePreference = $PreviousVerbosePreference
Stop-Transcript

Invoke-PsAvdErrorLogFilePester -LogDir $CurrentLogDir
