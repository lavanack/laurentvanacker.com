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

#requires -Version 5 -Modules PSAzureVirtualDesktop -RunAsAdministrator 

[CmdletBinding()]
Param (
    [switch] $AsJob,
    [string] $LogDir
)

#region Main code
Clear-Host
$Error.Clear()
#From https://helloitsliam.com/2021/10/25/powershell-function-and-variable-issue/
$Global:MaximumFunctionCount = 32768
#Import-Module -Name PSAzureVirtualDesktop -Force
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
if (-not(Test-Domaincontroller)) {
    Write-Error -Message "The '$env:COMPUTERNAME' is NOT an ADDS Domain Controller" -ErrorAction Stop
    Stop-Transcript
}

#Install-RequiredModule

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
#$null = Update-AzConfig -DisplayBreakingChangeWarning $false

Connect-PsAvdAzure
Register-PsAvdRequiredResourceProvider
Install-PsAvdFSLogixGpoSettings #-Force
Install-PsAvdAvdGpoSettings #-Force
#endregion

#region ADJoin User
$AdJoinUserName = 'adjoin'
$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$AdJoinPassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
#region Azure Key Vault for stroing ADJoin Credentials
$HostPoolSessionCredentialKeyVault = New-PsAvdHostPoolSessionHostCredentialKeyVault -ADJoinCredential $ADJoinCredential
#endregion
#endregion

#region Creating Host Pools
#Reset Index (starting at 1) for automatic numbering (every instantiation will increment the Index)
[PooledHostPool]::ResetIndex()
[PersonalHostPool]::ResetIndex()
#We don't to to 1000 to keep 10 values to be sure that we can provide at leat 10 hostpools (adjust this limit if needed)
$RandomNumber = Get-Random -Minimum 1 -Maximum 990
[PooledHostPool]::Index = $RandomNumber
[PersonalHostPool]::Index = $RandomNumber

<#
#region Getting the location of this Azure VM
$ThisDomainController = Get-AzVMCompute | Get-AzVM
# Get the VM's network interface
$ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
$ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
# Get the subnet ID
$ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
$ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
# Get the vnet ID
$ThisDomainControllerVirtualNetworkId = $ThisDomainControllerSubnetId -replace "/subnets/.*$"
$ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork
$Location = $ThisDomainControllerVirtualNetwork.Location

if ($null -eq $Location) {
    Write-Error -Message "Unable to determine the current Azure Location" -ErrorAction Stop
}
#Listing all Azure Ephemeral Os Disk Skus for the specified Azure location 
$AzureEphemeralOsDiskSku = [HostPool]::GetAzureEphemeralOsDiskSku($Location)
#endregion
#>

$HostPools = @(
    # Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault)#.EnableSpotInstance()
    # Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix, Ephemeral OS Disk (ResourceDisk mode) and a Standard_DS3_v2 size (compatible with Ephemeral OS Disk)
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMSize('Standard_D8ds_v5').EnableEphemeralOSDisk([DiffDiskPlacement]::ResourceDisk)#.EnableSpotInstance()
    # Use case 3: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix and Spot Instance VMs
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableSpotInstance()
    # Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and enrolled with Intune) with FSLogix
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).EnableIntune().DisableScalingPlan()#.SetVMNumberOfInstances(1).EnableSpotInstance()
    # Use case 5: Deploy a Personal HostPool with 2 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) 
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMNumberOfInstances(2)
    # Use case 6: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and Hibernation enabled
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableHibernation()#.EnableSpotInstance()
)

#region Creating a new Pooled Host Pool for every image definition in the Azure Compute Gallery
$Index = [PooledHostPool]::Index
#Bug: https://github.com/Azure/RDS-Templates/issues/793
# $AzureComputeGallery = New-AzureComputeGallery
# $AzureComputeGallery = Get-AzGallery | Sort-Object -Property Name -Descending | Select-Object -First 1
# $GalleryImageDefinition = Get-AzGalleryImageDefinition -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName
foreach ($CurrentGalleryImageDefinition in $GalleryImageDefinition) {
    #$LatestCurrentGalleryImageVersion = Get-AzGalleryImageVersion -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName -GalleryImageDefinitionName $CurrentGalleryImageDefinition.Name | Sort-Object -Property Id | Select-Object -Last 1
    # Use case 7 and more: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with an Image coming from an Azure Compute Gallery and without FSLogix and MSIX
    $PooledHostPool = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMSourceImageId($CurrentGalleryImageDefinition.Id).DisableFSLogix().DisableMSIX()#.EnableSpotInstance()
    Write-Verbose -Message "VM Source Image Id for the ACG Host Pool: $LatestCurrentGalleryImageVersion (MSIX: $($PooledHostPool.MSIX) / FSlogix: $($PooledHostPool.FSlogix))"
    # $HostPools += $PooledHostPool
}
#endregion
#Removing $null object(s) if any.
$HostPools = $HostPools | Where-Object -FilterScript { $null -ne $_ }
#endregion

#region Removing previously existing resources
#$LatestHostPoolJSONFile = Get-ChildItem -Path $CurrentDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending | Select-Object -First 1
$LatestHostPoolJSONFile = Get-ChildItem -Path $BackupDir -Filter "HostPool_*.json" -File | Sort-Object -Property Name -Descending
if ($LatestHostPoolJSONFile) {
    Remove-PsAvdHostPoolSetup -FullName $LatestHostPoolJSONFile.FullName
}
else {
    Remove-PsAvdHostPoolSetup -HostPool $HostPools
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
New-PsAvdHostPoolSetup -HostPool $HostPools -NoMFAEntraIDGroupName "No-MFA Users" -LogDir $CurrentLogDir -AsJob:$AsJob
#Or pipeline processing call
#$HostPools | New-PsAvdHostPoolSetup #-AsJob 

#Setting up the hostpool scaling plan(s)
New-PsAvdScalingPlan -HostPool $HostPools 
#Or pipeline processing call
#$HostPools | New-PsAvdHostPoolSetup

#Starting a Windows Explorer instance per FSLogix profiles share
Get-PsAvdFSLogixProfileShare -HostPool $HostPools

#Running RDCMan to connect to all Session Hosts (for administration purpose if needed)
New-PsAvdRdcMan -HostPool $HostPools -Install -Open

#region Restarting all session hosts
Restart-PsAvdSessionHost -HostPool $HostPools -Wait
#endregion

#region Adding Test Users (under the OrgUsers OU) as HostPool Users (for all HostPools)
$AVDUserGroupName = 'AVD Users'
Get-ADGroup -Filter "Name -like 'hp*-*Users'" | Add-ADGroupMember -Members $AVDUserGroupName
Start-MicrosoftEntraIDConnectSync
#endregion
#endregion

#region Checking data sent to the Log Analytics Workspace(s)
$Results = Invoke-PsAvdOperationalInsightsQuery -HostPool $HostPools #-Verbose
$Results.Results | Sort-Object -Property LocalTimeGenerated #| Out-GridView
#For getting all Data Collection Rule Associations
$DataCollectionRuleAssociations = $HostPools.GetResourceGroupName() | ForEach-Object -Process { Get-AzVM -ResourceGroupName $_ } | ForEach-Object -Process { Get-AzDataCollectionRuleAssociation -ResourceUri $_.Id } #| Out-GridView
#$DataCollectionRuleAssociations | Out-GridView
#endregion

<#
#region Updating the UsageLocation to the current machine location for all users
$UsageLocation = (Invoke-RestMethod -Uri http://ip-api.com/json/?fields=countryCode).countryCode
Update-PsAvdMgBetaUserUsageLocation -UsageLocation $UsageLocation -Force -Verbose
#endregion

#region Updating the UsageLocation to the current RDP client location for all users
$UsageLocation = (Invoke-RestMethod -Uri $("http://ip-api.com/json/{0}?fields=countryCode" -f (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore | Select-Object -First 1).RemoteAddress)).CountryCode
$UsageLocation
#endregion
#>

#region Updating the UsageLocation to France for all users (Adjust depending on your needs and from which country you will connect from)
Update-PsAvdMgBetaUserUsageLocation -UsageLocation FR -Force -Verbose
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
#endregion

#$VerbosePreference = $PreviousVerbosePreference
Stop-Transcript
#endregion

#$HostPools.GetFSLogixStorageAccountName() | ForEach-Object -Process { start $("\\{0}.file.core.windows.net\profiles" -f $_) }