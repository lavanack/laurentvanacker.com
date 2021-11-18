# From (with minor changes) https://docs.microsoft.com/en-us/azure/virtual-desktop/create-host-pools-powershell
Clear-Host
Get-Variable -Scope Script | Remove-Variable -Scope Script -Force -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$SettingsJSONFile = $CurrentScript -replace "ps1$", "json"
$Settings = Get-Content $SettingsJSONFile | ConvertFrom-Json
#We will create an AADS domain with the same name than the directory. For instance Azure Directory = contoso.com ==> AADS = contoso.com
$AzureADDSDomainName = $Settings.AzureADDS.DomainName.value
$AzureADDSAdminUserUpn = $Settings.AzureADDS.AdminUserUpn.value
$AzureLocation = $Settings.Azure.Location.value
$AzureSubscriptionName = $Settings.Azure.SubscriptionName.value


$WVDResourceGroupName = $Settings.WVD.ResourceGroupName.value


#region Defining variables for networking part

$AzureADUserMailNickName    = "dvu"
$AzureADUserDisplayName     = "Desktop Virtualization User"

$AzureADGroupDisplayName    = "Desktop Virtualization Users"
$AzureADGroupMailNickName   = "DesktopVirtualizationUsers"

$ResourceGroupName          = "WVD-RG"
$HostPoolName               = "WVD-HP"
$WorkSpaceName              = "WVD-WS"
$TokenExpirationTime        = $((get-date).ToUniversalTime().AddHours(2).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))

#endregion

$AzureADUserUPN             = "$AzureADUserMailNickName@$AzureADDSDomainName"
$AppGroupName               = "$HostPoolName-DAG"

if ("Az.DesktopVirtualization" -notin (Get-Module -ListAvailable).Name)
{
    Install-Module -Name Az.DesktopVirtualization
}

Import-Module -Name Az.DesktopVirtualization
# Login to your Azure subscription.
Connect-AzAccount
$Subscription = Get-AzSubscription -SubscriptionName $AzureSubscriptionName -ErrorAction Ignore
#Get Tenant matching the specified tenant name
$AzTenant = Get-AzTenant | Where-Object -FilterScript { $AzureADDSDomainName -in $_.Domains}
Set-AzContext -Subscription $Subscription -Tenant $AzTenant

#Connect to Azure Active Directory
Connect-AzAD

#Registering the Microsoft.DesktopVirtualization providerin the subscription
Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup)
{
    #Step 0: Remove previously existing Azure Resource Group with the "WVD-RG" name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}

#Step 1: Create Azure Resource Group
# Create Resource Groups and Storage Account for diagnostic
New-AzResourceGroup -Name $ResourceGroupName -Location $AzureLocation

#Step 2: Create the Host pool
$AzWvdHostPool = New-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName -WorkspaceName $WorkSpaceName -HostPoolType Pooled -LoadBalancerType BreadthFirst -Location $AzureLocation -DesktopAppGroupName $AppGroupName -PreferredAppGroupType Desktop

#Step 3: Create a registration token to authorize a session host to join the host pool and save it to a new file on your local computer
$AzWvdRegistrationInfo = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName -ExpirationTime $TokenExpirationTime
#$AzWvdRegistrationInfo = Get-AzWvdRegistrationInfo -ResourceGroupName ResourceGroupName -HostPoolName $HostPoolName

#Step 4: Create a user (if needed)
$AzureADUser = Get-AzADUser -ObjectId $AzureADUserUPN -ErrorAction Ignore
if (-not($AzureADUser))
{
    $Credential = Get-Credential -UserName $AzureADUserUPN -Message "Enter the password for the AD User you want to create ..."
    $AzureADUser = New-AzADUser -DisplayName $AzureADUserDisplayName -UserPrincipalName $AzureADUserUPN -Password $Credential.Password -MailNickname $AzureADUserMailNickName
}

#Step 5: Create a group for Desktop Virtualization Users (if needed)
$AzureADGroup = Get-AzADGroup -SearchString $AzureADGroupDisplayName -ErrorAction Ignore
if (-not($AzureADGroup))
{
    $AzureADGroup = New-AzADGroup -DisplayName $AzureADGroupDisplayName -Description $AzureADGroupDisplayName -MailNickName $AzureADGroupMailNickName
}
#Adding the User to the group
Add-AzADGroupMember -MemberUserPrincipalName $AzureADUserUPN -TargetGroupDisplayName $AzureADGroupDisplayName

#Step 6: Add Azure Active Directory users to the default desktop app group for the host pool.
#$AzRoleAssignment = New-AzRoleAssignment -SignInName $AzureADUserUPN -RoleDefinitionName "Desktop Virtualization User" -ResourceName "$($HostPoolName)-DAG" -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.DesktopVirtualization/applicationGroups'

#Step 6: Add Azure Active Directory Group to the default desktop app group for the host pool.
$AzRoleAssignment = New-AzRoleAssignment -ObjectId $AzureADGroup.Id -RoleDefinitionName "Desktop Virtualization User" -ResourceName $AppGroupName -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.DesktopVirtualization/applicationGroups'

#New PowerShell script on GitHub to add WVD Hosts to a host pool : https://medium.com/wortell/new-powershell-script-on-github-to-add-wvd-hosts-to-a-host-pool-cab5d3b08321