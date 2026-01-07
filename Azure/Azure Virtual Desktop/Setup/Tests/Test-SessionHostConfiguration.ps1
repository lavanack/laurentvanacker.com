#region function Definitions
#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'GeneratePassword')]
    param
    (
        [ValidateRange(12, 122)]
        [int] $minLength = 12, ## characters
        [ValidateRange(13, 123)]
        [ValidateScript({ $_ -gt $minLength })]
        [int] $maxLength = 15, ## characters
        [switch] $AsSecureString,
        [switch] $ClipBoard,
        [Parameter(ParameterSetName = 'GeneratePassword')]
        [int] $nonAlphaChars = 3,
        [Parameter(ParameterSetName = 'DinoPass')]
        [switch] $Online
    )
    #From https://learn.microsoft.com/en-us/azure/virtual-machines/windows/faq#what-are-the-password-requirements-when-creating-a-vm-
    $ProhibitedPasswords = @('abc@123', 'iloveyou!', 'P@$$w0rd', 'P@ssw0rd', 'P@ssword123', 'Pa$$word', 'pass@word1', 'Password!', 'Password1', 'Password22')
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    Do {
        if ($Online) {
            $URI = "https://www.dinopass.com/password/custom?length={0}&useSymbols=true&useNumbers=true&useCapitals=true" -f $length
            $RandomPassword = Invoke-RestMethod -Uri $URI
        }
        else {
            Add-Type -AssemblyName 'System.Web'
            $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        }
    } Until (($RandomPassword -notin $ProhibitedPasswords) -and (($RandomPassword -match '[A-Z]') -and ($RandomPassword -match '[a-z]') -and ($RandomPassword -match '\d') -and ($RandomPassword -match '\W')))

    #Write-Host -Object "The password is : $RandomPassword"
    if ($ClipBoard) {
        #Write-Verbose -Message "The password has beeen copied into the clipboard (Use Win+V) ..."
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

#region Main code
Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount -UseDeviceAuthentication
}
#endregion

#region Microsoft Graph Connection
try {
    $null = Get-MgBetaDevice -All -ErrorAction Stop
}
catch {
    Connect-MgGraph -NoWelcome -Scopes "Directory.Read.All"
}
#endregion


#region Variable Definitions
$RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
$CustomRdpProperty = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
$Index = $(Get-Random -Minimum 0 -Maximum 1000)
$ResourceGroupNamePattern = "rg-hp-np-ad-shc-mp-use2" 
$ResourceGroupName = "{0}-{1:D3}" -f $ResourceGroupNamePattern, $Index
$Tag = @{Test=$true}
$Location = "eastus2"
$SubNetId = "/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-ad-use2-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-use2-002/subnets/snet-avd-avd-use2-002"
$vNetId = $SubNetId -replace "/subnets/.*"
#endregion

#region Remove any existing ResourceGroup
$null = Get-AzResourceGroup -ResourceGroupName $("{0}*" -f $ResourceGroupNamePattern) | Remove-AzResourceGroup -AsJob -Force
#endregion

#region ResourceGroup
$Parameters = @{
    Name                  = $ResourceGroupName
    Location              = $Location
    Force                 = $true
    #Verbose               = $true
}
$null = Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction Ignore
$ResourceGroup = New-AzResourceGroup @Parameters
#endregion

#region Key Vault
#region Create an Azure Key Vault
#$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization #-EnablePurgeProtection
#As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
#$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru
$KeyVaultName = $ResourceGroupName -replace "^rg", "kv" -replace "\W"
$Parameters = @{
    VaultName          = $KeyVaultName
    Location           = $Location
    InRemovedState     =$true
    #Verbose            = $true
}
Get-AzKeyVault @Parameters | Remove-AzKeyVault -InRemovedState -Force -ErrorAction Ignore
$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 #-EnablePurgeProtection

#region 'Key Vault Administrator' RBAC Assignment
#region MySelf
$RoleDefinition = Get-AzRoleDefinition -Name "Key Vault Administrator"
$Parameters = @{
    SignInName         = (Get-AzContext).Account.Id
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $KeyVault.ResourceId
}
while (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters
    Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion 
#endregion 

$UserName = "localadmin"
$SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
Write-Host "UserName: $UserName"
$SecurePassword = New-RandomPassword -AsSecureString
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "LocalAdminUserName" -SecretValue $SecureUserName
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "LocalAdminPassword" -SecretValue $SecurePassword


$UserName = "adjoin"
$SecureUserName = $(ConvertTo-SecureString -String $UserName -AsPlainText -Force) 
Write-Host "UserName: $UserName"
$AdJoinUserClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$SecurePassword = ConvertTo-SecureString -String $AdJoinUserClearTextPassword -AsPlainText -Force
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "AdJoinUserName" -SecretValue $SecureUserName
$secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name "AdJoinPassword" -SecretValue $SecurePassword
#endregion
#endregion

#region HostPool
$CurrentHostPool = [PSCustomObject] @{
    Name = $ResourceGroupName -replace "^rg-"
    GetSessionHostConfigurationName = $ResourceGroupName -replace "^rg", "shc"
    LoadBalancerType = "BreadthFirst"
    PreferredAppGroupType = "Desktop"
    MaxSessionLimit = 5
    Location = $Location
    NamePrefix = "namuse2{0:D3}" -f $Index
    VMSize = "Standard_D2s_v5"
    SubnetId = $SubNetId
    ImagePublisherName = "microsoftwindowsdesktop"
    ImageOffer = "windows-11"
    ImageSku = "win11-25h2-ent"
    DistinguishedName = "OU=PooledDesktops,OU=$Location,OU=AVD,DC=csa,DC=fr"
    DomainName = "csa.fr"
    KeyVault = $KeyVault
    VMNumberOfInstances = 3
    ResourceGroupName = $ResourceGroupName
    CustomConfigurationScriptUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/3148cab7ec65e4eb39e3eaed14b263ecd18bff1b/Azure/Azure%20VM%20Image%20Builder/Install-VSCode.ps1"
}

$Parameters = @{
    Name                  = $CurrentHostPool.Name
    ResourceGroupName     = $ResourceGroupName
    HostPoolType          = 'Pooled'
    LoadBalancerType      = $CurrentHostPool.LoadBalancerType
    PreferredAppGroupType = $CurrentHostPool.PreferredAppGroupType
    MaxSessionLimit       = $CurrentHostPool.MaxSessionLimit
    Location              = $CurrentHostPool.Location
    StartVMOnConnect      = $true
    # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
    # No RDP redirection for COM ports, Local Drives and printers.
    ExpirationTime        = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    CustomRdpProperty     = $CustomRdpProperty
    IdentityType          = "SystemAssigned"
    Tag                   = $Tag
    ManagementType        = 'Automated'
    #Verbose               = $true
}
$CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
#endregion



#region RBAC Assignments to the HostPool System-Assigned Managed Identity
$ObjectId = $CurrentAzWvdHostPool.IdentityPrincipalId

#region 'Desktop Virtualization Virtual Machine Contributor' RBAC Assignment
$NsgId = (Get-AzVirtualNetworkSubnetConfig -ResourceId $SubNetId).NetworkSecurityGroup.Id
$Scopes = (Get-AzResourceGroup -ResourceGroupName $CurrentHostPool.ResourceGroupName).ResourceId, $vNetId, $NsgId
#/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-aib-use2-1750417854/providers/Microsoft.Compute/galleries/acg_avd_use2_1750417854/images/win11-24h2-avd-json-vscode/versions/2025.06.20
if ($CurrentHostPool.VMSourceImageId) {
    #$ACGResourceGroupId = $(Get-AzresourceGroup  -ResourceGroupName $((Get-AzResource -ResourceId $CurrentHostPool.VMSourceImageId).ResourceGroupName)).ResourceId
    $ACGResourceGroupId = $CurrentHostPool.VMSourceImageId -replace "/providers/.*"
    $Scopes += $ACGResourceGroupId
}
$RoleDefinition = Get-AzRoleDefinition -Name "Desktop Virtualization Virtual Machine Contributor"
foreach ($Scope in $Scopes) {
    $Parameters = @{
        ObjectId           = $ObjectId
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $Scope
    }
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
}
#endregion 

#region 'Key Vault Secrets User' RBAC Assignment
$RoleDefinition = Get-AzRoleDefinition -Name "Key Vault Secrets User"
$Parameters = @{
    ObjectId           = $ObjectId
    RoleDefinitionName = $RoleDefinition.Name
    Scope              = $KeyVault.ResourceId
}
while (-not(Get-AzRoleAssignment @Parameters)) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
    $RoleAssignment = New-AzRoleAssignment @Parameters
    Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
    Start-Sleep -Seconds 30
}
#endregion 
#endregion



#region SessionHostConfiguration
$ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq $CurrentHostPool.ImagePublisherName}
$ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer  -eq $CurrentHostPool.ImageOffer}
$ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus  -eq $CurrentHostPool.ImageSku}
$LatestImage = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1

$parameters = @{
        FriendlyName = $CurrentHostPool.GetSessionHostConfigurationName
        HostPoolName = $CurrentHostPool.Name
        ResourceGroupName = $CurrentHostPool.ResourceGroupName
        VMNamePrefix = $CurrentHostPool.NamePrefix
        VMLocation = $CurrentHostPool.Location
        ImageInfoImageType = 'Marketplace'
        VMSizeId = $CurrentHostPool.VMSize
        ManagedDiskType = 'StandardSSD_LRS'
        NetworkInfoSubnetId = $CurrentHostPool.SubnetId
        #DiffDiskSettingOption = 'Local'
        #DiffDiskSettingPlacement = 'CacheDisk'
        SecurityInfoType = 'TrustedLaunch'
        VMAdminCredentialsUsernameKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "LocalAdminUserName").Id
        VMAdminCredentialsPasswordKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "LocalAdminPassword").Id
        MarketplaceInfoPublisher = $CurrentHostPool.ImagePublisherName
        MarketplaceInfoOffer = $CurrentHostPool.ImageOffer 
        MarketplaceInfoSku = $CurrentHostPool.ImageSku
        MarketplaceInfoExactVersion = $LatestImage.Version
        DomainInfoJoinType = 'ActiveDirectory'
        ActiveDirectoryInfoOuPath = $CurrentHostPoolOU.DistinguishedName
        ActiveDirectoryInfoDomainName = $DomainName
        DomainCredentialsUsernameKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "AdJoinUserName").Id
        DomainCredentialsPasswordKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "AdJoinPassword").Id
        CustomConfigurationScriptUrl = $CurrentHostPool.CustomConfigurationScriptUrl
        #Debug = $true
}
$SessionHostConfiguration = New-AzWvdSessionHostConfiguration @parameters
#endregion

#region SessionHostManagement
$parameters = @{
    HostPoolName = $CurrentHostPool.Name
    ResourceGroupName = $CurrentHostPool.ResourceGroupName
    ScheduledDateTimeZone = $(Get-TimeZone)
    UpdateLogOffDelayMinute = 5
    UpdateMaxVmsRemoved = 1
	ProvisioningInstanceCount = $CurrentHostPool.VMNumberOfInstances
    UpdateDeleteOriginalVM = $False
    UpdateLogOffMessage = 'Update LogOff Message: You will be logged off in 5 minutes'
}

New-AzWvdSessionHostManagement @parameters
#endregion
#endregion