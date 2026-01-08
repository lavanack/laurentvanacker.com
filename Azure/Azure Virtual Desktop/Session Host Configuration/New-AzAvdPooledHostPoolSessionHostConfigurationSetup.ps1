<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

#requires -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.KeyVault, Az.Network, Az.Resources

#region Function Definitions
function New-AzAvdPooledHostPoolSessionHostConfigurationSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential] $LocalAdminCredential,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential] $ADJoinCredential,
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "eastus2",
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidatePattern("/subscriptions/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/resourceGroups/.+/providers/Microsoft\.Network/virtualNetworks/.+/subnets/.+")] 
        [string]$SubNetId = "/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-ad-use2-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-use2-002/subnets/snet-avd-avd-use2-002",
        [Parameter(Mandatory = $true)]
        [ValidatePattern("OU=.+")] 
        [string]$OUPath
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the prefix of every Azure resource type based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -notin @('Linux') } | Select-Object -Property resource, shortName, property, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Resource Naming
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $LocationShortName = $shortNameHT[$Location].shortName
    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $ResourceGroupNamePrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $KeyVaultPrefix = $ResourceTypeShortNameHT["KeyVault/vaults"].ShortName
    $DigitNumber = 3
    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $HostPoolName = "hp-np-ad-shc-mp-{0}-{1:D3}" -f $LocationShortName, $Instance
        $KeyVaultName = "{0}{1}" -f $KeyVaultPrefix, $($HostPoolName -replace "\W")
        $ResourceGroupName = "{0}-{1}" -f $ResourceGroupNamePrefix, $HostPoolName
    } while (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolName: $HostPoolName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$KeyVaultName: $KeyVaultName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    #endregion 

    #region ResourceGroup
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$ResourceGroupName' ResourceGroup"
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }
    #endregion

    #region KeyVault Setup
    #region Create an Azure Key Vault
    #$KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 -DisableRbacAuthorization #-EnablePurgeProtection
    #As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
    #$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$KeyVaultName' KeyVault"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 #-EnablePurgeProtection
    #region 'Key Vault Administrator' RBAC Assignment
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

    #region Defining local admin credential(s)
    $SecureUserName = $(ConvertTo-SecureString -String $LocalAdminCredential.UserName -AsPlainText -Force) 
    $SecurePassword = $LocalAdminCredential.Password

    $SecretUserName = "LocalAdminUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "LocalAdminPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion

    #region Defining AD join credential(s)
    $SecureUserName = $(ConvertTo-SecureString -String $ADJoinCredential.UserName -AsPlainText -Force) 
    $SecurePassword = $ADJoinCredential.Password

    $SecretUserName = "ADJoinUserName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretUserName'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName

    $SecretPassword = "ADJoinPassword"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating a secret in $KeyVaultName called '$SecretPassword'"
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword
    #endregion
    #endregion 

    #region HostPool Setup
    #region Create a HostPool
    $CurrentHostPool = [PSCustomObject] @{
        Name                            = $HostPoolName
        GetSessionHostConfigurationName = $ResourceGroupName -replace "^rg", "shc"
        LoadBalancerType                = "BreadthFirst"
        PreferredAppGroupType           = "Desktop"
        MaxSessionLimit                 = 5
        Location                        = $Location
        NamePrefix                      = "namuse2{0:D3}" -f $Index
        VMSize                          = "Standard_D2s_v5"
        SubnetId                        = $SubNetId
        ImagePublisherName              = "microsoftwindowsdesktop"
        ImageOffer                      = "windows-11"
        ImageSku                        = "win11-25h2-ent"
        DistinguishedName               = $OUPath
        DomainName                      = $DomainName
        KeyVault                        = $KeyVault
        VMNumberOfInstances             = 3
        ResourceGroupName               = $ResourceGroupName
        CustomConfigurationScriptUrl    = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20VM%20Image%20Builder/Install-VSCode.ps1"
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
        ExpirationTime        = (Get-Date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        CustomRdpProperty     = $CustomRdpProperty
        IdentityType          = "SystemAssigned"
        Tag                   = $Tag
        ManagementType        = 'Automated'
        #Verbose               = $true
    }
    $CurrentAzWvdHostPool = New-AzWvdHostPool @Parameters
    #endregion

    #region RBAC Assignments to the HostPool System-Assigned Managed Identity
    $ObjectId = $CurrentAzWvdHostPool.IdentityPrincipalId

    #region 'Desktop Virtualization Virtual Machine Contributor' RBAC Assignment
    $NsgId = (Get-AzVirtualNetworkSubnetConfig -ResourceId $SubNetId).NetworkSecurityGroup.Id
    $vNetId = $SubNetId -replace "/subnets/.*"
    $Scopes = (Get-AzResourceGroup -ResourceGroupName $CurrentHostPool.ResourceGroupName).ResourceId, $vNetId, $NsgId
    #/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-aib-use2-1750417854/providers/Microsoft.Compute/galleries/acg_avd_use2_1750417854/images/win11-24h2-avd-json-vscode/versions/2025.06.20
    if ($CurrentHostPool.VMSourceImageId) {
        #$ACGResourceGroupId = $(Get-AzresourceGroup  -ResourceGroupName $((Get-AzResource -ResourceId $CurrentHostPool.VMSourceImageId).ResourceGroupName)).ResourceId
        $ACGResourceGroupId = $CurrentHostPool.VMSourceImageId -replace "/providers/.+"
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
    $ImagePublisherName = Get-AzVMImagePublisher -Location $Location | Where-Object -FilterScript { $_.PublisherName -eq $CurrentHostPool.ImagePublisherName }
    $ImageOffer = Get-AzVMImageOffer -Location $Location -publisher $ImagePublisherName.PublisherName | Where-Object -FilterScript { $_.Offer -eq $CurrentHostPool.ImageOffer }
    $ImageSku = Get-AzVMImageSku -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer | Where-Object -FilterScript { $_.Skus -eq $CurrentHostPool.ImageSku }
    $LatestImage = Get-AzVMImage -Location  $Location -publisher $ImagePublisherName.PublisherName -offer $ImageOffer.Offer -sku $ImageSku.Skus | Sort-Object -Property Version -Descending | Select-Object -First 1

    $Parameters = @{
        FriendlyName                                = $CurrentHostPool.GetSessionHostConfigurationName
        HostPoolName                                = $CurrentHostPool.Name
        ResourceGroupName                           = $CurrentHostPool.ResourceGroupName
        VMNamePrefix                                = $CurrentHostPool.NamePrefix
        VMLocation                                  = $CurrentHostPool.Location
        ImageInfoImageType                          = 'Marketplace'
        VMSizeId                                    = $CurrentHostPool.VMSize
        ManagedDiskType                             = 'StandardSSD_LRS'
        NetworkInfoSubnetId                         = $CurrentHostPool.SubnetId
        #DiffDiskSettingOption = 'Local'
        #DiffDiskSettingPlacement = 'CacheDisk'
        SecurityInfoType                            = 'TrustedLaunch'
        VMAdminCredentialsUsernameKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "LocalAdminUserName").Id
        VMAdminCredentialsPasswordKeyVaultSecretUri = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "LocalAdminPassword").Id
        MarketplaceInfoPublisher                    = $CurrentHostPool.ImagePublisherName
        MarketplaceInfoOffer                        = $CurrentHostPool.ImageOffer 
        MarketplaceInfoSku                          = $CurrentHostPool.ImageSku
        MarketplaceInfoExactVersion                 = $LatestImage.Version
        DomainInfoJoinType                          = 'ActiveDirectory'
        ActiveDirectoryInfoOuPath                   = $CurrentHostPoolOU.DistinguishedName
        ActiveDirectoryInfoDomainName               = $CurrentHostPoolOU.DomainName
        DomainCredentialsUsernameKeyVaultSecretUri  = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "AdJoinUserName").Id
        DomainCredentialsPasswordKeyVaultSecretUri  = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name "AdJoinPassword").Id
        CustomConfigurationScriptUrl                = $CurrentHostPool.CustomConfigurationScriptUrl
        #Debug = $true
    }
    $SessionHostConfiguration = New-AzWvdSessionHostConfiguration @Parameters
    #endregion

    #region SessionHostManagement
    $Parameters = @{
        HostPoolName              = $CurrentHostPool.Name
        ResourceGroupName         = $CurrentHostPool.ResourceGroupName
        ScheduledDateTimeZone     = $(Get-TimeZone)
        UpdateLogOffDelayMinute   = 5
        UpdateMaxVmsRemoved       = 1
        ProvisioningInstanceCount = $CurrentHostPool.VMNumberOfInstances
        UpdateDeleteOriginalVM    = $False
        UpdateLogOffMessage       = 'Update LogOff Message: You will be logged off in 5 minutes'
    }

    New-AzWvdSessionHostManagement @Parameters
    #endregion
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"

    return $CurrentAzWvdHostPool
}
#endregion

#region Main code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$SubscriptionId = (Get-AzContext).Subscription.Id
Do {
    $ADJoinCredential = Get-Credential -Message "AD Join Credential (UPN Form : samaccountname@domain.com)"
} While ($ADJoinCredential.UserName -notmatch "^(.+)@(.+)(\.)(.+)$")
$LocalAdminCredential = Get-Credential -Message "Local Admin Credential"

$Location = "eastus2"
$DomainName = "csa.fr"
$Parameters = @{
    LocalAdminCredential = $LocalAdminCredential 
    ADJoinCredential     = $ADJoinCredential 
    Location             = $Location 
    DomainName           = $DomainName
    SubNetId             = $("/subscriptions/{0}/resourceGroups/rg-avd-ad-use2-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-use2-002/subnets/snet-avd-avd-use2-002" -f $SubscriptionId)
    OUPath               = "OU=PooledDesktops,OU={0},OU=AVD,DC={1}" -f $Location, $($DomainName -replace "\.", ",DC=")
    Verbose              = $true
}
$PooledHostPool = New-AzAvdPooledHostPoolSessionHostConfigurationSetup @Parameters
#endregion