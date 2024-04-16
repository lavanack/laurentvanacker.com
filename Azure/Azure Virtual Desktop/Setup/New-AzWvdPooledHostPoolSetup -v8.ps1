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

##requires -Version 5 -Modules AzureAD, Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.ImageBuilder, Az.Insights, Az.ManagedServiceIdentity, Az.Monitor, Az.Network, Az.KeyVault, Az.OperationalInsights, Az.PrivateDns, Az.Resources, Az.Storage, PowerShellGet, ThreadJob -RunAsAdministrator 
#requires -Version 5 -RunAsAdministrator 
#requires -Modules @{ ModuleName="Az.Compute"; ModuleVersion="6.3.0" }

# Uninstall-Module Az.Compute -AllVersions -Force -Verbose
# Install-Module -Name Az.Compute -RequiredVersion 6.3.0.0 -Force -Verbose -AllowClobber

#It is recommended not locate FSLogix on same storage as MSIX packages in production environment, 
#To run from a Domain Controller

#region PowerShell HostPool classes
$ClassDefinitionScriptBlock = {
    enum IdentityProvider {
        ActiveDirectory
        MicrosoftEntraID
        #Hybrid
    }

    enum HostPoolType {
        Personal
        Pooled
    }

    Class HostPool {
        [ValidateNotNullOrEmpty()] [IdentityProvider] $IdentityProvider
        [ValidateNotNullOrEmpty()] [string] $Name
        [ValidateNotNullOrEmpty()] [HostPoolType] $Type
        [ValidateNotNullOrEmpty()] [string] $Location
        [ValidateLength(3, 11)] [string] $NamePrefix
        [ValidateRange(0, 10)] [int]    $VMNumberOfInstances
        [ValidateNotNullOrEmpty()] [Object] $KeyVault
        [boolean] $Spot
        [ValidateNotNullOrEmpty()] [string] $VMSize
        [string] $ImagePublisherName
        [string] $ImageOffer
        [string] $ImageSku
        [string] $VMSourceImageId 
        static [hashtable] $AzLocationShortNameHT = $null     
    
        hidden static BuildAzureLocationSortNameHashtable() {
            $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
            $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
            [HostPool]::AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
        }
    
        HostPool([Object] $KeyVault) {
            #Write-Host "Calling HostPool Constructor with KeyVault parameter ..."
            if ($null -eq [HostPool]::AzLocationShortNameHT) {
                [HostPool]::BuildAzureLocationSortNameHashtable()
            }
            $this.Location = "EastUS"
            $this.VMNumberOfInstances = 3
            $this.VMSize = "Standard_D2s_v5"
            $this.EnableSpotInstance()
            $this.KeyVault = $KeyVault
            $this.IdentityProvider = [IdentityProvider]::ActiveDirectory
        }


        [HostPool]SetVMNumberOfInstances([int] $VMNumberOfInstances) {
            $this.VMNumberOfInstances = $VMNumberOfInstances
            return $this
        }

        [HostPool]DisableSpotInstance() {
            $this.Spot = $false
            return $this
        }

        [HostPool]EnableSpotInstance() {
            $this.Spot = $true
            return $this
        }

        hidden RefreshNames() {
            #Overwritten in the child classes
        }

        [bool] IsMicrosoftEntraIdJoined() {
            return ($this.IdentityProvider -eq [IdentityProvider]::MicrosoftEntraID)
        }

        [bool] IsActiveDirectoryJoined() {
            return ($this.IdentityProvider -eq [IdentityProvider]::ActiveDirectory)
        }

        [HostPool] SetIdentityProvider([IdentityProvider] $IdentityProvider) {
            $this.IdentityProvider = $IdentityProvider
            $this.RefreshNames()
            return $this
        }

        [HostPool] SetVMSize([string] $VMSize) {
            if ($VMSize -in (Get-AzVMSize -Location $this.Location).Name) {
                $this.VMSize = $VMSize
            }
            else {
                Write-Warning "The specified '$VMSize' is not available in the '$($this.Location)' Azure region. We keep the previously set VMSize: '$($this.VMSize)' ..."
            }
            return $this
        }

        [HostPool] SetLocation([string] $Location) {
            if ([HostPool]::AzLocationShortNameHT.ContainsKey($Location)) {
                if ($this.VMSize -in (Get-AzVMSize -Location $Location).Name) {
                    $this.Location = $Location
                    $this.RefreshNames()
                }
                else {
                    Write-Warning "The specified '$($Location)' Azure region doesn't allow the '$($this.VMSize)'. We keep the previously set location: '$($this.Location)' ..."
                }
            }
            else {
                Write-Warning -Message "Unknown Azure Location: '$($Location)'. We keep the previously set location: '$($this.Location)'"
            }
            return $this
        }

        [HostPool] SetName([string] $Name, [string] $NamePrefix) {
            $this.Name = $Name
            $this.NamePrefix = $NamePrefix
            return $this
        }

        [HostPool] SetImage([string] $ImagePublisherName, [string] $ImageOffer, [string] $ImageSku ) {
            $this.ImagePublisherName = $ImagePublisherName
            $this.ImageOffer = $ImageOffer
            $this.ImageSku = $ImageSku
            $this.RefreshNames()
            return $this
        }

        [HostPool] SetVMSourceImageId([string] $VMSourceImageId) {
            $this.VMSourceImageId = $VMSourceImageId
            $this.RefreshNames()
            return $this
        }

    }

    class PooledHostPool : HostPool {
        hidden [ValidateRange(0, 99)] static [int] $Index = 0
        [ValidateRange(0, 10)] [int] $MaxSessionLimit
        [ValidateNotNullOrEmpty()] [boolean] $FSlogix
        [ValidateNotNullOrEmpty()] [boolean] $MSIX

        PooledHostPool([Object] $KeyVault):base($KeyVault) {
            [PooledHostPool]::Index++
            $this.Type = [HostPoolType]::Pooled
            $this.MaxSessionLimit = 5
            $this.ImagePublisherName = "microsoftwindowsdesktop"
            $this.ImageOffer = "office-365"
            $this.ImageSku = "win11-23h2-avd-m365"
            $this.FSlogix = $true
            $this.MSIX = $true
            $this.RefreshNames()
        }

        static ResetIndex() {
            [PooledHostPool]::Index = 0
        }

        [PooledHostPool] SetIndex([int] $Index) {
            [PooledHostPool]::Index = $Index
            $this.RefreshNames()        
            return $this
        }

        [PooledHostPool] SetMaxSessionLimit([int] $MaxSessionLimit) {
            $this.MaxSessionLimit = $MaxSessionLimit
            return $this
        }

        [PooledHostPool]DisableFSLogix() {
            $this.FSLogix = $false
            return $this
        }

        [PooledHostPool]EnableFSLogix() {
            $this.FSLogix = $true
            return $this
        }

        [PooledHostPool]DisableMSIX() {
            $this.MSIX = $false
            return $this
        }

        [PooledHostPool]EnableMSIX() {
            if (-not($this.IsMicrosoftEntraIdJoined())) {
                $this.MSIX = $true
            }
            return $this
        }

        [PooledHostPool] SetIdentityProvider([IdentityProvider] $IdentityProvider) {
            $this.IdentityProvider = $IdentityProvider
            if ($this.IsMicrosoftEntraIdJoined()) {
                #No MSIX with EntraID: https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
                $this.MSIX = $false
            }
            $this.RefreshNames()
            return $this
        }

        hidden RefreshNames() {
            $TempName = "hp-np"
            $TempNamePrefix = "n"

            if ($this.IsMicrosoftEntraIdJoined()) {
                $TempName += "-ei"
                $TempNamePrefix += "e"
            }
            else {
                $TempName += "-ad"
                $TempNamePrefix += "a"
            }
        
            $TempName += "-poc"
            $TempNamePrefix += "pc"

            if ($this.VMSourceImageId) {
                $TempName += "-cg"
                $TempNamePrefix += "c"
            }
            else {
                $TempName += "-mp"
                $TempNamePrefix += "m"
            }

            $this.Name = "{0}-{1}-{2:D2}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D2}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
        }
    }

    class PersonalHostPool : HostPool {
        hidden [ValidateRange(0, 99)] static [int] $Index = 0
        #Hibernation is not compatible with Spot Instance and is only allowed for Personal Dektop
        [ValidateNotNullOrEmpty()] [boolean] $HibernationEnabled = $false

        PersonalHostPool([Object] $KeyVault):base($KeyVault) {
            [PersonalHostPool]::Index++
            $this.Type = [HostPoolType]::Personal
            $this.ImagePublisherName = "microsoftwindowsdesktop"
            $this.ImageOffer = "windows-11"
            $this.ImageSku = "win11-23h2-ent"
            $this.HibernationEnabled = $false
            $this.RefreshNames()
        }

        static ResetIndex() {
            [PersonalHostPool]::Index = 0
        }

        [PersonalHostPool] SetIndex([int] $Index) {
            [PersonalHostPool]::Index = $Index
            $this.RefreshNames()        
            return $this
        }

        [PersonalHostPool]DisableHibernation() {
            $this.HibernationEnabled = $false
            return $this
        }

        [PersonalHostPool]EnableHibernation() {
            $this.HibernationEnabled = $true
            #$this.Spot = $false
            $this.DisableSpotInstance()
            return $this
        }

        hidden RefreshNames() {
            $TempName = "hp-pd"
            $TempNamePrefix = "p"

            if ($this.IsMicrosoftEntraIdJoined()) {
                $TempName += "-ei"
                $TempNamePrefix += "e"
            }
            else {
                $TempName += "-ad"
                $TempNamePrefix += "a"
            }
        
            $TempName += "-poc"
            $TempNamePrefix += "pc"

            if ($this.VMSourceImageId) {
                $TempName += "-cg"
                $TempNamePrefix += "c"
            }
            else {
                $TempName += "-mp"
                $TempNamePrefix += "m"
            }

            $this.Name = "{0}-{1}-{2:D2}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D2}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
        }
    }
}
#endregion

#region Function definitions
#From https://stackoverflow.com/questions/63529599/how-to-grant-admin-consent-to-an-azure-aad-app-in-powershell
function Set-AdminConsent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$applicationId,
        # The Azure Context]
        [Parameter(Mandatory)]
        [object]$context
    )

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")
    $headers = @{
        'Authorization'          = 'Bearer ' + $token.AccessToken
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$applicationId/Consent?onBehalfOfAll=true"
    Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
}

function Test-AzAvdStorageAccountNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [HostPool[]]$HostPools
    )
    $result = $true
    foreach ($CurrentHostPool in $HostPools) {
        if ($CurrentHostPool.MSIX) {
            $CurrentHostPoolStorageAccountName = "fsl{0}" -f $($CurrentHostPool.Name -replace "\W")
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available ..."
                $result = $false
            }
            else {
                Write-Verbose -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is available ..."
            }
        }
        if ($CurrentHostPool.FSLogix) {
            $CurrentHostPoolStorageAccountName = "msix{0}" -f $($CurrentHostPool.Name -replace "\W")
            if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                Write-Error -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is NOT available ..."
                $result = $false
            }
            else {
                Write-Verbose -Message "The '$CurrentHostPoolStorageAccountName' Storage Account Name is available ..."
            }
        }
    }
    return $result
}

function New-AzHostPoolSessionCredentialKeyVault {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $false)]
        [string] $Location = "EastUs",
        [Parameter(Mandatory = $false)]
        [PSCredential] $LocalAdminCredential
    )
    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion
    
    $Index = 0
    Do {
        $Index++
        $KeyVaultName = "kvavdhpcred{0}{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index
        $KeyVaultName = $KeyVaultName.ToLower()
        if ($Index -gt 999) {
            Write-Error "No name available for HostPool Credential Keyvault ..." -ErrorAction Stop
        }
    } While (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    $ResourceGroupName = "rg-avd-kv-poc-{0}-{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    #Create an Azure Key Vault
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroup $ResourceGroupName -Location $location -EnabledForDeployment -EnabledForTemplateDeployment -SoftDeleteRetentionInDays 7 #-EnablePurgeProtection
    #As the owner of the key vault, you automatically have access to create secrets. If you need to let another user create secrets, use:
    #$AccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $UserPrincipalName -PermissionsToSecrets Get,Delete,List,Set -PassThru

    #region Defining local admin credential(s)
    if ($LocalAdminCredential) {
        $SecureUserName = $(ConvertTo-SecureString -String $LocalAdminCredential.UserName -AsPlainText -Force) 
        $SecurePassword = $LocalAdminCredential.Password
    }
    else {
        $SecureUserName = $(ConvertTo-SecureString -String "localadmin" -AsPlainText -Force) 
        $SecurePassword = New-RandomPassword -AsSecureString -ClipBoard
    }
    $SecretUserName = "LocalAdminUserName"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretUserName' ..."
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $SecureUserName -Verbose

    $SecretPassword = "LocalAdminPassword"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretPassword' ..."
    #$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
    #$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
    #Randomly generated password
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword -Verbose
    #endregion

    #region Defining local admin credential(s)
    $SecretUserName = "ADJoinUserName"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretUserName' ..."
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretUserName -SecretValue $(ConvertTo-SecureString -String "adjoin" -AsPlainText -Force)  -Verbose

    $SecretPassword = "ADJoinPassword"
    Write-Verbose -Message "Creating a secret in $KeyVaultName called '$SecretPassword' ..."
    $ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
    $SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
    #Randomly generated password
    #$SecurePassword = New-RandomPassword -AsSecureString -ClipBoard
    $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretPassword -SecretValue $SecurePassword -Verbose
    #endregion

    $ThisDomainController = Get-AzVMCompute | Get-AzVM
    # Get the VM's network interface
    $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
    $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
    # Get the subnet ID
    $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
    $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
    $split = $ThisDomainControllerSubnetId.split('/')
    # Get the vnet ID
    $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
    $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork
    
    #region Private endpoint for Key Vault Setup
    #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
    #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
    ## Create the private endpoint connection. ## 
    $PrivateEndpointName = "pep{0}" -f $($KeyVaultName -replace "\W")
    $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $KeyVault.ResourceId).GroupId
    $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $KeyVault.ResourceId -GroupId $GroupId
    Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$KeyVaultName' (in the '$ResourceGroupName' Resource Group) ..."
    $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

    ## Create the private DNS zone. ##
    $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
    $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
    if ($null -eq $PrivateDnsZone) {
        Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$KeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
        $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
    }

    $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
    $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
    if ($null -eq $PrivateDnsVirtualNetworkLink) {
        $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
        ## Create a DNS network link. ##
        Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$KeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
        $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
    }

    ## Configure the DNS zone. ##
    Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$KeyVaultName' ..."
    $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

    ## Create the DNS zone group. ##
    Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$ResourceGroupName' Resource Group) ..."
    $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

    #Key Vault - Disabling Public Access
    Write-Verbose -Message "Disabling the Public Access for the Key Vault'$KeyVaultName' (in the '$ResourceGroupName' Resource Group) ..."
    $null = Update-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -PublicNetworkAccess "Disabled" 
    #endregion

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Key Vault Setup Processing Time: $($TimeSpan.ToString())"

    return $KeyVault
}

#Based from https://adamtheautomator.com/powershell-random-password/
function New-RandomPassword {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [int] $minLength = 12, ## characters
        [int] $maxLength = 15, ## characters
        [int] $nonAlphaChars = 3,
        [switch] $AsSecureString,
        [switch] $ClipBoard
    )

    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    $RandomPassword = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    Write-Host "The password is : $RandomPassword"
    if ($ClipBoard) {
        Write-Verbose "The password has beeen copied into the clipboard (Use Win+V) ..."
        $RandomPassword | Set-Clipboard
    }
    if ($AsSecureString) {
        ConvertTo-SecureString -String $RandomPassword -AsPlainText -Force
    }
    else {
        $RandomPassword
    }
}

#Was coded as an alterative to Test-AzKeyVaultNameAvailability (for testing purpose - no more used in this script)
function Get-AzKeyVaultNameAvailability {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [string]$VaultName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "name" = $VaultName
        "type" = "Microsoft.KeyVault/vaults"
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
    }
    return $Response
}

#Was coded as an alterative to Expand-AzWvdMsixImage (for testing purpose - no more used in this script)
function Expand-AzAvdMsixImage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$HostPoolName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateScript({ $_ -match "^\\\\.*\.vhdx?$" })]
        [string]$Uri
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion
    $Body = [ordered]@{ 
        "uri" = $Uri
    }

    $expandMsixImageURI = "https://management.azure.com/subscriptions/$SubcriptionID/resourcegroups/$ResourceGroupName/providers/Microsoft.DesktopVirtualization/hostpools/$HostPoolName/expandMsixImage?api-version=2022-02-10-preview"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $expandMsixImageURI -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        if (-not([string]::IsNullOrEmpty($Response.message))) {
            Write-Warning -Message $Response.message
        }
    }
    finally {
    }
    return $Response
}

function Grant-ADJoinPermission {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('OU')]
        [string]$OrganizationalUnit
    )
    # Import the Active Directory module
    Import-Module ActiveDirectory

    $ComputerGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
    $ObjectTypeGUIDs = @{
        'Domain-Administer-Server'                      = 'ab721a52-1e2f-11d0-9819-00aa0040529b'
        'User-Change-Password'                          = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
        'User-Force-Change-Password'                    = '00299570-246d-11d0-a768-00aa006e0529'
        'Send-As'                                       = 'ab721a54-1e2f-11d0-9819-00aa0040529b'
        'Receive-As'                                    = 'ab721a56-1e2f-11d0-9819-00aa0040529b'
        'Send-To'                                       = 'ab721a55-1e2f-11d0-9819-00aa0040529b'
        'Domain-Password'                               = 'c7407360-20bf-11d0-a768-00aa006e0529'
        'General-Information'                           = '59ba2f42-79a2-11d0-9020-00c04fc2d3cf'
        'User-Account-Restrictions'                     = '4c164200-20c0-11d0-a768-00aa006e0529'
        'User-Logon'                                    = '5f202010-79a5-11d0-9020-00c04fc2d4cf'
        'Membership'                                    = 'bc0ac240-79a9-11d0-9020-00c04fc2d4cf'
        'Open-Address-Book'                             = 'a1990816-4298-11d1-ade2-00c04fd8d5cd'
        'Personal-Information'                          = '77B5B886-944A-11d1-AEBD-0000F80367C1'
        'Email-Information'                             = 'E45795B2-9455-11d1-AEBD-0000F80367C1'
        'Web-Information'                               = 'E45795B3-9455-11d1-AEBD-0000F80367C1'
        'DS-Replication-Get-Changes'                    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Synchronize'                    = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Manage-Topology'                = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
        'Change-Schema-Master'                          = 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd'
        'Change-Rid-Master'                             = 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd'
        'Do-Garbage-Collection'                         = 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd'
        'Recalculate-Hierarchy'                         = '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd'
        'Allocate-Rids'                                 = '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd'
        'Change-PDC'                                    = 'bae50096-4752-11d1-9052-00c04fc2d4cf'
        'Add-GUID'                                      = '440820ad-65b4-11d1-a3da-0000f875ae0d'
        'Change-Domain-Master'                          = '014bf69c-7b3b-11d1-85f6-08002be74fab'
        'Public-Information'                            = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
        'msmq-Receive-Dead-Letter'                      = '4b6e08c0-df3c-11d1-9c86-006008764d0e'
        'msmq-Peek-Dead-Letter'                         = '4b6e08c1-df3c-11d1-9c86-006008764d0e'
        'msmq-Receive-computer-Journal'                 = '4b6e08c2-df3c-11d1-9c86-006008764d0e'
        'msmq-Peek-computer-Journal'                    = '4b6e08c3-df3c-11d1-9c86-006008764d0e'
        'msmq-Receive'                                  = '06bd3200-df3e-11d1-9c86-006008764d0e'
        'msmq-Peek'                                     = '06bd3201-df3e-11d1-9c86-006008764d0e'
        'msmq-Send'                                     = '06bd3202-df3e-11d1-9c86-006008764d0e'
        'msmq-Receive-journal'                          = '06bd3203-df3e-11d1-9c86-006008764d0e'
        'msmq-Open-Connector'                           = 'b4e60130-df3f-11d1-9c86-006008764d0e'
        'Apply-Group-Policy'                            = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
        'RAS-Information'                               = '037088f8-0ae1-11d2-b422-00a0c968f939'
        'DS-Install-Replica'                            = '9923a32a-3607-11d2-b9be-0000f87a36b2'
        'Change-Infrastructure-Master'                  = 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd'
        'Update-Schema-Cache'                           = 'be2bb760-7f46-11d2-b9ad-00c04f79f805'
        'Recalculate-Security-Inheritance'              = '62dd28a8-7f46-11d2-b9ad-00c04f79f805'
        'DS-Check-Stale-Phantoms'                       = '69ae6200-7f46-11d2-b9ad-00c04f79f805'
        'Certificate-Enrollment'                        = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        'Self-Membership'                               = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        'Validated-DNS-Host-Name'                       = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
        'Validated-SPN'                                 = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        'Generate-RSoP-Planning'                        = 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7'
        'Refresh-Group-Cache'                           = '9432c620-033c-4db7-8b58-14ef6d0bf477'
        'SAM-Enumerate-Entire-Domain'                   = '91d67418-0135-4acc-8d79-c08e857cfbec'
        'Generate-RSoP-Logging'                         = 'b7b1b3de-ab09-4242-9e30-9980e5d322f7'
        'Domain-Other-Parameters'                       = 'b8119fd0-04f6-4762-ab7a-4986c76b3f9a'
        'DNS-Host-Name-Attributes'                      = '72e39547-7b18-11d1-adef-00c04fd8d5cd'
        'Create-Inbound-Forest-Trust'                   = 'e2a36dc9-ae17-47c3-b58b-be34c55ba633'
        'DS-Replication-Get-Changes-All'                = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        'Migrate-SID-History'                           = 'BA33815A-4F93-4c76-87F3-57574BFF8109'
        'Reanimate-Tombstones'                          = '45EC5156-DB7E-47bb-B53F-DBEB2D03C40F'
        'Allowed-To-Authenticate'                       = '68B1D179-0D15-4d4f-AB71-46152E79A7BC'
        'DS-Execute-Intentions-Script'                  = '2f16c4a5-b98e-432c-952a-cb388ba33f2e'
        'DS-Replication-Monitor-Topology'               = 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96'
        'Update-Password-Not-Required-Bit'              = '280f369c-67c7-438e-ae98-1d46f3c6f541'
        'Unexpire-Password'                             = 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501'
        'Enable-Per-User-Reversibly-Encrypted-Password' = '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5'
        'DS-Query-Self-Quota'                           = '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc'
        'Private-Information'                           = '91e647de-d96f-4b70-9557-d63ff4f3ccd8'
        'Read-Only-Replication-Secret-Synchronization'  = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
        'MS-TS-GatewayAccess'                           = 'ffa6f046-ca4b-4feb-b40d-04dfee722543'
        'Terminal-Server-License-Server'                = '5805bc62-bdc9-4428-a5e2-856a0f4c185e'
        'Reload-SSL-Certificate'                        = '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8'
        'DS-Replication-Get-Changes-In-Filtered-Set'    = '89e95b76-444d-4c62-991a-0facbeda640c'
        'Run-Protect-Admin-Groups-Task'                 = '7726b9d5-a4b4-4288-a6b2-dce952e80a7f'
        'Manage-Optional-Features'                      = '7c0e2a7c-a419-48e4-a995-10180aad54dd'
        'DS-Clone-Domain-Controller'                    = '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e'
        'Validated-MS-DS-Behavior-Version'              = 'd31a8757-2447-4545-8081-3bb610cacbf2'
        'Validated-MS-DS-Additional-DNS-Host-Name'      = '80863791-dbe9-4eb8-837e-7f0ab55d9ac7'
        'Certificate-AutoEnrollment'                    = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        'DS-Set-Owner'                                  = '4125c71f-7fac-4ff0-bcb7-f09a41325286'
        'DS-Bypass-Quota'                               = '88a9933e-e5c8-4f2a-9dd7-2527416b8092'
        'DS-Read-Partition-Secrets'                     = '084c93a2-620d-4879-a836-f0ae47de0e89'
        'DS-Write-Partition-Secrets'                    = '94825A8D-B171-4116-8146-1E34D8F54401'
        'DS-Validated-Write-Computer'                   = '9b026da6-0d3c-465c-8bee-5199d7165cba'
    }
    $ADRights = @(
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType"            = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType"   = "00000000-0000-0000-0000-000000000000"
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::ReadControl -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = "00000000-0000-0000-0000-000000000000"
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            "ObjectType"            = $ComputerGUID
            "InheritedObjectType"   = "00000000-0000-0000-0000-000000000000"
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'Validated-SPN'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::Self
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'DNS-Host-Name-Attributes'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'User-Force-Change-Password'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
        @{
            "ActiveDirectoryRights" = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            "InheritanceType"       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
            "ObjectType"            = $ObjectTypeGUIDs.'User-Change-Password'
            "InheritedObjectType"   = $ComputerGUID
            "AccessControlType"     = [System.Security.AccessControl.AccessControlType]::Allow
        }
    )
    $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($Credential.UserName)'"
    #If the user doesn't exist, we create it
    if (-not($ADUser)) {
        Write-Verbose -Message "Creating '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
        $DomainName = (Get-ADDomain).DNSRoot
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
        $ADUser = New-ADUser -Name $Credential.UserName -AccountPassword $Credential.Password -PasswordNeverExpires $true -Enabled $true -Description "Created by PowerShell Script for ADDS-joined AVD Session Hosts" -UserPrincipalName $("{0}@{1}" -f $Credential.UserName, $DomainName) -PassThru
    }

    # Define the security SamAccountName (user or group) to which you want to grant the permission
    $IdentityReference = [System.Security.Principal.IdentityReference] $ADUser.SID
    $Permission = Get-Acl "AD:$OrganizationalUnit"

    Write-Verbose -Message "Applying required privileges to '$($Credential.UserName)' AD User (for adding Azure VM to ADDS)"
    foreach ($CurrentADRight in $ADRights) {
        $AccessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($IdentityReference, $CurrentADRight.ActiveDirectoryRights, $CurrentADRight.AccessControlType, $CurrentADRight.ObjectType, $CurrentADRight.InheritanceType, $CurrentADRight.InheritedObjectType)
        $Permission.AddAccessRule($AccessRule)
    }

    # Apply the permission recursively to the OU and its descendants
    Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OrganizationalUnit'" -SearchBase $OrganizationalUnit -SearchScope Subtree | ForEach-Object {
        Write-Verbose -Message "Applying those required privileges to '$_'"
        Set-Acl "AD:$_" $Permission
    }

    Write-Verbose -Message "Permissions granted successfully."
}

#From https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
function New-AzureComputeGallery {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Location = "EastUS",
        [Parameter(Mandatory = $false)]
        [string[]]$targetRegions = @($Location, "EastUS2"),
        [Parameter(Mandatory = $false)]
        [int]$ReplicaCount = 1
    )

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Set up the environment and variables
    # get existing context
    $AzContext = Get-AzContext
    # Your subscription. This command gets your current subscription
    $subscriptionID = $AzContext.Subscription.Id

    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $AzureComputeGalleryPrefix = "acg"
    $ResourceGroupPrefix = "rg"

    # Location (see possible locations in the main docs)
    Write-Verbose -Message "`$Location: $Location"
    $LocationShortName = $AzLocationShortNameHT[$Location].shortName
    Write-Verbose -Message "`$LocationShortName: $LocationShortName"
    if ($Location -notin $targetRegions) {
        $targetRegions += $Location
    }
    Write-Verbose -Message "`$targetRegions: $($targetRegions -join ', ')"
    [array] $targetRegionSettings = foreach ($CurrentTargetRegion in $targetRegions) {
        @{"name" = $CurrentTargetRegion; "replicaCount" = $ReplicaCount; "storageAccountType" = "Premium_LRS" }
    }

    $Project = "avd"
    $Role = "aib"
    #Timestamp
    $timeInt = (Get-Date $([datetime]::UtcNow) -UFormat "%s").Split(".")[0]
    $ResourceGroupName = "{0}-{1}-{2}-{3}-{4}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $TimeInt 
    $ResourceGroupName = $ResourceGroupName.ToLower()
    Write-Verbose -Message "`$ResourceGroupName: $ResourceGroupName"


    # Image template and definition names
    #AVD MultiSession Session Image Market Place Image + customizations: VSCode
    $imageDefName01 = "win11-23h2-ent-avd-custom-vscode"
    $imageTemplateName01 = $imageDefName01 + "-template-" + $timeInt
    #AVD MultiSession + Microsoft 365 Market Place Image + customizations: VSCode
    $imageDefName02 = "win11-23h2-ent-avd-m365-vscode"
    $imageTemplateName02 = $imageDefName02 + "-template-" + $timeInt
    Write-Verbose -Message "`$imageDefName01: $imageDefName01"
    Write-Verbose -Message "`$imageTemplateName01: $imageTemplateName01"
    Write-Verbose -Message "`$imageDefName02: $imageDefName02"
    Write-Verbose -Message "`$imageTemplateName02: $imageTemplateName02"

    # Distribution properties object name (runOutput). Gives you the properties of the managed image on completion
    $runOutputName01 = "cgOutput01"
    $runOutputName02 = "cgOutput02"

    #$Version = "1.0.0"
    $Version = Get-Date -UFormat "%Y.%m.%d"
    $Jobs = @()
    #endregion

    # Create resource group
    if (Get-AzResourceGroup -Name $ResourceGroupName -Location $location -ErrorAction Ignore) {
        Write-Verbose -Message "Removing '$ResourceGroupName' Resource Group Name ..."
        Remove-AzResourceGroup -Name $ResourceGroupName -Force
    }
    Write-Verbose -Message "Creating '$ResourceGroupName' Resource Group Name ..."
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $location -Force

    #region Permissions, user identity, and role
    # setup role def names, these need to be unique
    $imageRoleDefName = "Azure Image Builder Image Def - $timeInt"
    $identityName = "aibIdentity-$timeInt"
    Write-Verbose -Message "`$imageRoleDefName: $imageRoleDefName"
    Write-Verbose -Message "`$identityName: $identityName"


    # Create the identity
    Write-Verbose -Message "Creating User Assigned Identity '$identityName' ..."
    $AssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName -Location $location

    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/PeterR-msft/M365AVDWS/master/Azure%20Image%20Builder/aibRoleImageCreation.json"
    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/12_Creating_AIB_Security_Roles/aibRoleImageCreation.json"
    #$aibRoleImageCreationUrl="https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
    $aibRoleImageCreationUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/aibRoleImageCreation.json"
    #$aibRoleImageCreationPath = "aibRoleImageCreation.json"
    $aibRoleImageCreationPath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $aibRoleImageCreationUrl -Leaf)
    #Generate a unique file name 
    $aibRoleImageCreationPath = $aibRoleImageCreationPath -replace ".json$", "_$timeInt.json"
    Write-Verbose -Message "`$aibRoleImageCreationPath: $aibRoleImageCreationPath"

    # Download the config
    Invoke-WebRequest -Uri $aibRoleImageCreationUrl -OutFile $aibRoleImageCreationPath -UseBasicParsing

    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $aibRoleImageCreationPath
    ((Get-Content -path $aibRoleImageCreationPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $aibRoleImageCreationPath

    # Create a role definition
    Write-Verbose -Message "Creating '$imageRoleDefName' Role Definition ..."
    $RoleDefinition = New-AzRoleDefinition -InputFile $aibRoleImageCreationPath

    # Grant the role definition to the VM Image Builder service principal
    Write-Verbose -Message "Assigning '$($RoleDefinition.Name)' Role to '$($AssignedIdentity.Name)' ..."
    Do {
        Write-Verbose -Message "Sleeping 10 seconds ..."
        Start-Sleep -Seconds 10
        $RoleAssignment = New-AzRoleAssignment -ObjectId $AssignedIdentity.PrincipalId -RoleDefinitionName $RoleDefinition.Name -Scope $ResourceGroup.ResourceId -ErrorAction Ignore #-Debug
    } While ($null -eq $RoleAssignment)
  
    #endregion

    #region Create an Azure Compute Gallery
    $GalleryName = "{0}_{1}_{2}_{3}" -f $AzureComputeGalleryPrefix, $Project, $LocationShortName, $timeInt
    Write-Verbose -Message "`$GalleryName: $GalleryName"

    # Create the gallery
    Write-Verbose -Message "Creating Azure Compute Gallery '$GalleryName' ..."
    $Gallery = New-AzGallery -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location
    #endregion

    #region Template #1 via a customized JSON file
    #Based on https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
    # Create the gallery definition
    Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName01' (From Customized JSON)..."
    $GalleryImageDefinition01 = New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $ResourceGroupName -Location $location -Name $imageDefName01 -OsState generalized -OsType Windows -Publisher 'Contoso' -Offer 'Windows' -Sku 'avd-win11-custom' -HyperVGeneration V2

    #region Download and configure the template
    #$templateUrl="https://raw.githubusercontent.com/azure/azvmimagebuilder/main/solutions/14_Building_Images_WVD/armTemplateWVD.json"
    #$templateFilePath = "armTemplateWVD.json"
    $templateUrl = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/armTemplateAVD.json"
    $templateFilePath = Join-Path -Path $CurrentDir -ChildPath $(Split-Path $templateUrl -Leaf)
    #Generate a unique file name 
    $templateFilePath = $templateFilePath -replace ".json$", "_$timeInt.json"
    Write-Verbose -Message "`$templateFilePath: $templateFilePath  ..."

    Invoke-WebRequest -Uri $templateUrl -OutFile $templateFilePath -UseBasicParsing

    ((Get-Content -path $templateFilePath -Raw) -replace '<subscriptionID>', $subscriptionID) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<rgName>', $ResourceGroupName) | Set-Content -Path $templateFilePath
    #((Get-Content -path $templateFilePath -Raw) -replace '<region>',$location) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<runOutputName>', $runOutputName01) | Set-Content -Path $templateFilePath

    ((Get-Content -path $templateFilePath -Raw) -replace '<imageDefName>', $imageDefName01) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<sharedImageGalName>', $GalleryName) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<targetRegions>', $($targetRegionSettings | ConvertTo-Json)) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<imgBuilderId>', $AssignedIdentity.Id) | Set-Content -Path $templateFilePath
    ((Get-Content -path $templateFilePath -Raw) -replace '<version>', $version) | Set-Content -Path $templateFilePath
    #endregion

    #region Submit the template
    Write-Verbose -Message "Starting Resource Group Deployment from '$templateFilePath' ..."
    $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFilePath -TemplateParameterObject @{"api-Version" = "2022-07-01"; "imageTemplateName" = $imageTemplateName01; "svclocation" = $location }

    #region Build the image
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName01' (As Job) ..."
    $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01 -AsJob
    #endregion
    #endregion
    #endregion

    #region Template #2 via a image from the market place + customizations
    # create gallery definition
    $GalleryParams = @{
        GalleryName       = $GalleryName
        ResourceGroupName = $ResourceGroupName
        Location          = $location
        Name              = $imageDefName02
        OsState           = 'generalized'
        OsType            = 'Windows'
        Publisher         = 'Contoso'
        Offer             = 'Windows'
        Sku               = 'avd-win11-m365'
        HyperVGeneration  = 'V2'
    }
    Write-Verbose -Message "Creating Azure Compute Gallery Image Definition '$imageDefName02' (From A Market Place Image)..."
    $GalleryImageDefinition02 = New-AzGalleryImageDefinition @GalleryParams

    $SrcObjParams = @{
        PlatformImageSource = $true
        Publisher           = 'MicrosoftWindowsDesktop'
        Offer               = 'Office-365'    
        Sku                 = 'win11-23h2-avd-m365'  
        Version             = 'latest'
    }
    Write-Verbose -Message "Creating Azure Image Builder Template Source Object  ..."
    $srcPlatform = New-AzImageBuilderTemplateSourceObject @SrcObjParams

    $disObjParams = @{
        SharedImageDistributor = $true
        GalleryImageId         = "$($GalleryImageDefinition02.Id)/versions/$version"
        ArtifactTag            = @{source = 'avd-win11'; baseosimg = 'windows11' }

        # 1. Uncomment following line for a single region deployment.
        #ReplicationRegion = $location

        # 2. Uncomment following line if the custom image should be replicated to another region(s).
        TargetRegion           = $targetRegionSettings

        RunOutputName          = $runOutputName02
        ExcludeFromLatest      = $false
    }
    Write-Verbose -Message "Creating Azure Image Builder Template Distributor Object  ..."
    $disSharedImg = New-AzImageBuilderTemplateDistributorObject @disObjParams

    $ImgTimeZoneRedirectionPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Timezone Redirection'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgTimeZoneRedirectionPowerShellCustomizerParams.Name)' ..."
    $TimeZoneRedirectionCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgTimeZoneRedirectionPowerShellCustomizerParams 

    $ImgVSCodePowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Install Visual Studio Code'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Azure%20Image%20Builder/Install-VSCode.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgVSCodePowerShellCustomizerParams.Name)' ..."
    $VSCodeCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgVSCodePowerShellCustomizerParams 

    Write-Verbose -Message "Creating Azure Image Builder Template WindowsUpdate Customizer Object ..."
    $WindowsUpdateCustomizer = New-AzImageBuilderTemplateCustomizerObject -WindowsUpdateCustomizer -Name 'WindowsUpdate' -Filter @('exclude:$_.Title -like ''*Preview*''', 'include:$true') -SearchCriterion "IsInstalled=0" -UpdateLimit 40

    $ImgDisableAutoUpdatesPowerShellCustomizerParams = @{  
        PowerShellCustomizer = $true  
        Name                 = 'Disable AutoUpdates'  
        RunElevated          = $true  
        runAsSystem          = $true  
        ScriptUri            = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2023-07-31/TimezoneRedirection.ps1'
    }

    Write-Verbose -Message "Creating Azure Image Builder Template PowerShell Customizer Object for '$($ImgDisableAutoUpdatesPowerShellCustomizerParams.Name)' ..."
    $DisableAutoUpdatesCustomizer = New-AzImageBuilderTemplateCustomizerObject @ImgDisableAutoUpdatesPowerShellCustomizerParams 

    #Create an Azure Image Builder template and submit the image configuration to the Azure VM Image Builder service:
    $Customize = $TimeZoneRedirectionCustomizer, $VSCodeCustomizer, $WindowsUpdateCustomizer, $DisableAutoUpdatesCustomizer
    $ImgTemplateParams = @{
        ImageTemplateName      = $imageTemplateName02
        ResourceGroupName      = $ResourceGroupName
        Source                 = $srcPlatform
        Distribute             = $disSharedImg
        Customize              = $Customize
        Location               = $location
        UserAssignedIdentityId = $AssignedIdentity.Id
        VMProfileVmsize        = "Standard_D4s_v5"
        VMProfileOsdiskSizeGb  = 127
    }
    Write-Verbose -Message "Creating Azure Image Builder Template from '$imageTemplateName02' Image Template Name ..."
    $ImageBuilderTemplate = New-AzImageBuilderTemplate @ImgTemplateParams

    #region Build the image
    #Start the image building process using Start-AzImageBuilderTemplate cmdlet:
    Write-Verbose -Message "Starting Image Builder Template from '$imageTemplateName02' (As Job) ..."
    $Jobs += Start-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02 -AsJob
    #endregion

    Write-Verbose -Message "Waiting for jobs to complete ..."
    $Jobs | Wait-Job | Out-Null

    #region imageTemplateName01 status 
    #To determine whenever or not the template upload process was successful, run the following command.
    $getStatus01 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName01
    # Optional - if you have any errors running the preceding command, run:
    Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorCode: $($getStatus01.ProvisioningErrorCode) "
    Write-Verbose -Message "'$imageTemplateName01' ProvisioningErrorMessage: $($getStatus01.ProvisioningErrorMessage) "
    # Shows the status of the build
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunState: $($getStatus01.LastRunStatusRunState) "
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusMessage: $($getStatus01.LastRunStatusMessage) "
    Write-Verbose -Message "'$imageTemplateName01' LastRunStatusRunSubState: $($getStatus01.LastRunStatusRunSubState) "
    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName01' ..."
    #$Jobs += $getStatus01 | Remove-AzImageBuilderTemplate -AsJob
    $getStatus01 | Remove-AzImageBuilderTemplate -NoWait
    Write-Verbose -Message "Removing '$aibRoleImageCreationPath' ..."
    Write-Verbose -Message "Removing '$templateFilePath' ..."
    Remove-Item -Path $aibRoleImageCreationPath, $templateFilePath -Force
    #endregion

    #region imageTemplateName02 status
    #To determine whenever or not the template upload process was successful, run the following command.
    $getStatus02 = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $imageTemplateName02
    # Optional - if you have any errors running the preceding command, run:
    Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorCode: $($getStatus02.ProvisioningErrorCode) "
    Write-Verbose -Message "'$imageTemplateName02' ProvisioningErrorMessage: $($getStatus02.ProvisioningErrorMessage) "
    # Shows the status of the build
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunState: $($getStatus02.LastRunStatusRunState) "
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusMessage: $($getStatus02.LastRunStatusMessage) "
    Write-Verbose -Message "'$imageTemplateName02' LastRunStatusRunSubState: $($getStatus02.LastRunStatusRunSubState) "
    #endregion

    Write-Verbose -Message "Removing Azure Image Builder Template for '$imageTemplateName02' ..."
    #$Jobs += $getStatus02 | Remove-AzImageBuilderTemplate -AsJob
    $getStatus02 | Remove-AzImageBuilderTemplate -NoWait
    #endregion

    #Adding a delete lock (for preventing accidental deletion)
    #New-AzResourceLock -LockLevel CanNotDelete -LockNotes "$ResourceGroupName - CanNotDelete" -LockName "$ResourceGroupName - CanNotDelete" -ResourceGroupName $ResourceGroupName -Force
    #region Clean up your resources
    <#
    ## Remove the Resource Group
    Remove-AzResourceGroup $ResourceGroupName -Force -AsJob
    ## Remove the definitions
    Remove-AzRoleDefinition -Name $RoleDefinition.Name -Force
    #>
    #endregion
  
    $Jobs | Wait-Job | Out-Null
    Write-Verbose -Message "Removing jobs ..."
    $Jobs | Remove-Job -Force
    return $Gallery
}

#Get The Azure VM Compute Object for the VM executing this function
function Get-AzVMCompute {
    [CmdletBinding()]
    Param(
    )
    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        return $response.compute
    }
    catch {
        return $null
    }
}

function New-AzAvdSessionHost {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$VMName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$OUPath,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$DomainName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$VMSize = "Standard_D2s_v5",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImagePublisherName = "microsoftwindowsdesktop",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageOffer = "office-365",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageSku = "win11-23h2-avd-m365",
        [Parameter(Mandatory = $true, ParameterSetName = 'ACG', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VMSourceImageId,
        [hashtable] $Tag,
        [switch]$IsMicrosoftEntraIdJoined, 
        [switch] $Spot,
        [switch] $HibernationEnabled
    )
    $OSDiskSize = "127"
    $OSDiskType = "Premium_LRS"

    Import-Module -Name Az.Compute
    $ThisDomainController = Get-AzVMCompute | Get-AzVM
    # Get the VM's network interface
    $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
    $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
    # Get the subnet ID
    $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
    $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
    $split = $ThisDomainControllerSubnetId.split('/')
    # Get the vnet ID
    $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
    $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

    if ($null -eq (Get-AZVMSize -Location $ThisDomainControllerVirtualNetwork.Location | Where-Object -FilterScript { $_.Name -eq $VMSize })) {
        Write-Error "The '$VMSize' is not available in the '$($ThisDomainControllerVirtualNetwork.Location)' location ..." -ErrorAction Stop
    }

    Write-Verbose -Message "`$HostPoolId: $HostPoolId"
    $HostPool = Get-AzResource -ResourceId $HostPoolId
    Write-Verbose -Message "Creating the '$VMName' Session Host into the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group) ..."

    $NICName = "nic-$VMName"
    $OSDiskName = '{0}_OSDisk' -f $VMName
    #$DataDiskName = "$VMName-DataDisk01"

    #Create Network Interface Card 
    $NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -SubnetId $ThisDomainControllerSubnet.Id -Force

    if ($Spot) {
        #Create a virtual machine configuration file (As a Spot Intance for saving costs . DON'T DO THAT IN A PRODUCTION ENVIRONMENT !!!)
        #We have to create a SystemAssignedIdentity for Microsoft Entra ID joined Azure VM but let's do it for all VM
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned -Priority "Spot" -MaxPrice -1
    }
    elseif ($HibernationEnabled) {
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned -HibernationEnabled
    }
    else {
        #Create a virtual machine configuration file
        #We have to create a SystemAssignedIdentity for Microsoft Entra ID joined Azure VM but let's do it for all VM
        $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize -SecurityType Standard -IdentityType SystemAssigned
    }
    $null = Add-AzVMNetworkInterface -VM $VMConfig -Id $NIC.Id

    $LocalAdminUserName = $KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
    $LocalAdminPassword = ($KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
    $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)

    #Set VM operating system parameters
    $null = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName $VMName -Credential $LocalAdminCredential -ProvisionVMAgent

    #Set boot diagnostic to managed storage account
    $null = Set-AzVMBootDiagnostic -VM $VMConfig -Enable 

    #Set virtual machine source image
    if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
        Write-Verbose "Building Azure VM via `$VMSourceImageId:$VMSourceImageId"
        $null = Set-AzVMSourceImage -VM $VMConfig -Id $VMSourceImageId
    }
    else {
        Write-Verbose "Building Azure VM via `$ImagePublisherName:$ImagePublisherName/`$ImageOffer:$ImageOffer/`$ImageSku:$ImageSku"
        $null = Set-AzVMSourceImage -VM $VMConfig -PublisherName $ImagePublisherName -Offer $ImageOffer -Skus $ImageSku -Version 'latest'
    }

    #Set OsDisk configuration
    $null = Set-AzVMOSDisk -VM $VMConfig -Name $OSDiskName -DiskSizeInGB $OSDiskSize -StorageAccountType $OSDiskType -CreateOption fromImage

    $null = New-AzVM -ResourceGroupName $ResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -VM $VMConfig -Tag $Tag #-DisableBginfoExtension
    $VM = Get-AzVM -ResourceGroup $ResourceGroupName -Name $VMName
    $null = Start-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

    if ($IsMicrosoftEntraIdJoined) {
        Write-Verbose -Message "The '$VMName' VM will be Microsoft Entra ID joined ..."
        $aadJoin = "true"
    }
    else {
        $ExtensionName = "joindomain$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
        Write-Verbose -Message "Adding '$VMName' VM to '$DomainName' AD domain ..."

        $AdJoinUserName = $KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
        $AdJoinPassword = ($KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue

        $ADDomainJoinUser = Get-ADUser -Identity $AdJoinUserName -Properties UserPrincipalName
        if ([string]::IsNullOrEmpty($ADDomainJoinUser.UserPrincipalName)) {
            $ADDomainJoinUPNCredential = New-Object System.Management.Automation.PSCredential -ArgumentList("$AdJoinUserName@$DomainName", $AdJoinPassword)
        }
        else {
            $ADDomainJoinUPNCredential = New-Object System.Management.Automation.PSCredential -ArgumentList($ADDomainJoinUser.UserPrincipalName, $AdJoinPassword)
        }
        $null = Set-AzVMADDomainExtension -Name $ExtensionName -DomainName $DomainName -OUPath $OUPath -VMName $VMName -Credential $ADDomainJoinUPNCredential -ResourceGroupName $ResourceGroupName -JoinOption 0x00000003 -Restart
        $aadJoin = "false"
    }
    # Adding local admin Credentials to the Credential Manager (and escaping the password)
    #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /generic:$VMName /user:$($LocalAdminCredential.UserName) /pass:$($LocalAdminCredential.GetNetworkCredential().Password -replace "(\W)", '^$1')" -Wait


    <#
    Write-Verbose -Message "Installing the 'AzureMonitorWindowsAgent' on '$VMName' ..."
    $ExtensionName = "AzureMonitorWindowsAgent_$("{0:yyyyMMddHHmmss}" -f (Get-Date))"
    $Params = @{
        Name                   = $ExtensionName 
        ExtensionType          = 'AzureMonitorWindowsAgent'
        Publisher              = 'Microsoft.Azure.Monitor' 
        VMName                 = $VMName
        ResourceGroupName      = $ResourceGroupName
        location               = $ThisDomainControllerVirtualNetwork.Location
        TypeHandlerVersion     = '1.0' 
        EnableAutomaticUpgrade = $true
    }
    $null = Set-AzVMExtension  @Params 
    #>

    #From https://www.rozemuller.com/avd-automation-cocktail-avd-automated-with-powershell/
    #From https://www.rozemuller.com/how-to-join-azure-ad-automated/
    #Date : 02/14/2024
    $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02599.267.zip"
    $avdDscSettings = @{
        Name               = "Microsoft.PowerShell.DSC"
        Type               = "DSC" 
        Publisher          = "Microsoft.Powershell"
        typeHandlerVersion = "2.73"
        SettingString      = "{
            ""modulesUrl"":'$avdModuleLocation',
            ""ConfigurationFunction"":""Configuration.ps1\\AddSessionHost"",
            ""Properties"": {
                ""hostPoolName"": ""$($HostPool.Name)"",
                ""RegistrationInfoToken"": ""$($RegistrationInfoToken)"",
                ""aadJoin"": $aadJoin
            }
        }"
        VMName             = $VMName
        ResourceGroupName  = $ResourceGroupName
        location           = $ThisDomainControllerVirtualNetwork.Location
    }
    
    Write-Verbose -Message "Adding '$VMName' to '$($HostPool.Name)' Host Pool ..."
    $result = Set-AzVMExtension @avdDscSettings

    <#
    # AVD Azure AD Join domain extension
    $moduleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.02454.213.zip"
    $avdExtensionName = "DSC"
    $avdExtensionPublisher = "Microsoft.Powershell"
    $avdExtensionVersion = "2.73"
    $avdExtensionSetting = @{
        modulesUrl            = $moduleLocation
        ConfigurationFunction = "Configuration.ps1\\AddSessionHost"
        Properties            = @{
            hostPoolName          = $HostPool.Name
            registrationInfoToken = $RegistrationInfoToken
            aadJoin               = $IsMicrosoftEntraIdJoined
        }
    }
    Set-AzVMExtension -VMName $VMName -ResourceGroupName $ResourceGroupName -Location  $ThisDomainControllerVirtualNetwork.Location -TypeHandlerVersion $avdExtensionVersion -Publisher $avdExtensionPublisher -ExtensionType $avdExtensionName -Name $avdExtensionName -Settings $avdExtensionSetting 
    #>

    if ($IsMicrosoftEntraIdJoined) {
        #region Installing the AADLoginForWindows extension
        $PreviouslyExistingAzureADDevice = Get-AzureADDevice -SearchString $VMName
        if ($null -ne $PreviouslyExistingAzureADDevice) {
            Write-Verbose -Message "Removing previously existing '$VMName' as a device into 'Microsoft Entra ID' ..."
            $PreviouslyExistingAzureADDevice | Remove-AzureADDevice
        }
        Write-Verbose -Message "Adding '$VMName' as a device into 'Microsoft Entra ID' ..."
        Set-AzVMExtension -Publisher Microsoft.Azure.ActiveDirectory -Name AADLoginForWindows -ResourceGroupName $ResourceGroupName -VMName $VMName -ExtensionType AADLoginForWindows -TypeHandlerVersion 2.0
        #endregion
        <#
        #>
    }
    <#
    Write-Verbose -Message "Restarting '$VMName' ..."
    Restart-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -Confirm:$false
    #>
}

function Add-AzAvdSessionHost {
    [CmdletBinding(DefaultParameterSetName = 'Image')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Id')]
        [String]$HostPoolId, 
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateLength(2, 13)]
        [string]$NamePrefix,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateScript({ $_ -gt 0 })]
        [int]$VMNumberOfInstances,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]$KeyVault,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$RegistrationInfoToken,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$OUPath,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [String]$DomainName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$VMSize = "Standard_D2s_v5",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImagePublisherName = "microsoftwindowsdesktop",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageOffer = "office-365",
        [Parameter(Mandatory = $false, ParameterSetName = 'Image', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string]$ImageSku = "win11-23h2-avd-m365",
        [Parameter(Mandatory = $true, ParameterSetName = 'ACG', ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VMSourceImageId,
        [hashtable] $Tag,
        [switch]$IsMicrosoftEntraIdJoined,
        [switch]$Spot,
        [switch]$HibernationEnabled,
        [switch]$AsJob
    )
    #HibernationEnabled can be used with Spot VMs
    if ($Spot) {
        $HibernationEnabled = $false
    }

    $HostPool = Get-AzResource -ResourceId $HostPoolId
    $ExistingSessionHostNames = (Get-AzWvdSessionHost -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name).ResourceId -replace ".*/"
    $ExistingSessionHostNamesWithSameNamePrefix = $ExistingSessionHostNames -match "$NamePrefix-"
    if (-not([string]::IsNullOrEmpty($ExistingSessionHostNamesWithSameNamePrefix))) {
        $VMIndexes = $ExistingSessionHostNamesWithSameNamePrefix -replace "\D"
        if ([string]::IsNullOrEmpty($VMIndexes)) {
            $Start = 0
        }
        else {
            #We take the highest existing VM index and restart just after
            $Start = ($VMIndexes | Measure-Object -Maximum).Maximum + 1
        }
    }
    else {
        $Start = 0
    }
    $End = $Start + $VMNumberOfInstances - 1
    Write-Verbose -Message "Adding $VMNumberOfInstances Session Hosts to the '$($HostPool.Name)' Host Pool (in the '$($HostPool.ResourceGroupName)' Resource Group) ..."
    $Jobs = foreach ($Index in $Start..$End) {
        $CurrentVMName = '{0}-{1}' -f $NamePrefix, $Index
        if (-not([string]::IsNullOrEmpty($VMSourceImageId))) {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $CurrentVMName
                ResourceGroupName        = $HostPool.ResourceGroupName 
                KeyVault                 = $KeyVault
                RegistrationInfoToken    = $RegistrationInfoToken
                OUPath                   = $OUPath
                DomainName               = $DomainName
                VMSize                   = $VMSize 
                VMSourceImageId          = $VMSourceImageId
                Tag                      = $Tag
                IsMicrosoftEntraIdJoined = $IsMicrosoftEntraIdJoined
                Spot                     = $Spot
                HibernationEnabled       = $HibernationEnabled
                Verbose                  = $true
            }
        }
        else {
            $Params = @{
                HostPoolId               = $HostPoolId 
                VMName                   = $CurrentVMName
                ResourceGroupName        = $HostPool.ResourceGroupName 
                KeyVault                 = $KeyVault
                RegistrationInfoToken    = $RegistrationInfoToken
                OUPath                   = $OUPath
                DomainName               = $DomainName
                VMSize                   = $VMSize 
                ImagePublisherName       = $ImagePublisherName
                ImageOffer               = $ImageOffer
                ImageSku                 = $ImageSku
                Tag                      = $Tag
                IsMicrosoftEntraIdJoined = $IsMicrosoftEntraIdJoined
                Spot                     = $Spot
                HibernationEnabled       = $HibernationEnabled
                Verbose                  = $true
            }
        }
        #$AsJob = $false
        if ($AsJob) {
            #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
            #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
            $ExportedFunctions = [scriptblock]::Create(@"
            Function New-AzAvdSessionHost { ${Function:New-AzAvdSessionHost} }          
            Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
            $ClassDefinitionScriptBlock
"@)
            Write-Verbose "Starting background job for '$CurrentVMName' SessionHost Creation (via New-AzAvdSessionHost) ... "
            try {
                #Getting the Script Directory if ran from a Start-ThreadJob
                $LocalCurrentDir = $using:CurrentDir
                Write-Verbose "We are in the context of a 'Start-ThreadJob' ..."
            }
            catch {
                #Getting the Script Directory if NOT ran from a Start-ThreadJob
                $LocalCurrentDir = $CurrentDir
                Write-Verbose "We are NOT in the context of a 'Start-ThreadJob' ..."
            }
            Write-Verbose "`$LocalCurrentDir: $LocalCurrentDir"
            Start-ThreadJob -ScriptBlock { param($CurrentDir) New-AzAvdSessionHost @using:Params *>&1 | Out-File -FilePath $("{0}\New-AzAvdSessionHost_{1}_{2}.txt" -f $CurrentDir, $using:CurrentVMName, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions -ArgumentList $LocalCurrentDir #-StreamingHost $Host
        }
        else {
            New-AzAvdSessionHost @Params
        }
    }
    if ($AsJob) {
        $Jobs | Receive-Job -Wait
    }
}

function Copy-MSIXDemoAppAttachPackage {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )   
    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty download_url
    $VHDFileURIs = $Files -match "\.vhd$"

    Write-Verbose -Message "VHD File Source URIs: $($VHDFileURIs -join ',')" 
    #Copying the VHD package for MSIX to the MSIX file share    
    Start-BitsTransfer -Source $VHDFileURIs -Destination $Destination
    $MSIXDemoPackage = $VHDFileURIs | ForEach-Object -Process { Join-Path -Path $Destination -ChildPath $($_ -replace ".*/") }
    return $MSIXDemoPackage
}

function Copy-MSIXDemoPFXFile {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNull()] 
        [System.Security.SecureString]$SecurePassword = $(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force)
    )   

    $URI = "https://api.github.com/repos/lavanack/laurentvanacker.com/contents/Azure/Azure%20Virtual%20Desktop/MSIX/MSIX"
    $Response = Invoke-WebRequest -Uri $URI -UseBasicParsing
    $Objects = $Response.Content | ConvertFrom-Json
    $Files = $Objects | Where-Object -FilterScript { $_.type -eq "file" } | Select-Object -ExpandProperty download_url
    $PFXFileURIs = $Files -match "\.pfx$"

    #Copying the PFX files for MSIX to a temp local folder
    $TempFolder = New-Item -Path $(Join-Path -Path $env:TEMP -ChildPath $("{0:yyyyMMddHHmmss}" -f (Get-Date))) -ItemType Directory -Force
    #Copying the Self-Signed certificate to the MSIX file share
    Start-BitsTransfer -Source $PFXFileURIs -Destination $TempFolder
    $DownloadedPFXFiles = Get-ChildItem -Path $TempFolder -Filter *.pfx -File

    $Session = New-PSSession -ComputerName $ComputerName
    #Copying the PFX to all session hosts
    $Session | ForEach-Object -Process { Copy-Item -Path $DownloadedPFXFiles.FullName -Destination C:\ -ToSession $_ -Force }

    Invoke-command -Session $Session -ScriptBlock {
        $using:DownloadedPFXFiles | ForEach-Object -Process { 
            $LocalFile = $(Join-Path -Path C: -ChildPath $_.Name)
            #Adding the self-signed certificate to the Trusted Root Certification Authorities (To validate this certificate)
            $ImportPfxCertificates = Import-PfxCertificate $LocalFile -CertStoreLocation Cert:\LocalMachine\TrustedPeople\ -Password $using:SecurePassword 
            Write-Verbose -Message $($ImportPfxCertificates | Out-String)
            #Removing the PFX file (useless now)
            Remove-Item -Path $LocalFile -Force
            Write-Verbose -Message "Updating GPO ..."
            gpupdate /force /wait:-1 /target:computer | Out-Null
        }
    }
    #Removing the Temp folder (useless now)
    Remove-Item -Path $TempFolder -Recurse -Force
}

function Wait-PSSession {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$ComputerName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Seconds = 30,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10
    )
    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
    }
    $Loop = 0
    Write-Verbose -Message "Computer Names (Nb: $($ComputerName.Count)): $($ComputerName -join ', ')"  
    Do
    {
        $Loop ++  
        Write-Verbose -Message "Loop #$($Loop) ..."  
        $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Ignore
        if ($Session.Count -lt $ComputerName.Count) {
            Write-Verbose -Message "Sleeping $Seconds Seconds ..."
            Start-Sleep -Seconds $Seconds
            $result =$false
        }
        else {
            $result =$true
        }
        $Session | Remove-PSSession
        Write-Verbose -Message "Result: $result ..."  
    } While ((-not($result)) -and ($Loop -lt $Attempts))
    return $result
}

function Wait-AzVMPowerShell {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string]$HostPoolName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Seconds = 30,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()] 
        [int]$Attempts = 10
    ) 
    #Any negative value means infinite loop. 
    if ($Attempts -lt 0) {
        $Attempts = [int]::MaxValue
        Write-Verbose -Message "Infinite Loop Mode Enabled ..."  
    }
    $Loop = 0
    $SessionHosts = Get-AzWvdSessionHost -HostpoolName $HostPoolName -ResourceGroupName $ResourceGroupName
    #Write-Verbose -Message "Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -join ', ')"
    Write-Verbose -Message "Session Hosts (Nb: $($SessionHosts.Count)): $($SessionHosts.Name -replace "^.*/" -replace "\..*$" -join ', ')"
    Do
    {
        $Loop ++  
        Write-Verbose -Message "Loop #$($Loop) ..."  
        $Jobs = foreach ($CurrentSessionHost in $SessionHosts) {
            $CurrentSessionHostVM = $CurrentSessionHost.ResourceId | Get-AzVM
            Write-Verbose -Message "Processing '$($CurrentSessionHostVM.Name)' ..."
            Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $CurrentSessionHostVM.Name -CommandId 'RunPowerShellScript' -ScriptString 'return $true' -AsJob
        }
        $Jobs | Wait-Job | Out-Null
        #Write-Host "Job State: $($Jobs.State -join ', ')" 
        Write-Verbose -Message "Job State:`r`n$($Jobs | Group-Object State -NoElement | Out-String)"  
        if ($Jobs.State -ne "Completed") {
            Write-Verbose -Message "Sleeping $Seconds Seconds ..."
            Start-Sleep -Seconds $Seconds
            $result = $false
        }
        else {
            $result = $true
        }
        $Jobs | Remove-Job -Force
        Write-Verbose -Message "Result: $result ..."  
    } While ((-not($result)) -and ($Loop -lt $Attempts))
    return $result
}

function Start-MicrosoftEntraIDConnectSync {
    [CmdletBinding()]
    Param()
    if (Get-Service -Name ADSync -ErrorAction Ignore) {
        Start-Service -Name ADSync
        Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
        $ADSyncConnectorRunStatus = Get-ADSyncConnectorRunStatus
        Write-Verbose "`$ADSyncConnectorRunStatus: $($ADSyncConnectorRunStatus | Out-String)"
        #if ($ADSyncConnectorRunStatus.RunState -ne [Microsoft.IdentityManagement.PowerShell.ObjectModel.ConnectorRunState]::Busy){
        if ($null -eq $ADSyncConnectorRunStatus) {
            Write-Verbose "Running a sync with Microsoft Entra ID ..."
            try {
                $null = Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Ignore
                Write-Verbose -Message "Sleeping 30 seconds ..."
                Start-Sleep -Seconds 30
            }
            catch {
                Write-Verbose "Microsoft Entra ID Sync already in progress ..."
            }
        }
        else {
            Write-Verbose "Microsoft Entra ID Sync already in progress ..."
        }
    }
}

function Remove-AzAvdHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [HostPool[]]$HostPool
    )
    $StartTime = Get-Date
    #region Cleanup of the previously existing resources
    #region DNS Cleanup
    $OUDistinguishedNames = (Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) }).DistinguishedName 
    if (-not([string]::IsNullOrEmpty($OUDistinguishedNames))) {
        $OUDistinguishedNames | ForEach-Object -Process {
            Write-Verbose "Processing OU: '$_' ..."
            (Get-ADComputer -Filter 'DNSHostName -like "*"' -SearchBase $_).Name } | ForEach-Object -Process { 
            try {
                if (-not([string]::IsNullOrEmpty($_))) {
                    Write-Verbose "Removing DNS Record: '$_' ..."
                    $DomainName = (Get-ADDomain).DNSRoot
                    #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
                    Remove-DnsServerResourceRecord -ZoneName $DomainName -RRType "A" -Name "$_" -Force -ErrorAction Ignore
                }
            } 
            catch {} 
        }
    }
    #endregion
    #region AD OU/GPO Cleanup
    Write-Verbose "Removing OUs ..."
    #Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) -or $_.Name -in 'PooledDesktops', 'PersonalDesktops' } | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false #-WhatIf
    Get-ADOrganizationalUnit -Filter * | Where-Object -FilterScript { $_.Name -in $($HostPools.Name) } | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Ignore | Remove-ADOrganizationalUnit -Recursive -Confirm:$false #-WhatIf
    Write-Verbose "Removing GPOs ..."
    #Get-GPO -All | Where-Object -FilterScript { ($_.DisplayName -match $($HostPools.Name -join "|")) -or ($_.DisplayName -in 'AVD - Global Settings', 'Group Policy Reporting Firewall Ports', 'Group Policy Remote Update Firewall Ports') } | Remove-GPO #-WhatIf
    Get-GPO -All | Where-Object -FilterScript { $_.DisplayName -match $($HostPools.Name -join "|") } | Remove-GPO #-WhatIf
    #endregion
    #region Azure AD/Microsoft Entra ID cleanup
    $MicrosoftEntraIDHostPools = $HostPools | Where-Object -FilterScript { $_.IsMicrosoftEntraIdJoined() }
    $MicrosoftEntraIDSessionHostNames = foreach ($CurrentHostPoolName in $MicrosoftEntraIDHostPools.Name) { (Get-AzWvdSessionHost -HostPoolName $CurrentHostPoolName -ResourceGroupName "rg-avd-$CurrentHostPoolName" -ErrorAction Ignore).ResourceId -replace ".*/" | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_)) } }
    Write-Verbose -Message "Removing Microsoft Entra ID Devices : $($MicrosoftEntraIDSessionHostNames -join ', ')"
    Get-AzureADDevice | Where-Object -FilterScript { $_.DisplayName -in $MicrosoftEntraIDSessionHostNames } | Remove-AzureADDevice
    #endregion
    #region Azure Cleanup
    <#
    $HostPool = (Get-AzWvdHostPool | Where-Object -FilterScript {$_.Name -in $($HostPools.Name)})
    Write-Verbose "Getting HostPool(s): $($HostPool.Name -join, ', ') ..."
    $ResourceGroup = $HostPool | ForEach-Object { Get-AzResourceGroup $_.Id.split('/')[4]}
    #Alternative to get the Resource Group(s)
    #$ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript {($_.ResourceGroupName -match $($HostPools.Name -join "|"))
    #>
    $ResourceGroupName = ($HostPools.Name | ForEach-Object -Process { "rg-avd-$($_)" })
    Write-Verbose "ResourceGroup Name(s): $($ResourceGroupName -join, ', ') ..."
    $ResourceGroup = Get-AzResourceGroup | Where-Object -FilterScript { ($_.ResourceGroupName -in $ResourceGroupName) }

    Write-Verbose "Removing Azure Delete Lock (if any) on Resource Group(s): $($ResourceGroup.ResourceGroupName -join, ', ') ..."
    $ResourceGroup | Foreach-Object -Process { Get-AzResourceLock -ResourceGroupName $_.ResourceGroupName -AtScope | Where-Object -FilterScript { $_.Properties.level -eq 'CanNotDelete' } } | Remove-AzResourceLock -Force -ErrorAction Ignore

    #region Windows Credential Manager Cleanup
    Write-Verbose -Message "Removing Credentials from Windows Credential Manager ..."
    $StorageAccountName = ($ResourceGroup | Get-AzStorageAccount).StorageAccountName
    $Pattern = $StorageAccountName -join "|"
    $StorageAccountCredentials = cmdkey /list | Select-string -Pattern "(?<Target>Target: (?<Domain>Domain:target=(?<FQDN>(?<Pattern>$Pattern)\.file\.core\.windows\.net)))" -AllMatches
    if ($StorageAccountCredentials.Matches) {
        $StorageAccountCredentials.Matches | ForEach-Object -Process { 
            $FQDN = $_.Groups['FQDN']
            $Domain = $_.Groups['Domain']
            Write-Verbose -Message "'$FQDN' credentials will be removed from the Windows Credential Manager"
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$Domain" -Wait
        }
    }
    #endregion

    Write-Verbose "Removing Resource Group(s) (As a Job): $($ResourceGroup.ResourceGroupName -join, ', ') ..."
    $Jobs = $ResourceGroup | Remove-AzResourceGroup -Force -AsJob
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job

    <#
    #region Removing HostPool Session Credentials Key Vault
    $CredKeyVault = $HostPools.KeyVault | Select-Object -Unique
    $Jobs = $CredKeyVault.ResourceGroupName | ForEach-Object -Process { Remove-AzResourceGroup -Name $_ -Force -AsJob } 
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job
    #endregion
    #>

    #region Removing Dedicated HostPool Key Vault in removed state
    Write-Verbose "Removing Dedicated HostPool Key Vault in removed state (As a Job) ..."
    #$Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript { ($_.VaultName -match $($(($HostPools.Name -replace "\W").ToLower()) -join "|")) -or ($_.VaultName -in $CredKeyVault.VaultName) } | Remove-AzKeyVault -InRemovedState -AsJob -Force 
    $Jobs = Get-AzKeyVault -InRemovedState | Where-Object -FilterScript { ($_.VaultName -match $($(($HostPools.Name -replace "\W").ToLower()) -join "|")) } | Remove-AzKeyVault -InRemovedState -AsJob -Force 
    $Jobs | Wait-Job | Out-Null
    $Jobs | Remove-Job
    #endregion
    #endregion
    #endregion

    #region Run a sync with Azure AD
    Start-MicrosoftEntraIDConnectSync
    #endregion
    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "HostPool Removal Processing Time: $($TimeSpan.ToString())"
}

function New-AzAvdPersonalHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [object[]]$HostPool,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [alias('OU')]
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ADOrganizationalUnit,

        [switch] $AsJob
    )

    begin {
        $StartTime = Get-Date
        $AzContext = Get-AzContext

        #region Variables
        $SKUName = "Standard_LRS"
        $CurrentHostPoolStorageAccountNameMaxLength = 24
        $CurrentHostPoolKeyVaultNameMaxLength = 24

        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        $DomainName = (Get-ADDomain).DNSRoot
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
        #endregion 

    }
    process {
        Foreach ($CurrentHostPool in $HostPool) {
            $StartTime = Get-Date
            $Tag = @{HostPoolName = $CurrentHostPool.Name; HostPoolType = "Personal" }

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)') ..."
            }
            #endregion

            #region Creating an PersonalDesktops OU 
            $PersonalDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PersonalDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PersonalDesktopsOU)) {
                $PersonalDesktopsOU = New-ADOrganizationalUnit -Name "PersonalDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($PersonalDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)') ..."
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PersonalDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PersonalDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PersonalDesktopsOU.DistinguishedName)') ..."
            }
            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolDAGUsersADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                $CurrentHostPoolDAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolDAGUsersADGroupName -SamAccountName $CurrentHostPoolDAGUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolDAGUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }
            #endregion

            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 
            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentHostPoolResourceGroupName = "rg-avd-$($CurrentHostPool.Name.ToLower())"

            $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
            if (-not($CurrentHostPoolResourceGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group ..."
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Microsoft Entra ID Management
            if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
                $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
                $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
                Grant-ADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName
                $Tag['DomainType'] = "Active Directory Directory Services"
            }
            else {
                $Tag['DomainType'] = "Microsoft Entra ID"
                #region Assign Virtual Machine Administrator Login' RBAC role to the Resource Group
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersADGroupName
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Virtual Machine Administrator Login'
                    Verbose            = $true
                }

                Write-Verbose -Message "Assigning the 'Virtual Machine Administrator Login' RBAC role to '$CurrentHostPoolDAGUsersADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group ..."
                $null = New-AzRoleAssignment @parameters
                #endregion 

            }
            #endregion 

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentHostPoolKeyVaultName = "kv{0}" -f $($CurrentHostPool.Name -replace "\W")
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentHostPoolKeyVaultNameMaxLength, $CurrentHostPoolKeyVaultName.Length)).ToLower()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.ToLower()
            #endregion 

            #region Dedicated Key Vault Setup
            $CurrentHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentHostPoolKeyVault)) {
                if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
                    Write-Error "The key vault name '$CurrentHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                Write-Verbose -Message "Creating '$CurrentHostPoolKeyVaultName' Key Vault (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $CurrentHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentHostPoolResourceGroupName -VaultName $CurrentHostPoolKeyVaultName -Location $ThisDomainControllerVirtualNetwork.Location -EnabledForDiskEncryption -SoftDeleteRetentionInDays 7
            }
            #endregion

            #region Private endpoint for Key Vault Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolKeyVaultName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolKeyVault.ResourceId).GroupId
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolKeyVault.ResourceId -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($null -eq $PrivateDnsZone) {
                Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($null -eq $PrivateDnsVirtualNetworkLink) {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$CurrentHostPoolKeyVaultName' ..."
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

            #Key Vault - Disabling Public Access
            Write-Verbose -Message "Disabling the Public Access for the Key Vault'$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $null = Update-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ResourceGroupName $CurrentHostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
            #endregion

            #endregion

            #region Host Pool Setup
            $RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
            #Microsoft Entra ID
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "targetisaadjoined:i:1;redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:;enablerdsaadauth:i:1"
            }
            #Active Directory Directory Services
            else {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
            }
            $parameters = @{
                Name                          = $CurrentHostPool.Name
                ResourceGroupName             = $CurrentHostPoolResourceGroupName
                HostPoolType                  = 'Personal'
                PersonalDesktopAssignmentType = 'Automatic'
                LoadBalancerType              = 'Persistent'
                PreferredAppGroupType         = 'Desktop'
                Location                      = $CurrentHostPool.Location
                StartVMOnConnect              = $true
                ExpirationTime                = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                CustomRdpProperty             = $CustomRdpProperty
                Tag                           = $Tag
                Verbose                       = $true
            }

            Write-Verbose -Message "Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentHostPoolResourceGroupName -HostPoolName $CurrentHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue


            #region Scale session hosts using Azure Automation
            #TODO : https://learn.microsoft.com/en-us/training/modules/automate-azure-virtual-desktop-management-tasks/1-introduction
            #endregion

            #region Set up Private Link with Azure Virtual Desktop
            #TODO: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-setup?tabs=powershell%2Cportal-2#enable-the-feature
            #endregion


            #region Use Azure Firewall to protect Azure Virtual Desktop deployments
            #TODO: https://learn.microsoft.com/en-us/training/modules/protect-virtual-desktop-deployment-azure-firewall/
            #endregion
            #endregion

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentHostPool.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                Verbose              = $true
            }

            Write-Verbose -Message "Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to 'Full Desktop' ..."
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName "Full Desktop"

            #region Assign 'Desktop Virtualization User RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersADGroupName
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                Verbose            = $true
            }

            Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentHostPoolDAGUsersADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Workspace Setup
            $Options = $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            $FriendlyName = "ws-{0} ({1})" -f $CurrentHostPool.Name,$($Options -join ', ')
            $parameters = @{
                Name                      = "ws-{0}" -f $CurrentHostPool.Name
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
                Location                  = $CurrentHostPool.Location
                Verbose                   = $true
            }

            Write-Verbose -Message "Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            #region Adding Session Hosts to the Host Pool
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -AsJob #:$AsJob
            }
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            #region Restarting the Session Hosts
            $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
            }
            $Jobs | Wait-Job | Out-Null
            $Jobs | Remove-Job -Force
            #endregion 

            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = "log{0}" -f $($CurrentAzWvdHostPool.Name -replace "\W")
            Write-Verbose -Message "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force
            Do {
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
                $LogAnalyticsWorkSpace = $null
                $LogAnalyticsWorkSpace = Get-AzOperationalInsightsWorkspace -Name $LogAnalyticsWorkSpaceName -ResourceGroupName $CurrentHostPoolResourceGroupName
            } While ($null -eq $LogAnalyticsWorkSpace)
            Write-Verbose -Message "Sleeping 30 seconds ..."
            Start-Sleep -Seconds 30
            #Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "Enabling Diagnostics Setting for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $HostPoolDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            #$HostPoolDiagnosticSetting
            #Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "Enabling Diagnostics Setting for the  '$($CurrentAzWvdWorkspace.Name)' Work Space ..."
            $WorkSpaceDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Feed"
            #$WorkSpaceDiagnosticSetting
            $EventLogs = @(
                @{EventLogName = 'Application' ; CollectInformation = $false; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'System' ; CollectInformation = $false; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
            )
            foreach ($CurrentEventLog in $EventLogs) {
                $Name = $CurrentEventLog.EventLogName -replace "\W", "-"
                Write-Verbose -Message "Enabling the '$($CurrentEventLog.EventLogName)' EventLog in the '$($LogAnalyticsWorkSpace.Name)' Log Analytics WorkSpace (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsEventDataSource -ResourceGroupName $CurrentHostPoolResourceGroupName -WorkspaceName $($LogAnalyticsWorkSpace.Name) -Name $Name @CurrentEventLog -Force
            }
            
            $PerformanceCouters = @(
                @{ObjectName = 'LogicalDisk'; CounterName = '% Free Space'; InstanceName = 'C:'; IntervalSeconds = 60 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = 'C:'; IntervalSeconds = 60 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Available Mbytes'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Page Faults/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Pages/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = '% Committed Bytes In Use'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Processor Information'; CounterName = '% Processor Time'; InstanceName = '_Total'; IntervalSeconds = 30 }
                @{ObjectName = 'RemoteFX Network'; CounterName = 'Current TCP RTT'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'RemoteFX Network'; CounterName = 'Current UDP Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Active Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Inactive Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Total Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'User Input Delay per Process'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'User Input Delay per Session'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
            )
            foreach ($CurrentPerformanceCouter in $PerformanceCouters) {
                $Name = $('{0}-{1}-{2}' -f $CurrentPerformanceCouter.ObjectName, $CurrentPerformanceCouter.CounterName, $CurrentPerformanceCouter.InstanceName) -replace "\W", "-"
                Write-Verbose -Message "Enabling '$($CurrentPerformanceCouter.CounterName)' Performance Counter in the '$($LogAnalyticsWorkSpace.Name)' Log Analytics WorkSpace (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsPerformanceCounterDataSource -ResourceGroupName $CurrentHostPoolResourceGroupName -WorkspaceName $($LogAnalyticsWorkSpace.Name) -Name $Name @CurrentPerformanceCouter -Force
            }
            #endregion

            #region install Log Analytics Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $LogAnalyticsWorkSpaceKey = ($LogAnalyticsWorkSpace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
                $PublicSettings = @{ "workspaceId" = $LogAnalyticsWorkSpace.CustomerId }
                $ProtectedSettings = @{ "workspaceKey" = $LogAnalyticsWorkSpaceKey }
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "Install Log Analytics Agent on the '$($CurrentSessionHostVM.Name )' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job) ..."
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $ThisDomainControllerVirtualNetwork.Location -AsJob
                }
                Write-Verbose -Message "Waiting all jobs completes ..."
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion


            #region Enabling VM insights by using PowerShell
            $TemplateUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/DCR/template.json"
            $DataCollectionRulesName = "MSVMI-{0}" -f $LogAnalyticsWorkSpace.Name
            $TemplateParameterObject = @{
                dataCollectionRules_name = $DataCollectionRulesName
                workspaces_externalid    = $LogAnalyticsWorkSpace.ResourceId
            }
            #region Submitting the template
            Write-Verbose -Message "Starting Resource Group Deployment from '$TemplateUri' ..."
            $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $CurrentHostPoolResourceGroupName -TemplateUri $TemplateUri -TemplateParameterObject $TemplateParameterObject
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            $DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRulesName
            foreach ($CurrentSessionHost in $SessionHosts) {
                $AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -TargetResourceId $CurrentSessionHost.ResourceId -AssociationName $AssociationName -RuleId $DataCollectionRule.Id
            }
            #endregion
            #endregion
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Host -Object "'$($CurrentHostPool.Name)' Setup Processing Time: $($TimeSpan.ToString())"
        }    
    }
    end {
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall Personal HostPool Setup Processing Time: $($TimeSpan.ToString())"
    }
}

function New-AzAvdPooledHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [object[]]$HostPool,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [alias('OU')]
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ADOrganizationalUnit,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        $NoMFAAzADGroupName = "No-MFA Users",

        [switch] $AsJob
    )

    begin {
        $StartTime = Get-Date
        $AzContext = Get-AzContext
        $StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix

        #region Variables
        $FSLogixContributor = "FSLogix Contributor"
        $FSLogixElevatedContributor = "FSLogix Elevated Contributor"
        $FSLogixReader = "FSLogix Reader"
        $FSLogixShareName = "profiles", "odfc" 

        $MSIXHosts = "MSIX Hosts"
        $MSIXShareAdmins = "MSIX Share Admins"
        $MSIXUsers = "MSIX Users"
        $MSIXShareName = "msix"  

        $SKUName = "Standard_LRS"
        $CurrentHostPoolStorageAccountNameMaxLength = 24
        $CurrentHostPoolKeyVaultNameMaxLength = 24

        #From https://www.youtube.com/watch?v=lvBiLj7oAG4&t=2s
        $RedirectionsXMLFileContent = @'
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection ExcludeCommonFolders="49">
<Excludes>
<Exclude Copy="0">AppData\Roaming\Microsoft\Teams\media-stack</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Teams\meeting-addin\Cache</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Outlook</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\OneDrive</Exclude>
<Exclude Copy="0">AppData\Local\Microsoft\Edge</Exclude>
</Excludes>
<Includes>
<Include>AppData\Local\Microsoft\Edge\User Data</Include>
</Includes>
</FrxProfileFolderRedirection>
'@

        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId
        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        $DomainName = (Get-ADDomain).DNSRoot
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
        #endregion 

    }
    process {
        Foreach ($CurrentHostPool in $HostPool) {
            $StartTime = Get-Date
            
            #Microsoft Entra ID
            <#
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                Write-Error "A Pooled HostPool must be an ADDS-joined Azure VM in this script. This is not the case for '$($CurrentHostPool.Name)'. We Skip it !!!"
                continue
            }
            else {
            }
            #>

            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            $Tag = @{MSIX = $Status[$CurrentHostPool.MSIX]; FSLogix = $Status[$CurrentHostPool.FSLogix]; HostPoolName = $CurrentHostPool.Name; HostPoolType = "Pooled"}

            #region Creating an <Azure Location> OU 
            $LocationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Location)'" -SearchBase $ADOrganizationalUnit.DistinguishedName
            if (-not($LocationOU)) {
                $LocationOU = New-ADOrganizationalUnit -Name $CurrentHostPool.Location -Path $ADOrganizationalUnit.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($LocationOU.DistinguishedName)' OU (under '$($ADOrganizationalUnit.DistinguishedName)') ..."
            }
            #endregion

            #region Creating an PooledDesktops OU 
            $PooledDesktopsOU = Get-ADOrganizationalUnit -Filter 'Name -eq "PooledDesktops"' -SearchBase $LocationOU.DistinguishedName
            if (-not($PooledDesktopsOU)) {
                $PooledDesktopsOU = New-ADOrganizationalUnit -Name "PooledDesktops" -Path $LocationOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($PooledDesktopsOU.DistinguishedName)' OU (under '$($LocationOU.DistinguishedName)') ..."
            }
            #endregion

            #region General AD Management
            #region Host Pool Management: Dedicated AD OU Setup (1 OU per HostPool)
            $CurrentHostPoolOU = Get-ADOrganizationalUnit -Filter "Name -eq '$($CurrentHostPool.Name)'" -SearchBase $PooledDesktopsOU.DistinguishedName
            if (-not($CurrentHostPoolOU)) {
                $CurrentHostPoolOU = New-ADOrganizationalUnit -Name "$($CurrentHostPool.Name)" -Path $PooledDesktopsOU.DistinguishedName -ProtectedFromAccidentalDeletion $false -PassThru
                Write-Verbose -Message "Creating '$($CurrentHostPoolOU.DistinguishedName)' OU (under '$($PooledDesktopsOU.DistinguishedName)') ..."
            }

            $AdJoinUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinUserName -AsPlainText
            $AdJoinPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name AdJoinPassword).SecretValue
            $AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
            Grant-ADJoinPermission -Credential $AdJoinCredential -OrganizationalUnit $CurrentHostPoolOU.DistinguishedName

            #endregion

            #region Host Pool Management: Dedicated AD users group
            $CurrentHostPoolDAGUsersADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
            $CurrentHostPoolDAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolDAGUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolDAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolDAGUsersADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                $CurrentHostPoolDAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolDAGUsersADGroupName -SamAccountName $CurrentHostPoolDAGUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolDAGUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }

            $CurrentHostPoolRAGUsersADGroupName = "$($CurrentHostPool.Name) - Remote Application Group Users"
            $CurrentHostPoolRAGUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolRAGUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
            if (-not($CurrentHostPoolRAGUsersADGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolRAGUsersADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                $CurrentHostPoolRAGUsersADGroup = New-ADGroup -Name $CurrentHostPoolRAGUsersADGroupName -SamAccountName $CurrentHostPoolRAGUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolRAGUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
            }
            #endregion
            #region Run a sync with Azure AD
            Start-MicrosoftEntraIDConnectSync
            #endregion 
            #endregion

            #region FSLogix
            #From https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles
            if ($CurrentHostPool.FSLogix) {
                #region FSLogix AD Management
                #region Dedicated HostPool AD group
                #region Dedicated HostPool AD FSLogix groups
                $CurrentHostPoolFSLogixContributorADGroupName = "$($CurrentHostPool.Name) - $FSLogixContributor"
                $CurrentHostPoolFSLogixContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixContributorADGroup)) {
                    $CurrentHostPoolFSLogixContributorADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixContributorADGroupName -SamAccountName $CurrentHostPoolFSLogixContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixContributorADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                }
                Write-Verbose -Message "Adding the '$CurrentHostPoolDAGUsersADGroupName' AD group to the '$CurrentHostPoolFSLogixContributorADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                $CurrentHostPoolFSLogixContributorADGroup | Add-ADGroupMember -Members $CurrentHostPoolDAGUsersADGroupName

                $CurrentHostPoolFSLogixElevatedContributorADGroupName = "$($CurrentHostPool.Name) - $FSLogixElevatedContributor"
                $CurrentHostPoolFSLogixElevatedContributorADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixElevatedContributorADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixElevatedContributorADGroup)) {
                    $CurrentHostPoolFSLogixElevatedContributorADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixElevatedContributorADGroupName -SamAccountName $CurrentHostPoolFSLogixElevatedContributorADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixElevatedContributorADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixElevatedContributorADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                }

                $CurrentHostPoolFSLogixReaderADGroupName = "$($CurrentHostPool.Name) - $FSLogixReader"
                $CurrentHostPoolFSLogixReaderADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolFSLogixReaderADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolFSLogixReaderADGroup)) {
                    $CurrentHostPoolFSLogixReaderADGroup = New-ADGroup -Name $CurrentHostPoolFSLogixReaderADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolFSLogixReaderADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                    Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixReaderADGroup.Name)' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                }
                #endregion
                #region Run a sync with Azure AD
                Start-MicrosoftEntraIDConnectSync
                #endregion 
                #endregion
                #endregion

                #region FSLogix Storage Account Management
                #region FSLogix Storage Account Name Setup
                $CurrentHostPoolStorageAccountName = "fsl{0}" -f $($CurrentHostPool.Name -replace "\W")
                $CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentHostPoolStorageAccountNameMaxLength, $CurrentHostPoolStorageAccountName.Length)).ToLower()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
                if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                    $CurrentHostPoolFSLogixGPO = Get-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings" -ErrorAction Ignore
                    if (-not($CurrentHostPoolFSLogixGPO)) {
                        $CurrentHostPoolFSLogixGPO = New-GPO -Name "$($CurrentHostPool.Name) - FSLogix Settings"
                        Write-Verbose -Message "Creating '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))' ..."
                    }
                    $null = $CurrentHostPoolFSLogixGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

                    #region FSLogix GPO Management: Dedicated GPO settings for FSLogix profiles for this HostPool 
                    #From https://learn.microsoft.com/en-us/fslogix/tutorial-configure-profile-containers#profile-container-configuration
                    Write-Verbose -Message "Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU) ..."
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "FlipFlopProfileDirectoryName" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LockedRetryInterval" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachIntervalSeconds" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 15
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ReAttachRetryCount" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 3
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "SizeInMBs" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 30000
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "ProfileType" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0

                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithFailure" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "PreventLoginWithTempProfile" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VolumeType" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value "VHDX"
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "LogFileKeepingPeriod" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 10
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "IsDynamic" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName "NoAutoUpdate" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableTimeZoneRedirection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    #From https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-storage-sense
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ValueName "01" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.StorageSense::SS_AllowStorageSenseGlobal
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\StorageSense' -ValueName "AllowStorageSenseGlobal" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

                    #region GPO Debug log file
                    #From https://blog.piservices.fr/post/2017/12/21/active-directory-debug-avance-de-l-application-des-gpos
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' -ValueName "GPSvcDebugLevel" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0x30002
                    #endregion

                    #region Microsoft Defender Endpoint A/V General Exclusions (the *.VHD and *.VHDX exclusions applies to FSLogix and MSIX) 
                    #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                    Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU) ..."
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Paths" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%TEMP%\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%Windir%\TEMP\*\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Cache\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramData%\FSLogix\Proxy\*" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0

                    #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDefender::Exclusions_Processesget-job
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -ValueName "Exclusions_Processes" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccd.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes' -ValueName "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                    #endregion

                    Write-Verbose -Message "Setting some 'FSLogix' related registry values for '$($CurrentHostPoolFSLogixGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU) ..."
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "VHDLocations" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #Use Redirections.xml. Be careful : https://twitter.com/JimMoyle/status/1247843511413755904w
                    $null = Set-GPRegistryValue -Name $CurrentHostPoolFSLogixGPO.DisplayName -Key 'HKLM\SOFTWARE\FSLogix\Profiles' -ValueName "RedirXMLSourceFolder" -Type ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles"
                    #endregion 

                    #region GPO "Local Users and Groups" Management via groups.xml
                    #From https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/37722b69-41dd-4813-8bcd-7a1b4d44a13d
                    #From https://jans.cloud/2019/08/microsoft-fslogix-profile-container/
                    $GroupXMLGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\Machine\Preferences\Groups\Groups.xml" -f $DomainName, $($CurrentHostPoolFSLogixGPO.Id)
                    Write-Verbose -Message "Creating '$GroupXMLGPOFilePath' ..."
                    #Generating an UTC time stamp
                    $Changed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    #$ADGroupToExcludeFromFSLogix = @('Domain Admins', 'Enterprise Admins')
                    $ADGroupToExcludeFromFSLogix = @('Domain Admins')
                    $Members = foreach ($CurrentADGroupToExcludeFromFSLogix in $ADGroupToExcludeFromFSLogix) {
                        $CurrentADGroupToExcludeFromFSLogixSID = (Get-ADGroup -Filter "Name -eq '$CurrentADGroupToExcludeFromFSLogix'").SID.Value
                        if (-not([string]::IsNullOrEmpty($CurrentADGroupToExcludeFromFSLogixSID))) {
                            Write-Verbose -Message "Excluding '$CurrentADGroupToExcludeFromFSLogix' from '$GroupXMLGPOFilePath' ..."
                            "<Member name=""$((Get-ADDomain).NetBIOSName)\$CurrentADGroupToExcludeFromFSLogix"" action=""ADD"" sid=""$CurrentADGroupToExcludeFromFSLogixSID""/>"
                        }
                    }
                    $Members = $Members -join ""

                    $GroupXMLGPOFileContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the exclude list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix ODFC Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix ODFC Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for Outlook Data Folder Containers" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix ODFC Include List"/></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Exclude List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}" userContext="0" removePolicy="0"><Properties action="U" newName="" description="Members of this group are on the exclude list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="" groupName="FSLogix Profile Exclude List"><Members>$Members</Members></Properties></Group>
	<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="FSLogix Profile Include List" image="2" changed="$Changed" uid="{$((New-Guid).Guid.ToUpper())}"><Properties action="U" newName="" description="Members of this group are on the include list for dynamic profiles" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupName="FSLogix Profile Include List"/></Group>
</Groups>
"@
            
                    $null = New-Item -Path $GroupXMLGPOFilePath -ItemType File -Value $GroupXMLGPOFileContent -Force
                    <#
                    Set-Content -Path $GroupXMLGPOFilePath -Value $GroupXMLGPOFileContent -Encoding UTF8
                    $GroupXMLGPOFileContent | Out-File $GroupXMLGPOFilePath -Encoding utf8
                    #>
                    #endregion
        
                    #region GPT.INI Management
                    $GPTINIGPOFilePath = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}\GPT.INI" -f $DomainName, $($CurrentHostPoolFSLogixGPO.Id)
                    Write-Verbose -Message "Processing '$GPTINIGPOFilePath' ..."
                    $result = Select-string -Pattern "(Version)=(\d+)" -AllMatches -Path $GPTINIGPOFilePath
                    #Getting current version
                    [int]$VersionNumber = $result.Matches.Groups[-1].Value
                    Write-Verbose -Message "Version Number: $VersionNumber"
                    #Increasing current version
                    $VersionNumber += 2
                    Write-Verbose -Message "New Version Number: $VersionNumber"
                    #Updating file
                    (Get-Content $GPTINIGPOFilePath -Encoding UTF8) -replace "(Version)=(\d+)", "`$1=$VersionNumber" | Set-Content $GPTINIGPOFilePath -Encoding UTF8
                    Write-Verbose -Message $(Get-Content $GPTINIGPOFilePath -Encoding UTF8 | Out-String)
                    #endregion 

                    #region gPCmachineExtensionNames Management
                    #From https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/
                    #[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]
                    #[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
                    Write-Verbose -Message "Processing gPCmachineExtensionNames Management ..."
                    $gPCmachineExtensionNamesToAdd = "[{00000000-0000-0000-0000-000000000000}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}][{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}]"
                    $RegExPattern = $gPCmachineExtensionNamesToAdd -replace "(\W)" , '\$1'
                    $GPOADObject = Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    #if (-not($GPOADObject.gPCmachineExtensionNames.StartsWith($gPCmachineExtensionNamesToAdd)))
                    if ($GPOADObject.gPCmachineExtensionNames -notmatch $RegExPattern) {
                        $GPOADObject | Set-ADObject -Replace @{gPCmachineExtensionNames = $($gPCmachineExtensionNamesToAdd + $GPOADObject.gPCmachineExtensionNames) }
                        #Get-ADObject -LDAPFilter "CN={$($CurrentHostPoolFSLogixGPO.Id.Guid)}" -Properties gPCmachineExtensionNames
                    }
                    #endregion
                }
                #endregion 

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = "rg-avd-$($CurrentHostPool.Name.ToLower())"

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                    Write-Verbose -Message "Creating '$($CurrentHostPoolResourceGroup.ResourceGroupName)' Resource Group ..."
                }
                #endregion

                #region Microsoft Entra ID Management
                if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                    $Tag['DomainType'] = "Active Directory Directory Services"
                }
                else {
                    $Tag['DomainType'] = "Microsoft Entra ID"
                    #region Assign Virtual Machine User Login' RBAC role to the Resource Group
                    # Get the object ID of the user group you want to assign to the application group
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersADGroupName
                    } While (-not($AzADGroup.Id))

                    # Assign users to the application group
                    $parameters = @{
                        ObjectId           = $AzADGroup.Id
                        ResourceGroupName  = $CurrentHostPoolResourceGroupName
                        RoleDefinitionName = 'Virtual Machine User Login'
                        Verbose            = $true
                    }

                    Write-Verbose -Message "Assigning the 'Virtual User Administrator Login' RBAC role to '$CurrentHostPoolDAGUsersADGroupName' AD Group on the '$CurrentHostPoolResourceGroupName' Resource Group ..."
                    $null = New-AzRoleAssignment @parameters
                    #endregion 

                }
                #endregion 

                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                    Write-Verbose -Message "Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group) ..."
                }
                #Registering the Storage Account with your active directory environment under the target
                if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                    if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                        if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                            $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                            $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                            Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                            Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                            Push-Location -Path $env:TEMP\AzFilesHybrid
                            .\CopyToPSPath.ps1
                            Pop-Location
                        }
                        Write-Verbose -Message "Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU ..."
                        Import-Module AzFilesHybrid
                        $null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"
                        $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false
                        #Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -EnableAzureActiveDirectoryKerberosForFile $true

                        #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -ListKerbKey 
                    }
                    # Get the target storage account
                    #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName

                    # List the directory service of the selected service account
                    #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

                    # List the directory domain information if the storage account has enabled AD authentication for file shares
                    #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
                }
                else {
                    #region Enable Kerberos authentication
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#enable-microsoft-entra-kerberos-authentication-for-hybrid-user-accounts
                    #From https://smbtothecloud.com/azure-ad-joined-avd-with-fslogix-aad-kerberos-authentication/
                    $DomainInformation = Get-ADDomain
                    $DomainGuid = $DomainInformation.ObjectGUID.ToString()
                    $DomainName = $DomainInformation.DnsRoot
                    Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -EnableAzureActiveDirectoryKerberosForFile $true -ActiveDirectoryDomainName $domainName -ActiveDirectoryDomainGuid $domainGuid
                    #endregion

                    #region Grant admin consent to the new service principal
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#grant-admin-consent-to-the-new-service-principal
                    # Get the created service principal
                    Do
                    {
                        Start-Sleep -Seconds 60
                        $ServicePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '[Storage Account] $CurrentHostPoolStorageAccountName.file.core.windows.net'"
                    } While ($null -eq $ServicePrincipal)

                    # Grant admin consent to the service principal for the app role
                    Set-AdminConsent -context $AzContext -applicationId $ServicePrincipal.AppId
                    #endregion

                    #region Disable multi-factor authentication on the storage account
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account
                    $AzADGroup = Get-AzADGroup -SearchString $NoMFAAzADGroupName
                    if ($AzADGroup) {
                        Write-Verbose -Message "Adding the '$($ServicePrincipal.DisplayName)' Service Principal as member of the '$($AzADGroup.DisplayName)' Microsoft Entra ID Group ..."
                        $null = Add-AzADGroupMember -TargetGroupObjectId $AzADGroup.Id -MemberObjectId $ServicePrincipal.Id
                    }
                    else {
                        Write-Warning -Message "'$NoMFAAzADGroupName' Entra ID group not found for disabling the MFA for the '$($ServicePrincipal.DisplayName)' Service Principal. PROCEED MANUALLY AND READ THE ARTICLE IN THE NEW BROWSER WINDOWS THAT JUST OPENED BEFORE CONTINUING !!!"
                        Start-Process -FilePath "https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#disable-multi-factor-authentication-on-the-storage-account"
                        Do {
                            $Response = Read-Host -Prompt "Did you disable multi-factor authentication on the storage account ? (Y/N)"

                        } While ($Response -ne "Y")
                    }
                    #endregion

                    #region Configure the clients to retrieve Kerberos tickets
                    #From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-portal#configure-the-clients-to-retrieve-kerberos-tickets
                    #endregion
                }

                $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

                # Save the password so the drive 
                Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager ..."
                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$($CurrentHostPoolStorageAccountKey.Value)`""

                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

                ## Create the private DNS zone. ##
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName' ..."
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #endregion
                Start-Sleep -Seconds 60
                #region Dedicated Share Management
                $FSLogixShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    Write-Verbose -Message "Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                    #Create a share for FSLogix
                    #$CurrentHostPoolStorageAccountShare = New-AzRmStorageShare -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -Name $CurrentHostPoolShareName -AccessTier Hot -QuotaGiB 200
                    $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    $storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    # Mount the share
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region NTFS permissions for FSLogix
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    #region Sample NTFS permissions for FSLogix
                    Write-Verbose -Message "Setting the ACL for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)  ..."
                    $existingAcl = Get-Acl Z:

                    #Disabling inheritance
                    $existingAcl.SetAccessRuleProtection($true, $false)

                    #Remove all inherited permissions from this object.
                    $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }

                    #Add Modify for CREATOR OWNER Group for Subfolders and files only
                    $identity = "CREATOR OWNER"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly           
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Full Control for "Administrators" Group for This folder, subfolders and files
                    $identity = "Administrators"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Modify for "Users" Group for This folder only
                    #$identity = "Users"
                    $identity = $CurrentHostPoolDAGUsersADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::Modify
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Enabling inheritance
                    $existingAcl.SetAccessRuleProtection($false, $true)

                    # Apply the modified access rule to the folder
                    $existingAcl | Set-Acl -Path Z:
                    #endregion

                    #region redirection.xml file management
                    #Creating the redirection.xml file
                    if ($CurrentHostPoolShareName -eq "profiles") {
                        Write-Verbose -Message "Creating the 'redirections.xml' file for the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                        $null = New-Item -Path Z: -Name "redirections.xml" -ItemType "file" -Value $RedirectionsXMLFileContent -Force
                        Write-Verbose -Message "Setting the ACL for the 'redirections.xml' file in the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                        $existingAcl = Get-Acl Z:\redirections.xml
                        #Add Read for "Users" Group for This folder only
                        #$identity = "Users"
                        $identity = $CurrentHostPoolDAGUsersADGroupName
                        $colRights = [System.Security.AccessControl.FileSystemRights]::Read
                        $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
                        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                        $objType = [System.Security.AccessControl.AccessControlType]::Allow
                        # Create a new FileSystemAccessRule object
                        $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                        # Modify the existing ACL to include the new rule
                        $existingAcl.SetAccessRule($AccessRule)
                        $existingAcl | Set-Acl -Path Z:\redirections.xml
                    }
                    #endregion

                    # Unmount the share
                    Remove-PSDrive -Name Z
                    #endregion

                    #region Run a sync with Azure AD
                    Start-MicrosoftEntraIDConnectSync
                    #endregion 

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: FSLogix Contributor = "Storage File Data SMB Share Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixContributorADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)  ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Elevated Contributor = "Storage File Data SMB Share Elevated Contributor"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixElevatedContributorADGroupName
                    } While (-not($AzADGroup.Id))

                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixElevatedContributorADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)  ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC: FSLogix Reader = "Storage File Data SMB Share Reader"
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolFSLogixReaderADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolFSLogixReaderADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group)  ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion
                }
                #endregion
                #endregion
            }
            else {
                Write-Verbose -Message "FSLogix NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region MSIX
            #No EntraID and MSIX : https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            if ((-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) -and ($CurrentHostPool.MSIX)) {
                #region MSIX AD Management
                #region Dedicated HostPool AD group

                #region Dedicated HostPool AD MSIX groups
                $CurrentHostPoolMSIXHostsADGroupName = "$($CurrentHostPool.Name) - $MSIXHosts"
                $CurrentHostPoolMSIXHostsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXHostsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXHostsADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXHostsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                    $CurrentHostPoolMSIXHostsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXHostsADGroupName -SamAccountName $CurrentHostPoolMSIXHostsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXHostsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXShareAdminsADGroupName = "$($CurrentHostPool.Name) - $MSIXShareAdmins"
                $CurrentHostPoolMSIXShareAdminsADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXShareAdminsADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXShareAdminsADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                    $CurrentHostPoolMSIXShareAdminsADGroup = New-ADGroup -Name $CurrentHostPoolMSIXShareAdminsADGroupName -SamAccountName $CurrentHostPoolMSIXShareAdminsADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXShareAdminsADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }

                $CurrentHostPoolMSIXUsersADGroupName = "$($CurrentHostPool.Name) - $MSIXUsers"
                $CurrentHostPoolMSIXUsersADGroup = Get-ADGroup -Filter "Name -eq '$CurrentHostPoolMSIXUsersADGroupName' -and GroupCategory -eq 'Security' -and GroupScope -eq 'Global'" -SearchBase $CurrentHostPoolOU.DistinguishedName
                if (-not($CurrentHostPoolMSIXUsersADGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                    $CurrentHostPoolMSIXUsersADGroup = New-ADGroup -Name $CurrentHostPoolMSIXUsersADGroupName -GroupCategory Security -GroupScope Global -DisplayName $CurrentHostPoolMSIXUsersADGroupName -Path $CurrentHostPoolOU.DistinguishedName -PassThru
                }
                Write-Verbose -Message "Adding the '$CurrentHostPoolDAGUsersADGroupName' AD group to the '$CurrentHostPoolMSIXUsersADGroup' AD Group (under '$($CurrentHostPoolOU.DistinguishedName)') ..."
                $CurrentHostPoolMSIXUsersADGroup | Add-ADGroupMember -Members $CurrentHostPoolDAGUsersADGroupName
                #endregion
                #region Run a sync with Azure AD
                Start-MicrosoftEntraIDConnectSync
                #endregion 
                #endregion
                #endregion 

                #region MSIX Storage Account Management
                #region MSIX Storage Account Name Setup
                $CurrentHostPoolStorageAccountName = "msix{0}" -f $($CurrentHostPool.Name -replace "\W")
                $CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName.Substring(0, [system.math]::min($CurrentHostPoolStorageAccountNameMaxLength, $CurrentHostPoolStorageAccountName.Length)).ToLower()
                #endregion 

                #region Dedicated Host Pool AD GPO Management (1 GPO per Host Pool for setting up the dedicated VHDLocations/CCDLocations value)
                $CurrentHostPoolMSIXGPO = Get-GPO -Name "$($CurrentHostPool.Name) - MSIX Settings" -ErrorAction Ignore
                if (-not($CurrentHostPoolMSIXGPO)) {
                    $CurrentHostPoolMSIXGPO = New-GPO -Name "$($CurrentHostPool.Name) - MSIX Settings"
                    Write-Verbose -Message "Creating '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '($($CurrentHostPoolOU.DistinguishedName))' ..."
                }
                $null = $CurrentHostPoolMSIXGPO | New-GPLink -Target $CurrentHostPoolOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

                #region Turning off automatic updates for MSIX app attach applications
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                Write-Verbose -Message "Turning off automatic updates for MSIX app attach applications for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($PooledDesktopsOU.DistinguishedName)' OU) ..."
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\WindowsStore' -ValueName "AutoDownload" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -ValueName "PreInstalledAppsEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Debug' -ValueName "ContentDeliveryAllowedOverride" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
                #Look for Disable-ScheduledTask ... in the code for the next step(s)
                #endregion

                #region Microsoft Defender Endpoint A/V Exclusions for this HostPool 
                #From https://learn.microsoft.com/en-us/fslogix/overview-prerequisites#configure-antivirus-file-and-folder-exclusions
                Write-Verbose -Message "Setting some 'Microsoft Defender Endpoint A/V Exclusions for this HostPool' related registry values for '$($CurrentHostPoolMSIXGPO.DisplayName)' GPO (linked to '$($CurrentHostPoolOU.DistinguishedName)' OU) ..."
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHD.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.lock" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.meta" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.VHDX.metadata" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                $null = Set-GPRegistryValue -Name $CurrentHostPoolMSIXGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' -ValueName "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\profiles\*.CIM" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Value 0
                #endregion

                #region Dedicated Resource Group Management (1 per HostPool)
                $CurrentHostPoolResourceGroupName = "rg-avd-$($CurrentHostPool.Name.ToLower())"

                $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
                if (-not($CurrentHostPoolResourceGroup)) {
                    Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group ..."
                    $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
                }
                #endregion


                #region Dedicated Storage Account Setup
                $CurrentHostPoolStorageAccount = Get-AzStorageAccount -Name $CurrentHostPoolStorageAccountName -ResourceGroupName $CurrentHostPoolResourceGroupName -ErrorAction Ignore
                if (-not($CurrentHostPoolStorageAccount)) {
                    if (-not(Get-AzStorageAccountNameAvailability -Name $CurrentHostPoolStorageAccountName).NameAvailable) {
                        Write-Error "The storage account name '$CurrentHostPoolStorageAccountName' is not available !" -ErrorAction Stop
                    }
                    $CurrentHostPoolStorageAccount = New-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName -Location $ThisDomainControllerVirtualNetwork.Location -SkuName $SKUName -MinimumTlsVersion TLS1_2 -EnableHttpsTrafficOnly $true
                    Write-Verbose -Message "Creating '$($CurrentHostPoolStorageAccount.StorageAccountName)' Storage Account (in the '$($CurrentHostPoolStorageAccount.ResourceGroupName)' Resource Group) ..."
                }
                #Registering the Storage Account with your active directory environment under the target
                if (-not(Get-ADComputer -Filter "Name -eq '$CurrentHostPoolStorageAccountName'" -SearchBase $CurrentHostPoolOU.DistinguishedName)) {
                    if (-not(Get-Module -Name AzFilesHybrid -ListAvailable)) {
                        $AzFilesHybridZipName = 'AzFilesHybrid.zip'
                        $OutFile = Join-Path -Path $env:TEMP -ChildPath $AzFilesHybridZipName
                        Start-BitsTransfer https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -destination $OutFile
                        Expand-Archive -Path $OutFile -DestinationPath $env:TEMP\AzFilesHybrid -Force
                        Push-Location -Path $env:TEMP\AzFilesHybrid
                        .\CopyToPSPath.ps1
                        Pop-Location
                    }
                    Write-Verbose -Message "Registering the Storage Account '$CurrentHostPoolStorageAccountName' with your AD environment (under '$($CurrentHostPoolOU.DistinguishedName)') OU ..."
                    Import-Module AzFilesHybrid
                    $null = New-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -KeyName "kerb1"
                    $null = Join-AzStorageAccountForAuth -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -DomainAccountType "ComputerAccount" -OrganizationUnitDistinguishedName $CurrentHostPoolOU.DistinguishedName -Confirm:$false
                    #$KerbKeys = Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -ListKerbKey 
                }

                # Get the target storage account
                #$storageaccount = Get-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName

                # List the directory service of the selected service account
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions

                # List the directory domain information if the storage account has enabled AD authentication for file shares
                #$CurrentHostPoolStorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties

                $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }

                # Save the password so the drive 
                Write-Verbose -Message "Saving the credentials for accessing to the Storage Account '$CurrentHostPoolStorageAccountName' in the Windows Credential Manager ..."
                Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$CurrentHostPoolStorageAccountName`" /pass:`"$($CurrentHostPoolStorageAccountKey.Value)`""

                #region Private endpoint for Storage Setup
                #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
                #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
                #From https://ystatit.medium.com/azure-key-vault-with-azure-service-endpoints-and-private-link-part-1-bcc84b4c5fbc
                ## Create the private endpoint connection. ## 

                Write-Verbose -Message "Creating the Private Endpoint for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolStorageAccountName -replace "\W")
                $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolStorageAccount.Id).GroupId | Where-Object -FilterScript { $_ -match "file" }
                $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolStorageAccount.Id -GroupId $GroupId
                $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

                ## Create the private DNS zone. ##
                Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZoneName = "privatelink.$GroupId.$StorageEndpointSuffix"
                $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
                if ($null -eq $PrivateDnsZone) {
                    Write-Verbose -Message "Creating the Private DNS Zone for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                    $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
                }

                $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
                $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
                if ($null -eq $PrivateDnsVirtualNetworkLink) {
                    $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                    ## Create a DNS network link. ##
                    Write-Verbose -Message "Creating the Private DNS VNet Link for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                    $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
                }


                ## Configure the DNS zone. ##
                Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for the Storage Account '$CurrentHostPoolStorageAccountName' ..."
                $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

                ## Create the DNS zone group. ##
                Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

                #Storage Account - Disabling Public Access
                #From https://www.jorgebernhardt.com/azure-storage-public-access/
                #From https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-powershell#change-the-default-network-access-rule
                #From https://github.com/adstuart/azure-privatelink-dns-microhack
                Write-Verbose -Message "Disabling the Public Access for the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = Set-AzStorageAccount -ResourceGroupName $CurrentHostPoolResourceGroupName -Name $CurrentHostPoolStorageAccountName -PublicNetworkAccess Disabled
                #(Get-AzStorageAccount -Name $CurrentHostPoolResourceGroupName -ResourceGroupName $CurrentHostPoolStorageAccountName ).AllowBlobPublicAccess
                #endregion
                #endregion
                Start-Sleep -Seconds 60
                $MSIXDemoPackages = $null
                #region Dedicated Share Management
                $MSIXShareName | ForEach-Object -Process { 
                    $CurrentHostPoolShareName = $_
                    #Create a share for MSIX
                    Write-Verbose -Message "Creating the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                    #$CurrentHostPoolStorageShare = New-AzRmStorageShare -ResourceGroupName $CurrentHostPoolResourceGroupName -StorageAccountName $CurrentHostPoolStorageAccountName -Name $CurrentHostPoolShareName -AccessTier Hot -QuotaGiB 200
                    $CurrentHostPoolStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $CurrentHostPoolResourceGroupName -AccountName $CurrentHostPoolStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }
                    $storageContext = New-AzStorageContext -StorageAccountName $CurrentHostPoolStorageAccountName -StorageAccountKey $CurrentHostPoolStorageAccountKey.Value
                    $CurrentHostPoolStorageAccountShare = New-AzStorageShare -Name $CurrentHostPoolShareName -Context $storageContext

                    # Copying the  Demo MSIX Packages from my dedicated GitHub repository
                    $MSIXDemoPackages = Copy-MSIXDemoAppAttachPackage -Destination "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    # Mount the share
                    $null = New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$CurrentHostPoolStorageAccountName.file.$StorageEndpointSuffix\$CurrentHostPoolShareName"

                    #region NTFS permissions for MSIX
                    #From https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #From https://blue42.net/windows/changing-ntfs-security-permissions-using-powershell/
                    Write-Verbose -Message "Setting the ACL on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                    $existingAcl = Get-Acl Z:
                    $existingAcl.Access | ForEach-Object -Process { $null = $existingAcl.RemoveAccessRule($_) }
                    #Disabling inheritance
                    $existingAcl.SetAccessRuleProtection($true, $false)

                    #Add Full Control for Administrators Group for This folder, subfolders and files
                    $identity = "BUILTIN\Administrators"
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add Full Control for MSIXShareAdmins Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXShareAdminsADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add "Read And Execute" for MSIXUsers Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXUsersADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None           
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Add "Read And Execute" for MSIXHosts Group for This folder, subfolders and files
                    $identity = $CurrentHostPoolMSIXHostsADGroupName
                    $colRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
                    $objType = [System.Security.AccessControl.AccessControlType]::Allow
                    # Create a new FileSystemAccessRule object
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($identity, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                    # Modify the existing ACL to include the new rule
                    $existingAcl.SetAccessRule($AccessRule)

                    #Enabling inheritance
                    $existingAcl.SetAccessRuleProtection($false, $true)

                    # Apply the modified access rule to the folder
                    $existingAcl | Set-Acl -Path Z:
                    #endregion

                    # Unmount the share
                    Remove-PSDrive -Name Z

                    #region RBAC Management
                    #Constrain the scope to the target file share
                    $SubscriptionId = $AzContext.Subscription.Id
                    $Scope = "/subscriptions/$SubscriptionId/resourceGroups/$CurrentHostPoolResourceGroupName/providers/Microsoft.Storage/storageAccounts/$CurrentHostPoolStorageAccountName/fileServices/default/fileshares/$CurrentHostPoolShareName"

                    #region Setting up the file share with right RBAC: MSIX Hosts & MSIX Users = "Storage File Data SMB Share Contributor" + MSIX Share Admins = Storage File Data SMB Share Elevated Contributor
                    #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach-file-share#how-to-set-up-the-file-share
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXHostsADGroupName
                    } While (-not($AzADGroup.Id))

                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXHostsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }

                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXUsersADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to 'CurrentPooledHostPoolMSIXUsersADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName'  (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #region Setting up the file share with right RBAC
                    #Get the name of the custom role
                    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
                    #Assign the custom role to the target identity with the specified scope.
                    Do {
                        Start-MicrosoftEntraIDConnectSync
                        Write-Verbose -Message "Sleeping 10 seconds ..."
                        Start-Sleep -Seconds 10
                        $AzADGroup = $null
                        $AzADGroup = Get-AzADGroup -SearchString $CurrentHostPoolMSIXShareAdminsADGroupName
                    } While (-not($AzADGroup.Id))
                    if (-not(Get-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope)) {
                        Write-Verbose -Message "Assigning the '$($FileShareContributorRole.Name)' RBAC role to '$CurrentHostPoolMSIXShareAdminsADGroupName' AD Group on the Share '$CurrentHostPoolShareName' in the Storage Account '$CurrentHostPoolStorageAccountName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                        $null = New-AzRoleAssignment -ObjectId $AzADGroup.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $Scope
                    }
                    #endregion

                    #endregion
                }
                #endregion
                #endregion
            
                #endregion

            }
            else {
                Write-Verbose -Message "MSIX NOT enabled for '$($CurrentHostPool.Name)' HostPool"
            }
            #endregion

            #region Dedicated Resource Group Management (1 per HostPool)
            $CurrentHostPoolResourceGroupName = "rg-avd-$($CurrentHostPool.Name.ToLower())"

            $CurrentHostPoolResourceGroup = Get-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -ErrorAction Ignore
            if (-not($CurrentHostPoolResourceGroup)) {
                Write-Verbose -Message "Creating '$CurrentHostPoolResourceGroupName' Resource Group ..."
                $CurrentHostPoolResourceGroup = New-AzResourceGroup -Name $CurrentHostPoolResourceGroupName -Location $CurrentHostPool.Location -Force
            }
            #endregion

            #region Key Vault
            #region Key Vault Name Setup
            $CurrentHostPoolKeyVaultName = "kv{0}" -f $($CurrentHostPool.Name -replace "\W")
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.Substring(0, [system.math]::min($CurrentHostPoolKeyVaultNameMaxLength, $CurrentHostPoolKeyVaultName.Length)).ToLower()
            $CurrentHostPoolKeyVaultName = $CurrentHostPoolKeyVaultName.ToLower()
            #endregion 

            #region Dedicated Key Vault Setup
            $CurrentHostPoolKeyVault = Get-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ErrorAction Ignore
            if (-not($CurrentHostPoolKeyVault)) {
                if (-not(Test-AzKeyVaultNameAvailability -Name $CurrentHostPoolKeyVaultName).NameAvailable) {
                    Write-Error "The key vault name '$CurrentHostPoolKeyVaultName' is not available !" -ErrorAction Stop
                }
                Write-Verbose -Message "Creating '$CurrentHostPoolKeyVaultName' Key Vault (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $CurrentHostPoolKeyVault = New-AzKeyVault -ResourceGroupName $CurrentHostPoolResourceGroupName -VaultName $CurrentHostPoolKeyVaultName -Location $ThisDomainControllerVirtualNetwork.Location -EnabledForDiskEncryption -SoftDeleteRetentionInDays 7
            }
            #endregion

            #region Private endpoint for Key Vault Setup
            #From https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-powershell?tabs=dynamic-ip#create-a-private-endpoint
            #From https://www.jorgebernhardt.com/private-endpoint-azure-key-vault-powershell/
            ## Create the private endpoint connection. ## 

            $PrivateEndpointName = "pep{0}" -f $($CurrentHostPoolKeyVaultName -replace "\W")
            $GroupId = (Get-AzPrivateLinkResource -PrivateLinkResourceId $CurrentHostPoolKeyVault.ResourceId).GroupId
            $PrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection -Name $PrivateEndpointName -PrivateLinkServiceId $CurrentHostPoolKeyVault.ResourceId -GroupId $GroupId
            Write-Verbose -Message "Creating the Private Endpoint for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $PrivateEndpoint = New-AzPrivateEndpoint -Name $PrivateEndpointName -ResourceGroupName $CurrentHostPoolResourceGroupName -Location $ThisDomainControllerVirtualNetwork.Location -Subnet $ThisDomainControllerSubnet -PrivateLinkServiceConnection $PrivateLinkServiceConnection -CustomNetworkInterfaceName $("{0}-nic" -f $PrivateEndpointName) -Force

            ## Create the private DNS zone. ##
            $PrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
            $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName -ErrorAction Ignore
            if ($null -eq $PrivateDnsZone) {
                Write-Verbose -Message "Creating the Private DNS Zone for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsZoneName
            }

            $PrivateDnsVirtualNetworkLinkName = "pdvnl{0}" -f $($ThisDomainControllerVirtualNetwork.Name -replace "\W")
            $PrivateDnsVirtualNetworkLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -ErrorAction Ignore
            if ($null -eq $PrivateDnsVirtualNetworkLink) {
                $ThisDomainControllerVirtualNetworkId = [string]::Join("/", $split[0..($split.Count - 3)])
                ## Create a DNS network link. ##
                Write-Verbose -Message "Creating the Private DNS VNet Link for the Key Vault '$CurrentHostPoolKeyVaultName' (in the '$($ThisDomainController.ResourceGroupName)' Resource Group) ..."
                $PrivateDnsVirtualNetworkLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $ThisDomainController.ResourceGroupName -Name $PrivateDnsVirtualNetworkLinkName -ZoneName $PrivateDnsZone.Name -VirtualNetworkId $ThisDomainControllerVirtualNetworkId
            }


            ## Configure the DNS zone. ##
            Write-Verbose -Message "Creating the DNS Zone Configuration of the Private Dns Zone Group for Key Vault '$CurrentHostPoolKeyVaultName' ..."
            $PrivateDnsZoneConfig = New-AzPrivateDnsZoneConfig -Name $PrivateDnsZone.Name -PrivateDnsZoneId $PrivateDnsZone.ResourceId

            ## Create the DNS zone group. ##
            Write-Verbose -Message "Creating the Private DNS Zone Group in the Specified Private Endpoint '$PrivateEndpointName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $PrivateDnsZoneGroup = New-AzPrivateDnsZoneGroup -ResourceGroupName $CurrentHostPoolResourceGroupName -PrivateEndpointName $PrivateEndpointName -Name 'default' -PrivateDnsZoneConfig $PrivateDnsZoneConfig -Force

            #Key Vault - Disabling Public Access
            Write-Verbose -Message "Disabling the Public Access for the Key Vault'$CurrentHostPoolKeyVaultName' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $null = Update-AzKeyVault -VaultName $CurrentHostPoolKeyVaultName -ResourceGroupName $CurrentHostPoolResourceGroupName -PublicNetworkAccess "Disabled" 
            #endregion

            #endregion

            #Microsoft Entra ID
            if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "targetisaadjoined:i:1;redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
            }
            #Active Directory Directory Services
            else {
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                $CustomRdpProperty = "redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:"
            }

            #region Host Pool Setup
            $RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
            $parameters = @{
                Name                  = $CurrentHostPool.Name
                ResourceGroupName     = $CurrentHostPoolResourceGroupName
                HostPoolType          = 'Pooled'
                LoadBalancerType      = 'BreadthFirst'
                PreferredAppGroupType = 'Desktop'
                MaxSessionLimit       = $CurrentHostPool.MaxSessionLimit
                Location              = $CurrentHostPool.Location
                StartVMOnConnect      = $true
                # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
                # No RDP redirection for COM ports, Local Drives and printers.
                ExpirationTime        = $RegistrationInfoExpirationTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                CustomRdpProperty     = $CustomRdpProperty
                Tag                   = $Tag
                Verbose               = $true
            }

            Write-Verbose -Message "Creating the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdHostPool = New-AzWvdHostPool @parameters
            Write-Verbose -Message "Creating Registration Token (Expiration: '$RegistrationInfoExpirationTime') for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $CurrentHostPoolResourceGroupName -HostPoolName $CurrentHostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue

            #region Set up Private Link with Azure Virtual Desktop
            #TODO: https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-setup?tabs=powershell%2Cportal-2#enable-the-feature
            #endregion

            #region Use Azure Firewall to protect Azure Virtual Desktop deployments
            #TODO: https://learn.microsoft.com/en-us/training/modules/protect-virtual-desktop-deployment-azure-firewall/
            #endregion
            #endregion

            #region Desktop Application Group Setup
            $parameters = @{
                Name                 = "{0}-DAG" -f $CurrentHostPool.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
                Location             = $CurrentHostPool.Location
                HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                ApplicationGroupType = 'Desktop'
                ShowInFeed           = $true
                Verbose              = $true
            }

            Write-Verbose -Message "Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @parameters

            Write-Verbose -Message "Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) to 'Full Desktop' ..."
            $parameters = @{
                ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName    = $CurrentHostPoolResourceGroupName
            }
            Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName "Full Desktop"

            #region Assign 'Desktop Virtualization User' RBAC role to application groups
            # Get the object ID of the user group you want to assign to the application group
            Do {
                Start-MicrosoftEntraIDConnectSync
                Write-Verbose -Message "Sleeping 10 seconds ..."
                Start-Sleep -Seconds 10
                $AzADGroup = $null
                $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolDAGUsersADGroupName
            } While (-not($AzADGroup.Id))

            # Assign users to the application group
            $parameters = @{
                ObjectId           = $AzADGroup.Id
                ResourceName       = $CurrentAzDesktopApplicationGroup.Name
                ResourceGroupName  = $CurrentHostPoolResourceGroupName
                RoleDefinitionName = 'Desktop Virtualization User'
                ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                Verbose            = $true
            }

            Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentHostPoolDAGUsersADGroupName' AD Group on the Desktop Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $null = New-AzRoleAssignment @parameters
            #endregion 

            #endregion

            #region Remote Application Group Setup
            #No EntraID and RemoteApp : https://learn.microsoft.com/en-us/azure/virtual-desktop/azure-ad-joined-session-hosts#known-limitations
            if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                $parameters = @{
                    Name                 = "{0}-RAG" -f $CurrentHostPool.Name
                    ResourceGroupName    = $CurrentHostPoolResourceGroupName
                    Location             = $CurrentHostPool.Location
                    HostPoolArmPath      = $CurrentAzWvdHostPool.Id
                    ApplicationGroupType = 'RemoteApp'
                    ShowInFeed           = $true
                    Verbose              = $true
                }

                Write-Verbose -Message "Creating the Remote Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $CurrentAzRemoteApplicationGroup = New-AzWvdApplicationGroup @parameters

                #region Assign required RBAC role to application groups
                # Get the object ID of the user group you want to assign to the application group
                Do {
                    Start-MicrosoftEntraIDConnectSync
                    Write-Verbose -Message "Sleeping 10 seconds ..."
                    Start-Sleep -Seconds 10
                    $AzADGroup = $null
                    $AzADGroup = Get-AzADGroup -DisplayName $CurrentHostPoolRAGUsersADGroupName
                } While (-not($AzADGroup.Id))

                # Assign users to the application group
                $parameters = @{
                    ObjectId           = $AzADGroup.Id
                    ResourceName       = $CurrentAzRemoteApplicationGroup.Name
                    ResourceGroupName  = $CurrentHostPoolResourceGroupName
                    RoleDefinitionName = 'Desktop Virtualization User'
                    ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
                    Verbose            = $true
                }

                Write-Verbose -Message "Assigning the 'Desktop Virtualization User' RBAC role to '$CurrentHostPoolRAGUsersADGroupName' AD Group on the Remote Application Group (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzRoleAssignment @parameters
            }
            #endregion 

            #endregion

            #region Workspace Setup
            if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                $ApplicationGroupReference = $CurrentAzRemoteApplicationGroup.Id, $CurrentAzDesktopApplicationGroup.Id
            }
            else {
                #No EntraID and RemoteApp : https://learn.microsoft.com/en-us/azure/virtual-desktop/azure-ad-joined-session-hosts#known-limitations
                $ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
            }

            $Options = $CurrentHostPool.Type, $CurrentHostPool.IdentityProvider
            if ($CurrentHostPool.FSLogix) {
                $Options += 'FSLogix'
            }
            if ($CurrentHostPool.MSIX) {
                $Options += 'MSIX'
            }
            $FriendlyName = "ws-{0} ({1})" -f $CurrentHostPool.Name,$($Options -join ', ')
            $parameters = @{
                Name                      = "ws-{0}" -f $CurrentHostPool.Name
                FriendlyName              = $FriendlyName
                ResourceGroupName         = $CurrentHostPoolResourceGroupName
                ApplicationGroupReference = $ApplicationGroupReference
                Location                  = $CurrentHostPool.Location
                Verbose                   = $true
            }

            Write-Verbose -Message "Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $CurrentAzWvdWorkspace = New-AzWvdWorkspace @parameters
            #endregion

            #region Adding Session Hosts to the Host Pool
            $Status = @{ $true = "Enabled"; $false = "Disabled" }
            if (-not([String]::IsNullOrEmpty($CurrentHostPool.VMSourceImageId))) {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -VMSourceImageId $CurrentHostPool.VMSourceImageId -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -AsJob #:$AsJob
            }
            else {
                #We propagate the AsJob context to the child function
                Add-AzAvdSessionHost -HostPoolId $CurrentAzWvdHostPool.Id -NamePrefix $CurrentHostPool.NamePrefix -VMNumberOfInstances $CurrentHostPool.VMNumberOfInstances -KeyVault $CurrentHostPool.KeyVault -RegistrationInfoToken $RegistrationInfoToken.Token -DomainName $DomainName -OUPath $CurrentHostPoolOU.DistinguishedName -VMSize $CurrentHostPool.VMSize -ImagePublisherName $CurrentHostPool.ImagePublisherName -ImageOffer $CurrentHostPool.ImageOffer -ImageSku $CurrentHostPool.ImageSku -Tag $Tag -IsMicrosoftEntraIdJoined:$CurrentHostPool.IsMicrosoftEntraIdJoined() -Spot:$CurrentHostPool.Spot -HibernationEnabled:$CurrentHostPool.HibernationEnabled -AsJob #:$AsJob
            }
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
            #endregion 

            if (($CurrentHostPool.IsMicrosoftEntraIdJoined()) -and ($CurrentHostPool.FSLogix)) {
                foreach ($CurrentSessionHostName in $SessionHostNames) {
                    #region Configure the clients to retrieve Kerberos tickets
                    # From https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable?tabs=azure-powershell#configure-the-clients-to-retrieve-kerberos-tickets
                    $ScriptString = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "CloudKerberosTicketRetrievalEnabled" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 1'
                    # Run PowerShell script on the VM
                    Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    #endregion

                    #region Configure FSLogix
                    # Run PowerShell script on the VM
                    $URI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/Set-FSLogixRegistryItemProperty.ps1"
                    $ScriptPath = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $URI -Leaf)
                    Invoke-WebRequest -Uri $URI -UseBasicParsing -OutFile $ScriptPath
                    Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath -Parameter @{CurrentHostPoolStorageAccountName = $CurrentHostPoolStorageAccountName }
                    Remove-Item -Path $ScriptPath -Force
                    #endregion

                    #region Excluding Administrators from FSLogix
                    $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                    $ScriptString = "Add-LocalGroupMember -Group 'FSLogix Profile Exclude List' -Member $LocalAdminUserName -ErrorAction Ignore; Add-LocalGroupMember -Group 'FSLogix ODFC Exclude List' -Member $LocalAdminUserName -ErrorAction Ignore"
                    # Run PowerShell script on the VM
                    Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    #endregion

                    <#
                    #region Configure the clients to disable FSLogix
                    $ScriptString = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name 'Enabled' -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -Value 0"
                    # Run PowerShell script on the VM
                    Invoke-AzVMRunCommand -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostName -CommandId 'RunPowerShellScript' -ScriptString $ScriptString
                    #endregion
                    #>
                }
            }

            #region Restarting the Session Hosts
            $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
            }
            $Jobs | Wait-Job | Out-Null
            $Jobs | Remove-Job -Force
            #endregion 

            #region MSIX
            #No EntraID and MSIX : https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-overview?pivots=msix-app-attach#identity-providers
            if ((-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) -and ($CurrentHostPool.MSIX)) {
                #Adding the Session Hosts to the dedicated ADGroup for MSIX 
                #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
                #$SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                #Adding Session Hosts to the dedicated AD MSIX Host group
                Write-Verbose -Message "Adding the Session Hosts Session Hosts to the '$($CurrentHostPoolMSIXHostsADGroup.Name)' AD Group ..."
                $CurrentHostPoolMSIXHostsADGroup | Add-ADGroupMember -Members $($SessionHostNames | Get-ADComputer).DistinguishedName
                Start-MicrosoftEntraIDConnectSync
    
                #Copying, Installing the MSIX Demo PFX File(s) (for signing MSIX Packages) on Session Host(s)
                Write-Verbose -Message "`$CurrentHostPool : $($CurrentHostPool.Name)"
                Write-Verbose -Message "`$SessionHostNames : $($SessionHostNames -join ',')"
                $result = Wait-PSSession -ComputerName $SessionHostNames -Verbose
                Write-Verbose -Message "`$result: $result"
                Copy-MSIXDemoPFXFile -ComputerName $SessionHostNames

                #region Disabling the "\Microsoft\Windows\WindowsUpdate\Scheduled Start" Scheduled Task on Session Host(s)
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-azure-portal#turn-off-automatic-updates-for-msix-app-attach-applications
                $null = Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Scheduled Start" -CimSession $SessionHostNames
                #endregion 

                #region Restarting the Session Hosts
                $Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Restart-AzVM -Name $CurrentSessionHostName -ResourceGroupName $CurrentHostPoolResourceGroupName -Confirm:$false -AsJob
                }
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
                #endregion 

                #region Adding the MSIX package(s) to the Host Pool
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
                foreach ($CurrentMSIXDemoPackage in $MSIXDemoPackages) {
                    $obj = $null
                    While ($null -eq $obj) {
                        Write-Verbose -Message "Expanding MSIX Image '$CurrentMSIXDemoPackage' ..."
                        $MyError = $null
                        #$obj = Expand-AzAvdMsixImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage
                        $obj = Expand-AzWvdMsixImage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Uri $CurrentMSIXDemoPackage -ErrorAction Ignore -ErrorVariable MyError
                        if (($null -eq $obj)) {
                            Write-Verbose -Message "Error Message: $($MyError.Exception.Message)"
                            Write-Verbose -Message "Sleeping 30 seconds ..."
                            Start-Sleep -Seconds 30
                        }
                    }

                    $DisplayName = "{0} v{1}" -f $obj.PackageApplication.FriendlyName, $obj.Version
                    Write-Verbose -Message "Adding MSIX Image '$CurrentMSIXDemoPackage' as '$DisplayName'..."
                    New-AzWvdMsixPackage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -PackageAlias $obj.PackageAlias -DisplayName $DisplayName -ImagePath $CurrentMSIXDemoPackage -IsActive:$true
                    #Get-AzWvdMsixPackage -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Where-Object {$_.PackageFamilyName -eq $obj.PackageFamilyName}
                }
                #endregion 

                #region Publishing MSIX apps to application groups
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell#publish-msix-apps-to-an-application-group
                #Publishing MSIX application to a desktop application group
                $SubscriptionId = $AzContext.Subscription.Id
                $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzDesktopApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0
            
                #Publishing MSIX application to a RemoteApp application group
                $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $obj.PackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -MsixPackageFamilyName $obj.PackageFamilyName -CommandLineSetting 0 -MsixPackageApplicationId $obj.PackageApplication.AppId
                #endregion 
            }
            else {
                Write-Warning "No MSIX configuration for the Host Pool '$($CurrentHostPool.Name)' HostPool ..."
            }
            #endregion

            #region Adding Some Remote Apps
            #No EntraID and RemoteApp : https://learn.microsoft.com/en-us/azure/virtual-desktop/azure-ad-joined-session-hosts#known-limitations
            if (-not($CurrentHostPool.IsMicrosoftEntraIdJoined())) {
                #$RemoteApps = "Edge","Excel"
                #$SelectedAzWvdStartMenuItem = (Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Where-Object -FilterScript {$_.Name -match $($RemoteApps -join '|')} | Select-Object -Property *)
            
                #2 Random Applications
                $result = Wait-AzVMPowerShell -HostPoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName -Verbose
                $SelectedAzWvdStartMenuItem = Get-AzWvdStartMenuItem -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -ResourceGroupName $CurrentHostPoolResourceGroupName | Get-Random -Count 2

                $AzWvdApplications = foreach ($CurrentAzWvdStartMenuItem in $SelectedAzWvdStartMenuItem) {
                    #$Name = $CurrentAzWvdStartMenuItem.Name -replace "(.*)/"
                    $Name = $CurrentAzWvdStartMenuItem.Name -replace "$($CurrentAzRemoteApplicationGroup.Name)/"
                    try {
                        New-AzWvdApplication -AppAlias $CurrentAzWvdStartMenuItem.appAlias -GroupName $CurrentAzRemoteApplicationGroup.Name -Name $Name -ResourceGroupName $CurrentHostPoolResourceGroupName -CommandLineSetting DoNotAllow
                    }
                    catch {
                        Write-Warning -Message "Unable to add '$($CurrentAzWvdStartMenuItem.appAlias)' application as Remoteapp in the '$($CurrentAzRemoteApplicationGroup.Name)' Application Group ..."
                    }
                }
            }
            #endregion

            #region Log Analytics WorkSpace Setup : Monitor and manage performance and health
            #From https://learn.microsoft.com/en-us/training/modules/monitor-manage-performance-health/3-log-analytics-workspace-for-azure-monitor
            #From https://www.rozemuller.com/deploy-azure-monitor-for-windows-virtual-desktop-automated/#update-25-03-2021
            $LogAnalyticsWorkSpaceName = "log{0}" -f $($CurrentAzWvdHostPool.Name -replace "\W")
            Write-Verbose -Message "Creating the Log Analytics WorkSpace '$($LogAnalyticsWorkSpaceName)' (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $CurrentHostPool.Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $CurrentHostPoolResourceGroupName -Force
            #Enabling Diagnostics Setting for the HostPool
            Write-Verbose -Message "Enabling Diagnostics Setting for the HostPool for the '$($CurrentAzWvdHostPool.Name)' Host Pool (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
            $HostPoolDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Connection", "HostRegistration", "AgentHealthStatus"
            #$HostPoolDiagnosticSetting
            #Enabling Diagnostics Setting for the WorkSpace
            Write-Verbose -Message "Enabling Diagnostics Setting for the HostPool for the  '$($CurrentAzWvdWorkspace.Name)' Work Space ..."
            $WorkSpaceDiagnosticSetting = Set-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Enabled $true -Category "Checkpoint", "Error", "Management", "Feed"
            #$WorkSpaceDiagnosticSetting
            $EventLogs = @(
                @{EventLogName = 'Application' ; CollectInformation = $false; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Admin' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-FSLogix-Apps/Operational' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' ; CollectInformation = $true; CollectWarnings = $true; CollectErrors = $true }
                @{EventLogName = 'System' ; CollectInformation = $false; CollectWarnings = $true; CollectErrors = $true }
            )
            foreach ($CurrentEventLog in $EventLogs) {
                $Name = $CurrentEventLog.EventLogName -replace "\W", "-"
                Write-Verbose -Message "Enabling the '$($CurrentEventLog.EventLogName)' EventLog in the '$($LogAnalyticsWorkSpace.Name)' Log Analytics WorkSpace (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsEventDataSource -ResourceGroupName $CurrentHostPoolResourceGroupName -WorkspaceName $($LogAnalyticsWorkSpace.Name) -Name $Name @CurrentEventLog -Force
            }
            
            $PerformanceCouters = @(
                @{ObjectName = 'LogicalDisk'; CounterName = '% Free Space'; InstanceName = 'C:'; IntervalSeconds = 60 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = 'C:'; IntervalSeconds = 60 }
                @{ObjectName = 'LogicalDisk'; CounterName = 'Current Disk Queue Length'; InstanceName = 'C:'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Available Mbytes'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Page Faults/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = 'Pages/sec'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Memory'; CounterName = '% Committed Bytes In Use'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Read'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Transfer'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk sec/Write'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'PhysicalDisk'; CounterName = 'Avg. Disk Queue Length'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Processor Information'; CounterName = '% Processor Time'; InstanceName = '_Total'; IntervalSeconds = 30 }
                @{ObjectName = 'RemoteFX Network'; CounterName = 'Current TCP RTT'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'RemoteFX Network'; CounterName = 'Current UDP Bandwidth'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Active Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Inactive Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'Terminal Services'; CounterName = 'Total Sessions'; InstanceName = '*'; IntervalSeconds = 60 }
                @{ObjectName = 'User Input Delay per Process'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
                @{ObjectName = 'User Input Delay per Session'; CounterName = 'Max Input Delay'; InstanceName = '*'; IntervalSeconds = 30 }
            )
            foreach ($CurrentPerformanceCouter in $PerformanceCouters) {
                $Name = $('{0}-{1}-{2}' -f $CurrentPerformanceCouter.ObjectName, $CurrentPerformanceCouter.CounterName, $CurrentPerformanceCouter.InstanceName) -replace "\W", "-"
                Write-Verbose -Message "Enabling '$($CurrentPerformanceCouter.CounterName)' Performance Counter in the '$($LogAnalyticsWorkSpace.Name)' Log Analytics WorkSpace (in the '$CurrentHostPoolResourceGroupName' Resource Group) ..."
                $null = New-AzOperationalInsightsWindowsPerformanceCounterDataSource -ResourceGroupName $CurrentHostPoolResourceGroupName -WorkspaceName $($LogAnalyticsWorkSpace.Name) -Name $Name @CurrentPerformanceCouter -Force
            }
            #endregion

            #region install Log Analytics Agent on Virtual Machine(s)
            #$SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $CurrentHostPoolResourceGroupName
            if (-not([string]::IsNullOrEmpty($SessionHosts.ResourceId))) {
                $SessionHostVMs = $SessionHosts.ResourceId | Get-AzVM
                $LogAnalyticsWorkSpaceKey = ($LogAnalyticsWorkSpace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
                $PublicSettings = @{ "workspaceId" = $LogAnalyticsWorkSpace.CustomerId }
                $ProtectedSettings = @{ "workspaceKey" = $LogAnalyticsWorkSpaceKey }
                $Jobs = foreach ($CurrentSessionHostVM in $SessionHostVMs) {
                    Write-Verbose -Message "Install Log Analytics Agent on the '$($CurrentSessionHostVM.Name )' Virtual Machine (in the '$CurrentHostPoolResourceGroupName' Resource Group) (As A Job) ..."
                    Set-AzVMExtension -ExtensionName "MicrosoftMonitoringAgent" -ResourceGroupName $CurrentHostPoolResourceGroupName -VMName $CurrentSessionHostVM.Name -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -Settings $PublicSettings -TypeHandlerVersion "1.0" -ProtectedSettings $ProtectedSettings -Location $ThisDomainControllerVirtualNetwork.Location -AsJob
                }
                Write-Verbose -Message "Waiting all jobs completes ..."
                $Jobs | Wait-Job | Out-Null
                $Jobs | Remove-Job -Force
            }
            #endregion

            #region Enabling VM insights by using PowerShell
            $TemplateUri = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/DCR/template.json"
            $DataCollectionRulesName = "MSVMI-{0}" -f $LogAnalyticsWorkSpace.Name
            $TemplateParameterObject = @{
                dataCollectionRules_name = $DataCollectionRulesName
                workspaces_externalid    = $LogAnalyticsWorkSpace.ResourceId
            }
            #region Submitting the template
            Write-Verbose -Message "Starting Resource Group Deployment from '$TemplateUri' ..."
            $ResourceGroupDeployment = New-AzResourceGroupDeployment -ResourceGroupName $CurrentHostPoolResourceGroupName -TemplateUri $TemplateUri -TemplateParameterObject $TemplateParameterObject
            #endregion

            #region Adding Data Collection Rule Association for every Session Host
            $DataCollectionRule = Get-AzDataCollectionRule -ResourceGroupName $CurrentHostPoolResourceGroupName -RuleName $DataCollectionRulesName
            foreach ($CurrentSessionHost in $SessionHosts) {                
                $AssociationName = "dcr-{0}" -f $($CurrentSessionHost.ResourceId -replace ".*/").ToLower()
                Write-Verbose -Message "`$AssociationName: $AssociationName"
                New-AzDataCollectionRuleAssociation -TargetResourceId $CurrentSessionHost.ResourceId -AssociationName $AssociationName -RuleId $DataCollectionRule.Id
            }
            #endregion
            #endregion
            $EndTime = Get-Date
            $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
            Write-Host -Object "'$($CurrentHostPool.Name)' Setup Processing Time: $($TimeSpan.ToString())"
        }    
    }
    end {
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall Pooled HostPool Setup Processing Time: $($TimeSpan.ToString())"
    }
}

function New-AzAvdHostPoolSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [alias('Name')]
        [HostPool[]]$HostPool,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        $NoMFAAzADGroupName = "No-MFA Users",

        [switch] $AsJob
    )

    begin {
        $StartTime = Get-Date
        $AzContext = Get-AzContext
        <#
        $StorageEndpointSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty StorageEndpointSuffix
        $AzureKeyVaultDnsSuffix = $AzContext | Select-Object -ExpandProperty Environment | Select-Object -ExpandProperty AzureKeyVaultDnsSuffix
        $AzureKeyVaultDnsSuffix2 = "vaultcore.azure.net"
        $DnsServerConditionalForwarderZones = $StorageEndpointSuffix, $AzureKeyVaultDnsSuffix, $AzureKeyVaultDnsSuffix2
        #>
        $DnsServerConditionalForwarderZones = "file.core.windows.net", "vaultcore.azure.net", "vault.azure.net"
        #region DNS Conditional Forwarders
        foreach ($CurrentDnsServerConditionalForwarderZone in $DnsServerConditionalForwarderZones) {
            if ($null -eq (Get-DnsServerZone -Name $CurrentDnsServerConditionalForwarderZone -ErrorAction Ignore)) {
                #Adding Dns Server Conditional Forwarder Zone
                Write-Verbose -Message "Adding Dns Server Conditional Forwarder Zone for '$CurrentDnsServerConditionalForwarderZone' ..."
                #From https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
                Add-DnsServerConditionalForwarderZone -Name $CurrentDnsServerConditionalForwarderZone -MasterServers "168.63.129.16"
            }
        }
        #endregion


        #region Get the vnet and subnet where this DC is connected to
        # Get the VM networking data
        $ThisDomainController = Get-AzVMCompute | Get-AzVM
        # Get the VM's network interface
        $ThisDomainControllerNetworkInterfaceId = $ThisDomainController.NetworkProfile.NetworkInterfaces[0].Id
        $ThisDomainControllerNetworkInterface = Get-AzNetworkInterface -ResourceId $ThisDomainControllerNetworkInterfaceId

        # Get the subnet ID
        $ThisDomainControllerSubnetId = $ThisDomainControllerNetworkInterface.IpConfigurations[0].Subnet.Id
        $split = $ThisDomainControllerSubnetId.split('/')
        # Get the vnet ID
        $ThisDomainControllerVirtualNetworkId = $split[0..($split.Count - 3)] -join "/"
        $ThisDomainControllerVirtualNetwork = Get-AzResource -ResourceId $ThisDomainControllerVirtualNetworkId | Get-AzVirtualNetwork

        # Get the subnet details
        $ThisDomainControllerSubnet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ThisDomainControllerSubnetId
        #endregion

        #region AVD OU Management

        $DefaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $DomainName = (Get-ADDomain).DNSRoot
        #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name

        $AVDRootOU = Get-ADOrganizationalUnit -Filter 'Name -eq "AVD"' -SearchBase $DefaultNamingContext
        if (-not($AVDRootOU)) {
            $AVDRootOU = New-ADOrganizationalUnit -Name "AVD" -Path $DefaultNamingContext -ProtectedFromAccidentalDeletion $true -PassThru
            Write-Verbose -Message "Creating '$($AVDRootOU.DistinguishedName)' OU (under '$DefaultNamingContext') ..."
        }
        #Blocking Inheritance
        $null = $AVDRootOU | Set-GPInheritance -IsBlocked Yes
        #endregion

        #region AVD GPO Management
        $AVDGPO = Get-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
        if (-not($AVDGPO)) {
            $AVDGPO = New-GPO -Name "AVD - Global Settings" -ErrorAction Ignore
            Write-Verbose -Message "Creating '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        }
        $null = $AVDGPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore

        Write-Verbose -Message "Setting GPO Setting for $($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        #region Network Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/4-configure-user-settings-through-group-policies
        Write-Verbose -Message "Setting some 'Network Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.BITS::BITS_DisableBranchCache
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\BITS' -ValueName "DisableBranchCache" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.PoliciesContentWindowsBranchCache::EnableWindowsBranchCache
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service' -ValueName "Enable" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.HotspotAuthentication::HotspotAuth_Enable
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\HotspotAuthentication' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PlugandPlay::P2P_Disabled
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\policies\Microsoft\Peernet' -ValueName "Disabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.OfflineFiles::Pol_Enabled
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\Software\Policies\Microsoft\Windows\NetCache' -ValueName "Enabled" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Session Time Settings
        #From https://learn.microsoft.com/en-us/training/modules/configure-user-experience-settings/6-configure-session-timeout-properties
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Idle_Limit_1
        Write-Verbose -Message "Setting some 'Session Time Settings' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxIdleTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Disconnected_Timeout_1
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxDisconnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 900000
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_SESSIONS_Limits_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "MaxConnectionTime" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #From https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TerminalServer::TS_Session_End_On_Limit_2
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fResetBroken" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        #endregion

        #region Enable Screen Capture Protection
        #From https://learn.microsoft.com/en-us/training/modules/manage-access/5-configure-screen-capture-protection-for-azure-virtual-desktop
        #Value 2 is for blocking screen capture on client and server.
        Write-Verbose -Message "Setting some 'Enable Screen Capture Protection' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableScreenCaptureProtection" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
        #endregion

        #region Enable Watermarking
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/watermarking#enable-watermarking
        Write-Verbose -Message "Setting some 'Enable Watermarking' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "fEnableWatermarking" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1

        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingHeightFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 180
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingOpacity" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2000
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingQrScale" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 4
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ValueName "WatermarkingWidthFactor" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 320
        #endregion

        #region Enabling and using the new performance counters
        #From https://learn.microsoft.com/en-us/training/modules/install-configure-apps-session-host/10-troubleshoot-application-issues-user-input-delay
        Write-Verbose -Message "Setting some 'Performance Counters' related registry values for '$($AVDGPO.DisplayName)' GPO (linked to '$($AVDRootOU.DistinguishedName)' OU) ..."
        $null = Set-GPRegistryValue -Name $AVDGPO.DisplayName -Key 'HKLM\System\CurrentControlSet\Control\Terminal Server' -ValueName "EnableLagCounter" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
        #endregion 

        #region Starter GPOs Management
        Write-Verbose -Message "Starter GPOs Management ..."
        try {
            $null = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Stop
        }
        catch {
            <#
            Write-Warning "The required starter GPOs are not installed. Please click on the 'Create Starter GPOs Folder' under Group Policy Management / Forest / Domains / $DomainName / Starter GPOs before continuing"
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "gpmc.msc" -Wait
            #>
            $OutFile = Join-Path -Path $env:Temp -ChildPath StarterGPOs.zip
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Virtual%20Desktop/Setup/StarterGPOs.zip -OutFile $OutFile
            $DomainName = (Get-ADDomain).DNSRoot
            #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
            $DestinationPath = "\\{0}\SYSVOL\{0}" -f $DomainName
            Expand-Archive -Path $OutFile -DestinationPath $DestinationPath
            Remove-Item -Path $OutFile -Force -ErrorAction Ignore
        }
        #region These Starter GPOs include policy settings to configure the firewall rules required for GPO operations
        $GPO = Get-GPO -Name "Group Policy Reporting Firewall Ports" -ErrorAction Ignore
        if (-not($GPO)) {
            $GPO = Get-GPStarterGPO -Name "Group Policy Reporting Firewall Ports" | New-GPO -Name "Group Policy Reporting Firewall Ports"
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO ..."
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU ..."

        $GPO = Get-GPO -Name "Group Policy Remote Update Firewall Ports" -ErrorAction Ignore
        if (-not($GPO)) {
            $GPO = Get-GPStarterGPO -Name "Group Policy Remote Update Firewall Ports" | New-GPO -Name "Group Policy Remote Update Firewall Ports"
            Write-Verbose -Message "Creating '$($GPO.DisplayName)' Starter GPO ..."
        }
        $GPLink = $GPO | New-GPLink -Target $AVDRootOU.DistinguishedName -LinkEnabled Yes -ErrorAction Ignore
        Write-Verbose -Message "Linking '$($GPO.DisplayName)' Starter GPO to '$($AVDRootOU.DistinguishedName)' OU ..."
        #endregion
        #endregion
        #endregion

        #region Assigning the Desktop Virtualization Power On Off Contributor
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect?tabs=azure-portal#assign-the-desktop-virtualization-power-on-contributor-role-with-the-azure-portal
        #$objId = (Get-AzADServicePrincipal -AppId "9cdead84-a844-4324-93f2-b2e6bb768d07").Id
        $objId = (Get-AzADServicePrincipal -DisplayName "Azure Virtual Desktop").Id
        $SubscriptionId = $AzContext.Subscription.Id
        $Scope = "/subscriptions/$SubscriptionId"
        if (-not(Get-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope)) {
            Write-Verbose -Message "Assigning the 'Desktop Virtualization Power On Off Contributor' RBAC role to Service Principal '$objId' on the Subscription '$SubscriptionId' ..."
            $null = New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName "Desktop Virtualization Power On Off Contributor" -Scope $Scope
        }
        #endregion
    }
    process {
        $PooledHostPools = $HostPools | Where-Object -FilterScript { $_.Type -eq [HostPoolType]::Pooled }
        $PersonalHostPools = $HostPools | Where-Object -FilterScript { $_.Type -eq [HostPoolType]::Personal }

        #From https://stackoverflow.com/questions/7162090/how-do-i-start-a-job-of-a-function-i-just-defined
        #From https://stackoverflow.com/questions/76844912/how-to-call-a-class-object-in-powershell-jobs
        if ($AsJob) {
            #Setting the ThrottleLimit to the total number of host pool VM instances + 1
            $null = Start-ThreadJob -ScriptBlock { $null } -ThrottleLimit $(($HostPools.VMNumberOfInstances | Measure-Object -Sum).Sum + $HostPools.Count + 1)

            $ExportedFunctions = [scriptblock]::Create(@"
                Function New-AzAvdPooledHostPoolSetup { ${Function:New-AzAvdPooledHostPoolSetup} }
                Function New-AzAvdPersonalHostPoolSetup { ${Function:New-AzAvdPersonalHostPoolSetup} }
                Function Grant-ADJoinPermission { ${Function:Grant-ADJoinPermission} }
                Function Start-MicrosoftEntraIDConnectSync { ${Function:Start-MicrosoftEntraIDConnectSync} }
                Function Get-AzVMCompute { ${Function:Get-AzVMCompute} }
                Function Wait-PSSession { ${Function:Wait-PSSession} }
                function Set-AdminConsent { ${Function:Set-AdminConsent} }
                Function Copy-MSIXDemoAppAttachPackage { ${Function:Copy-MSIXDemoAppAttachPackage} }
                Function Copy-MSIXDemoPFXFile { ${Function:Copy-MSIXDemoPFXFile} }
                Function Get-AzKeyVaultNameAvailability { ${Function:Get-AzKeyVaultNameAvailability} }
                Function Add-AzAvdSessionHost { ${Function:Add-AzAvdSessionHost} }                       
                Function New-AzAvdSessionHost { ${Function:New-AzAvdSessionHost} }
                $ClassDefinitionScriptBlock                       
"@)
            $Jobs = @()
            $Jobs += foreach ($CurrentPooledHostPool in $PooledHostPools) {
                Write-Verbose "Starting background job for '$($CurrentPooledHostPool.Name)' Pooled HostPool Creation (via New-AzAvdPooledHostPoolSetup) ... "
                Start-ThreadJob -ScriptBlock { New-AzAvdPooledHostPoolSetup -HostPool $using:CurrentPooledHostPool -ADOrganizationalUnit $using:AVDRootOU -NoMFAAzADGroupName $NoMFAAzADGroupName -Verbose -AsJob *>&1 | Out-File -FilePath $("{0}\New-AzAvdPooledHostPoolSetup_{1}_{2}.txt" -f $using:CurrentDir, $($using:CurrentPooledHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions #-StreamingHost $Host
            }

            $Jobs += foreach ($CurrentPersonalHostPool in $PersonalHostPools) {
                Write-Verbose "Starting background job for '$($CurrentPersonalHostPool.Name)' Personal HostPool Creation (via New-AzAvdPersonalHostPoolSetup) ..."
                Start-ThreadJob -ScriptBlock { New-AzAvdPersonalHostPoolSetup -HostPool $using:CurrentPersonalHostPool -ADOrganizationalUnit $using:AVDRootOU -Verbose -AsJob *>&1 | Out-File -FilePath $("{0}\New-AzAvdPersonalHostPoolSetup_{1}_{2}.txt" -f $using:CurrentDir, $($using:CurrentPersonalHostPool).Name, (Get-Date -Format 'yyyyMMddHHmmss')) } -InitializationScript $ExportedFunctions #-StreamingHost $Host
            }

            Write-Verbose -Message "Waiting the background jobs complete ..."
            $Jobs | Wait-Job | Receive-Job -Keep
            Write-Verbose -Message "Removing the background jobs ..."
            $Jobs | Remove-Job -Force
        }
        else {
            if ($null -ne $PooledHostPools) {
                $PooledHostPools | New-AzAvdPooledHostPoolSetup -ADOrganizationalUnit $AVDRootOU -NoMFAAzADGroupName $NoMFAAzADGroupName -Verbose
            }
            if ($null -ne $PersonalHostPools) {
                $PersonalHostPools | New-AzAvdPersonalHostPoolSetup -ADOrganizationalUnit $AVDRootOU -Verbose
            }
        }
    }
    end {
        $EndTime = Get-Date
        $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
        Write-Host -Object "Overall HostPool Setup Processing Time: $($TimeSpan.ToString())"
    }
}

#Use the AD OU for generating the RDG file. Had to be called after the AD Object creation (at the end of the processing)
function New-AvdRdcMan {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    $null = Add-Type -AssemblyName System.Security
    #region variables
    $RootAVDOUName = 'AVD'
    $DomainName = (Get-ADDomain).DNSRoot
    #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
    $RDGFileContentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>$($DomainName)</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <localResources inherit="None">
            <audioRedirection>Client</audioRedirection>
            <audioRedirectionQuality>Dynamic</audioRedirectionQuality>
            <audioCaptureRedirection>DoNotRecord</audioCaptureRedirection>
            <keyboardHook>FullScreenClient</keyboardHook>
            <redirectClipboard>True</redirectClipboard>
            <redirectDrives>True</redirectDrives>
            <redirectDrivesList>
            </redirectDrivesList>
            <redirectPrinters>False</redirectPrinters>
            <redirectPorts>False</redirectPorts>
            <redirectSmartCards>False</redirectSmartCards>
            <redirectPnpDevices>False</redirectPnpDevices>
        </localResources>
        <group>
            <properties>
                <expanded>True</expanded>
                <name>$RootAVDOUName</name>
            </properties>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
"@
    #endregion

    #Remove-Item -Path $FullName -Force 
    If ((-not(Test-Path -Path $FullName)) -or (-not($Update))) {
        Write-Verbose -Message "Creating '$FullName' file ..."
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "Processing '$($CurrentHostPool.Name)' HostPool ..."
        $CurrentOU = Get-ADOrganizationalUnit -SearchBase "OU=$RootAVDOUName,$((Get-ADDomain).DistinguishedName)" -Filter "Name -eq '$($CurrentHostPool.Name)'" -Properties *
        #region Remove all previously existing nodes in the same host pool name
        #$PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//group/group/group/properties[contains(name, '$($CurrentOU.Name)')]")
        $PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//properties[contains(name, '$($CurrentHostPool.Name)')]")
        #$PreviouslyExistingNodes | ForEach-Object -Process {$_.ParentNode.RemoveAll()}
        $PreviouslyExistingNodes | ForEach-Object -Process {
            $ParentNode = $_.ParentNode
            $null = $ParentNode.ParentNode.RemoveChild($ParentNode)
        }
        #endregion 


        $ResourceGroupName = "rg-avd-{0}" -f $CurrentHostPool.Name

        #region Dedicated RDG Group creation
        $ParentCurrentOUs = ($CurrentOU.DistinguishedName -replace ",OU=$RootAVDOUName.*$" -replace "OU=" -split ",")
        [array]::Reverse($ParentCurrentOUs)
        $groupElement = $AVDGroupElement
        foreach ($ParentCurrentOU in $ParentCurrentOUs) {
            
            Write-Verbose -Message "Processing '$ParentCurrentOU' ..."
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentCurrentOU }
            if ($ParentElement) {
                Write-Verbose -Message "'$ParentCurrentOU' found under '$($groupElement.FirstChild.name)' ..."
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "Creating '$ParentCurrentOU' level ..."
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentCurrentOU))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
                $RDCManCredential = $LocalAdminCredential
            }
            else {
                $RDCManCredential = $null
            }
        }
        elseif ($null -ne $Credential) {
            $RDCManCredential = $Credential
        }
        else {
            $RDCManCredential = $null
        }

        #region Credential Management
        if ($null -ne $RDCManCredential) {
            if ($RDCManCredential.UserName -match '(?<Domain>\w+)\\(?<SAMAccountName>\w+)') {
                $UserName = $Matches['SAMAccountName']
                $DomainName = $Matches['Domain']
            }
            else {
                $UserName = $RDCManCredential.UserName
                $DomainName = '.'
            }
            $Password = $RDCManCredential.GetNetworkCredential().Password
            #Write-Host -Object "`$UserName: $UserName"
            #Write-Host -Object "`$Password: $Password"
            $PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
            $SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
            $logonCredentialsElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('logonCredentials'))
            $logonCredentialsElement.SetAttribute('inherit', 'None')
            $profileNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('profileName'))
            $profileNameElement.SetAttribute('scope', 'Local')
            $profileNameTextNode = $profileNameElement.AppendChild($AVDRDGFileContent.CreateTextNode('Custom'))
            $UserNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('UserName'))
            $UserNameTextNode = $UserNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($UserName))
            $PasswordElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Password'))
            $PasswordTextNode = $PasswordElement.AppendChild($AVDRDGFileContent.CreateTextNode($SecurePasswordStr))
            $DomainElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Domain'))
            #$DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode($DomainName))
            $DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode('.'))
        }
        #endregion

        #region Server Nodes Management
        #$Machines = Get-ADComputer -SearchBase $CurrentOU -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel
        $Machines = Get-ADComputer -SearchBase $CurrentOU -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel | Select-Object -Property Name
        if ($null -eq $Machines) {
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "Processing '$CurrentSessionHostName' Session Host ..."
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "Processing '$($CurrentMachine.Name)' Machine ..."
            $serverElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('server'))
            $propertiesElement = $serverElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
            $displayNameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('displayName'))
            $displayNameTextNode = $displayNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine.DisplayName))
            $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
            $NameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine.Name))
        }
        #endregion
        #endregion 
    }
    $AVDRDGFileContent.Save($FullName)
    if ($Install) {
        $OutFile = Join-Path -Path $env:Temp -ChildPath "RDCMan.zip"
        Write-Verbose "Downloading the latest RDCMan version form SysInternals ..."
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose "Extracting the downloaded archive file to system32 ..."
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force -Verbose
        }
        Write-Verbose "Removing the downloaded archive file to system32 ..."
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose "Opening RDC Manager ..."
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName"""
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
}

#Use the HostPool properties for generating the RDG file. Doesn't required to be called after the AD Object creation. Can be called at the start of the processing.
function New-AvdRdcManV2 {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("Desktop")) -ChildPath "$((Get-ADDomain).DNSRoot).rdg"),
        [Parameter(Mandatory = $true)]
        [HostPool[]]$HostPool,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        [switch] $Open,
        [switch] $Install,
        [switch] $Update
    )

    $null = Add-Type -AssemblyName System.Security
    #region variables
    $RootAVDOUName = 'AVD'
    $DomainName = (Get-ADDomain).DNSRoot
    #$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
    $RDGFileContentTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.83" schemaVersion="3">
    <file>
        <credentialsProfiles />
        <properties>
            <expanded>True</expanded>
            <name>$($DomainName)</name>
        </properties>
        <remoteDesktop inherit="None">
            <sameSizeAsClientArea>True</sameSizeAsClientArea>
            <fullScreen>False</fullScreen>
            <colorDepth>24</colorDepth>
        </remoteDesktop>
        <localResources inherit="None">
            <audioRedirection>Client</audioRedirection>
            <audioRedirectionQuality>Dynamic</audioRedirectionQuality>
            <audioCaptureRedirection>DoNotRecord</audioCaptureRedirection>
            <keyboardHook>FullScreenClient</keyboardHook>
            <redirectClipboard>True</redirectClipboard>
            <redirectDrives>True</redirectDrives>
            <redirectDrivesList>
            </redirectDrivesList>
            <redirectPrinters>False</redirectPrinters>
            <redirectPorts>False</redirectPorts>
            <redirectSmartCards>False</redirectSmartCards>
            <redirectPnpDevices>False</redirectPnpDevices>
        </localResources>
        <group>
            <properties>
                <expanded>True</expanded>
                <name>$RootAVDOUName</name>
            </properties>
        </group>
    </file>
    <connected />
    <favorites />
    <recentlyUsed />
</RDCMan>
"@
    #endregion

    #Remove-Item -Path $FullName -Force 
    If ((-not(Test-Path -Path $FullName)) -or (-not($Update))) {
        Write-Verbose -Message "Creating '$FullName' file ..."
        Set-Content -Value $RDGFileContentTemplate -Path $FullName
    }

    $AVDRDGFileContent = [xml](Get-Content -Path $FullName)
    $AVDFileElement = $AVDRDGFileContent.RDCMan.file
    $AVDGroupElement = $AVDFileElement.group | Where-Object -FilterScript {
        $_.ChildNodes.Name -eq $RootAVDOUName
    }

    foreach ($CurrentHostPool in $HostPool) {
        Write-Verbose -Message "Processing '$($CurrentHostPool.Name)' HostPool ..."
        #region Remove all previously existing nodes in the same host pool name
        $PreviouslyExistingNodes = $AVDRDGFileContent.SelectNodes("//properties[contains(name, '$($CurrentHostPool.Name)')]")
        #$PreviouslyExistingNodes | ForEach-Object -Process {$_.ParentNode.RemoveAll()}
        $PreviouslyExistingNodes | ForEach-Object -Process {
            $ParentNode = $_.ParentNode
            $null = $ParentNode.ParentNode.RemoveChild($ParentNode)
        }
        #endregion 


        $ResourceGroupName = "rg-avd-{0}" -f $CurrentHostPool.Name

        #region Dedicated RDG Group creation
        $ParentLevels = $CurrentHostPool.Location, $("{0}Desktops" -f $CurrentHostPool.Type), $CurrentHostPool.Name
        $groupElement = $AVDGroupElement
        foreach ($ParentLevel in $ParentLevels) {
            
            Write-Verbose -Message "Processing '$ParentLevel' ..."
            $ParentElement = $groupElement.group | Where-Object -FilterScript { $_.ChildNodes.Name -eq $ParentLevel }
            if ($ParentElement) {
                Write-Verbose -Message "'$ParentLevel' found under '$($groupElement.FirstChild.name)' ..."
            } 
            else {
                $ParentElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('group'))
                $propertiesElement = $ParentElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
                $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
                Write-Verbose -Message "Creating '$ParentLevel' level ..."
                $nameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($ParentLevel))
                $expandedElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('expanded'))
                $expandedTextNode = $expandedElement.AppendChild($AVDRDGFileContent.CreateTextNode('True'))
            }
            $groupElement = $ParentElement
        }

        if ($CurrentHostPool.IsMicrosoftEntraIdJoined()) {
            if ($null -ne $CurrentHostPool.KeyVault) {
                $LocalAdminUserName = $CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminUserName -AsPlainText
                $LocalAdminPassword = ($CurrentHostPool.KeyVault | Get-AzKeyVaultSecret -Name LocalAdminPassword).SecretValue
                $LocalAdminCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($LocalAdminUserName, $LocalAdminPassword)
                $RDCManCredential = $LocalAdminCredential
            }
            else {
                $RDCManCredential = $null
            }
        }
        elseif ($null -ne $Credential) {
            $RDCManCredential = $Credential
        }
        else {
            $RDCManCredential = $null
        }

        #region Credential Management
        if ($null -ne $RDCManCredential) {
            if ($RDCManCredential.UserName -match '(?<Domain>\w+)\\(?<SAMAccountName>\w+)') {
                $UserName = $Matches['SAMAccountName']
                $DomainName = $Matches['Domain']
            }
            else {
                $UserName = $RDCManCredential.UserName
                $DomainName = '.'
            }
            $Password = $RDCManCredential.GetNetworkCredential().Password
            #Write-Host -Object "`$UserName: $UserName"
            #Write-Host -Object "`$Password: $Password"
            $PasswordBytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
            $SecurePassword = [Security.Cryptography.ProtectedData]::Protect($PasswordBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $SecurePasswordStr = [System.Convert]::ToBase64String($SecurePassword)
            $logonCredentialsElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('logonCredentials'))
            $logonCredentialsElement.SetAttribute('inherit', 'None')
            $profileNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('profileName'))
            $profileNameElement.SetAttribute('scope', 'Local')
            $profileNameTextNode = $profileNameElement.AppendChild($AVDRDGFileContent.CreateTextNode('Custom'))
            $UserNameElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('UserName'))
            $UserNameTextNode = $UserNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($UserName))
            $PasswordElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Password'))
            $PasswordTextNode = $PasswordElement.AppendChild($AVDRDGFileContent.CreateTextNode($SecurePasswordStr))
            $DomainElement = $logonCredentialsElement.AppendChild($AVDRDGFileContent.CreateElement('Domain'))
            #$DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode($DomainName))
            $DomainTextNode = $DomainElement.AppendChild($AVDRDGFileContent.CreateTextNode('.'))
        }
        #endregion

        #region Server Nodes Management
        #$Machines = Get-ADComputer -SearchBase $Level -Properties DNSHostName -Filter 'DNSHostName -like "*"' -SearchScope OneLevel | Select-Object -Property @{Name = 'DisplayName'; Expression = { $_.Name } }, Name
        $Machines = for ($index = 0; $index -lt $CurrentHostPool.VMNumberOfInstances; $index++) {
            "{0}-{1}" -f $CurrentHostPool.NamePrefix, $index
        }
        if ($null -eq $Machines) {
            $SessionHosts = Get-AzWvdSessionHost -HostpoolName $CurrentHostPool.Name -ResourceGroupName $ResourceGroupName
            if ($null -ne $SessionHosts) {
                $SessionHostNames = $SessionHosts.ResourceId -replace ".*/"
                $Machines = foreach ($CurrentSessionHostName in $SessionHostNames) {
                    Write-Verbose -Message "Processing '$CurrentSessionHostName' Session Host ..."
                    $VM = Get-AzVM -Name $CurrentSessionHostName -ResourceGroupName $resourceGroupName
                    $NIC = Get-AzNetworkInterface -Name $($VM.NetworkProfile.NetworkInterfaces.Id -replace ".*/")
                    $PrivateIpAddress = $NIC.IpConfigurations.PrivateIPAddress
                    [pscustomobject]@{DisplayName = $CurrentSessionHostName; Name = $PrivateIpAddress }
                }
            }
        }
        foreach ($CurrentMachine in $Machines) {
            Write-Verbose -Message "Processing '$($CurrentMachine)' Machine ..."
            $serverElement = $groupElement.AppendChild($AVDRDGFileContent.CreateElement('server'))
            $propertiesElement = $serverElement.AppendChild($AVDRDGFileContent.CreateElement('properties'))
            $displayNameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('displayName'))
            $displayNameTextNode = $displayNameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine))
            $nameElement = $propertiesElement.AppendChild($AVDRDGFileContent.CreateElement('name'))
            $NameTextNode = $nameElement.AppendChild($AVDRDGFileContent.CreateTextNode($CurrentMachine))
        }
        #endregion
        #endregion 
    }
    $AVDRDGFileContent.Save($FullName)
    if ($Install) {
        $OutFile = Join-Path -Path $env:Temp -ChildPath "RDCMan.zip"
        Write-Verbose "Downloading the latest RDCMan version form SysInternals ..."
        $Response = Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RDCMan.zip" -UseBasicParsing -OutFile $OutFile -PassThru
        Write-Verbose "Extracting the downloaded archive file to system32 ..."
        $System32 = $(Join-Path -Path $env:windir -ChildPath "system32")
        $RDCManProcess = (Get-Process -Name rdcman -ErrorAction Ignore)
        #If RDCMan is running for system32 folder
        if (($null -ne $RDCManProcess) -and ((Split-Path -Path $RDCManProcess.Path -Parent) -eq $System32)) {
            Write-Warning "RDCMan is running. Unable to update the update the executable in the '$System32' folder."
        }
        else { 
            Expand-Archive -Path $OutFile -DestinationPath $System32 -Force -Verbose
        }
        Write-Verbose "Removing the downloaded archive file to system32 ..."
        Remove-Item -Path $OutFile -Force
        if ($Open) {
            Write-Verbose "Opening RDC Manager ..."
            #Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "rdcman ""$FullName"""
            Start-Process -FilePath "rdcman" -ArgumentList """$FullName"""
        }
    }
    elseif ($Open) {
        & $FullName
    }
}

#From https://learn.microsoft.com/en-us/azure/virtual-desktop/autoscale-scaling-plan?tabs=powershell
function New-AzAvdScalingPlan {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [HostPool[]]$HostPools
    )
    foreach ($CurrentHostPool in $HostPools) {
        #region Sclaing Plan
        $AzWvdHostPool = (Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -eq $($CurrentHostPool.Name) })
        $ResourceGroupName = ($AzWvdHostPool.Id -split "/")[4]
        $ScalingPlanName = "sp-avd-{0}" -f $CurrentHostPool.Name
        $scalingPlanParams = @{
            #ResourceGroupName = "rg-avd-{0}" -f $CurrentHostPool.Name
            ResourceGroupName = $ResourceGroupName
            Name              = $ScalingPlanName
            Location          = $CurrentHostPool.Location
            Description       = $CurrentHostPool.Name
            FriendlyName      = $CurrentHostPool.Name
            HostPoolType      = $CurrentHostPool.Type
            TimeZone          = (Get-TimeZone).Id
            HostPoolReference = @(@{'hostPoolArmPath' = $AzWvdHostPool.Id; 'scalingPlanEnabled' = $true; })
        }
        $scalingPlan = New-AzWvdScalingPlan @scalingPlanParams
        #endregion

        if ($CurrentHostPool.Type -eq [HostPoolType]::Pooled) {
            $scalingPlanPooledScheduleParams = @{
                ResourceGroupName              = $ResourceGroupName
                ScalingPlanName                = $ScalingPlanName
                ScalingPlanScheduleName        = 'PooledWeekDaySchedule'
                DaysOfWeek                     = 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'
                RampUpStartTimeHour            = '8'
                RampUpStartTimeMinute          = '0'
                RampUpLoadBalancingAlgorithm   = 'BreadthFirst'
                RampUpMinimumHostsPct          = '20'
                RampUpCapacityThresholdPct     = '50'
                PeakStartTimeHour              = '9'
                PeakStartTimeMinute            = '0'
                PeakLoadBalancingAlgorithm     = 'DepthFirst'
                RampDownStartTimeHour          = '18'
                RampDownStartTimeMinute        = '0'
                RampDownLoadBalancingAlgorithm = 'BreadthFirst'
                RampDownMinimumHostsPct        = '20'
                RampDownCapacityThresholdPct   = '20'
                RampDownForceLogoffUser        = $true
                RampDownWaitTimeMinute         = '30'
                RampDownNotificationMessage    = '"Log out now, please."'
                RampDownStopHostsWhen          = 'ZeroSessions'
                OffPeakStartTimeHour           = '19'
                OffPeakStartTimeMinute         = '00'
                OffPeakLoadBalancingAlgorithm  = 'DepthFirst'
            }

            $scalingPlanPooledSchedule = New-AzWvdScalingPlanPooledSchedule @scalingPlanPooledScheduleParams
        }
        else {
            if ($CurrentHostPool.HibernationEnabled) {
                $PeakActionOnDisconnect = 'Hibernate'
                $RampDownActionOnLogoff = 'Hibernate'
            }
            else {
                $PeakActionOnDisconnect = 'Deallocate '
                $RampDownActionOnLogoff = 'Deallocate '
            }
            $scalingPlanPersonalScheduleParams = @{
                ResourceGroupName                 = $ResourceGroupName
                ScalingPlanName                   = $ScalingPlanName
                ScalingPlanScheduleName           = 'PersonalWeekDaySchedule'
                DaysOfWeek                        = 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'
                RampUpStartTimeHour               = '8'
                RampUpStartTimeMinute             = '0'
                RampUpAutoStartHost               = 'WithAssignedUser'
                RampUpStartVMOnConnect            = 'Enable'
                RampUpMinutesToWaitOnDisconnect   = '30'
                RampUpActionOnDisconnect          = 'Deallocate'
                RampUpMinutesToWaitOnLogoff       = '3'
                RampUpActionOnLogoff              = 'Deallocate'
                PeakStartTimeHour                 = '9'
                PeakStartTimeMinute               = '0'
                PeakStartVMOnConnect              = 'Enable'
                PeakMinutesToWaitOnDisconnect     = '10'
                PeakActionOnDisconnect            = $PeakActionOnDisconnect
                PeakMinutesToWaitOnLogoff         = '15'
                PeakActionOnLogoff                = 'Deallocate'
                RampDownStartTimeHour             = '18'
                RampDownStartTimeMinute           = '0'
                RampDownStartVMOnConnect          = 'Disable'
                RampDownMinutesToWaitOnDisconnect = '10'
                RampDownActionOnDisconnect        = 'None'
                RampDownMinutesToWaitOnLogoff     = '15'
                RampDownActionOnLogoff            = $RampDownActionOnLogoff
                OffPeakStartTimeHour              = '19'
                OffPeakStartTimeMinute            = '0'
                OffPeakStartVMOnConnect           = 'Disable'
                OffPeakMinutesToWaitOnDisconnect  = '10'
                OffPeakActionOnDisconnect         = 'Deallocate'
                OffPeakMinutesToWaitOnLogoff      = '15'
                OffPeakActionOnLogoff             = 'Deallocate'
            }

            $scalingPlanPersonalSchedule = New-AzWvdScalingPlanPersonalSchedule @scalingPlanPersonalScheduleParams
        }
    }
}
#endregion

#region Main code
Clear-Host
$StartTime = Get-Date
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$TranscriptFile = $CurrentScript -replace ".ps1$", "_$("{0:yyyyMMddHHmmss}" -f $StartTime).txt"
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader #-Verbose

$Error.Clear()
# Define the class in the current scope by dot-sourcing the script block.
. $ClassDefinitionScriptBlock

#For installing required modules if needed
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$null = Get-PackageProvider -Name NuGet -Force
$RequiredModules = 'AzureAD', 'Az.Accounts', 'Az.Compute', 'Az.DesktopVirtualization', 'Az.ImageBuilder', 'Az.Insights', 'Az.ManagedServiceIdentity', 'Az.Monitor', 'Az.Network', 'Az.KeyVault', 'Az.OperationalInsights', 'Az.PrivateDns', 'Az.Resources', 'Az.Storage', 'PowerShellGet', 'ThreadJob'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule))) {
    $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject $InstalledModule.Name).InputObject
}
else {
    $MissingModules = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules))) {
    Install-Module -Name $MissingModules -AllowClobber -Force
}

#From https://aka.ms/azps-changewarnings: Disabling breaking change warning messages in Azure PowerShell
$null = Update-AzConfig -DisplayBreakingChangeWarning $true

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Verbose -Message "Account : $((Get-AzContext).Account)"
    Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
}
#endregion

#region Microsoft Entra ID/Azure AD Connection
try {
    $null = Get-AzureADDevice #-ErrorAction Stop
}
catch {
    Write-Verbose -Message "Connecting to Microsoft Entra ID/Azure AD"
    Connect-AzureAD
}
#endregion

#region Azure Provider Registration
#To use Azure Virtual Desktop, you have to register for the providers and to ensure that RegistrationState will be set to Registered.
$RequiredResourceProviders = "Microsoft.DesktopVirtualization", "Microsoft.Insights", "Microsoft.VirtualMachineImages", "Microsoft.Storage", "Microsoft.Compute", "Microsoft.KeyVault", "Microsoft.ManagedIdentity"
$Jobs = foreach ($CurrentRequiredResourceProvider in $RequiredResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $CurrentRequiredResourceProvider -AsJob
}
#Important: Wait until RegistrationState is set to Registered. 
While (Get-AzResourceProvider -ProviderNamespace $RequiredResourceProviders | Where-Object -FilterScript { $_.RegistrationState -ne 'Registered' }) {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
$Jobs | Remove-Job -Force

#Enabling hibernation feature for your subscription
Register-AzProviderFeature -FeatureName "VMHibernationPreview" -ProviderNamespace "Microsoft.Compute"
While ((Get-AzProviderPreviewFeature -FeatureName VMHibernationPreview -ProviderNamespace Microsoft.Compute).Properties.State -ne 'Registered') {
    Write-Verbose -Message "Sleeping 10 seconds ..."
    Start-Sleep -Seconds 10
}
#endregion

#region Installling FSLogix GPO Setting
if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\fslogix.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\fslogix.admx -PathType Leaf)) {
    $FSLogixLatestZipName = 'FSLogix_Apps_Latest.zip'
    $OutFile = Join-Path -Path $env:Temp -ChildPath $FSLogixLatestZipName
    #From  https://aka.ms/fslogix-latest
    #$FSLogixLatestURI = 'https://download.microsoft.com/download/1/7/1/17134492-1ef3-420b-a78a-cf13c42d1078/FSLogix_Apps_2.9.8784.63912.zip'
    #Always get the latest version of FSLogix
    $FSLogixLatestURI = ((Invoke-WebRequest -Uri "https://aka.ms/fslogix-latest").Links | Where-Object -FilterScript {$_.innerText -eq "Download"}).href
    Start-BitsTransfer $FSLogixLatestURI -destination $OutFile
    Expand-Archive -Path $OutFile -DestinationPath $env:Temp\FSLogixLatest -Force
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.adml $env:SystemRoot\policyDefinitions\en-US
    Copy-Item -Path $env:Temp\FSLogixLatest\fslogix.admx $env:SystemRoot\policyDefinitions
}
#endregion 

#region Installling AVD GPO Setting
if (-not(Test-Path -Path $env:SystemRoot\policyDefinitions\en-US\terminalserver-avd.adml -PathType Leaf) -or -not(Test-Path -Path $env:SystemRoot\policyDefinitions\terminalserver-avd.admx -PathType Leaf)) {
    $AVDGPOLatestCabName = 'AVDGPTemplate.cab'
    $OutFile = Join-Path -Path $env:Temp -ChildPath $AVDGPOLatestCabName
    $AVDGPOLatestURI = 'https://aka.ms/avdgpo'
    Invoke-WebRequest -Uri  $AVDGPOLatestURI -OutFile $OutFile
    $AVDGPOLatestDir = New-Item -Path $env:Temp\AVDGPOLatest -ItemType Directory -Force
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "extrac32 $OutFile /Y" -WorkingDirectory $AVDGPOLatestDir -Wait 
    $ZipFiles = Get-ChildItem -Path $AVDGPOLatestDir -Filter *.zip -File 
    $ZipFiles | Expand-Archive -DestinationPath $AVDGPOLatestDir -Force
    Remove-Item -Path $ZipFiles.FullName -Force

    Copy-Item -Path $AVDGPOLatestDir\en-US\terminalserver-avd.adml $env:SystemRoot\policyDefinitions\en-US
    Copy-Item -Path $AVDGPOLatestDir\terminalserver-avd.admx $env:SystemRoot\policyDefinitions
    Remove-Item -Path $AVDGPOLatestDir -Recurse -Force
}
#endregion 

#region function calls
$HostPoolSessionCredentialKeyVault = New-AzHostPoolSessionCredentialKeyVault -Verbose

#region Creating Host Pools
#Reset Index (starting at 1) for automatic numbering (every instantiation will increment the Index)
[PooledHostPool]::ResetIndex()
[PersonalHostPool]::ResetIndex()
$RandomNumber = Get-Random -Minimum 1 -Maximum 100
[PooledHostPool]::Index=7
[PersonalHostPool]::Index=7
#$RandomNumber = 99
$HostPools = @(
    # Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault)
    # Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
    # Use case 3: Deploy a Personal HostPool with 4 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMNumberOfInstances(4)
    # Use case 4: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops)
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableHibernation()
)

#region Creating a new Pooled Host Pool for every image definition in the Azure Compute Gallery
$Index = [PooledHostPool]::Index
#$AzureComputeGallery = New-AzureComputeGallery -Verbose
$AzureComputeGallery = Get-AzGallery | Sort-Object -Property Name -Descending | Select-Object -First 1
$GalleryImageDefinition = Get-AzGalleryImageDefinition -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName
foreach ($CurrentGalleryImageDefinition in $GalleryImageDefinition) {
    #$LatestCurrentGalleryImageVersion = Get-AzGalleryImageVersion -GalleryName $AzureComputeGallery.Name -ResourceGroupName $AzureComputeGallery.ResourceGroupName -GalleryImageDefinitionName $CurrentGalleryImageDefinition.Name | Sort-Object -Property Id | Select-Object -Last 1
    # Use case 5 and more: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with an Image coming from an Azure Compute Gallery and without FSLogix and MSIX
    $PooledHostPool = [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMSourceImageId($CurrentGalleryImageDefinition.Id).DisableFSLogix().DisableMSIX()
    Write-Verbose "VM Source Image Id for the ACG Host Pool: $LatestCurrentGalleryImageVersion (MSIX: $($PooledHostPool.MSIX) / FSlogix: $($PooledHostPool.FSlogix))" -Verbose
    $HostPools += $PooledHostPool
}
#endregion

#endregion

#Uncomment the following block to remove all previously existing resources
#Remove-AzAvdHostPoolSetup -HostPool $HostPools -KeyVault $HostPoolSessionCredentialKeyVault -Verbose
Remove-AzAvdHostPoolSetup -HostPool $HostPools -Verbose
#Or pipeline processing call
#$HostPools | Remove-AzAvdHostPoolSetup -Verbose

if (-not(Test-AzAvdStorageAccountNameAvailability -HostPools $HostPools -Verbose)) {
    Stop-Transcript
    Write-Error -Message "Storage Account Name(s) NOT available" -ErrorAction Stop 
}

#Running RDCMan to connect to all Session Hosts (for administration purpose if needed)
#New-AvdRdcManV2 -HostPool $HostPools -Install -Open -Verbose

#Setting up the hostpools
New-AzAvdHostPoolSetup -HostPool $HostPools -NoMFAAzADGroupName "No-MFA Users" -Verbose #-AsJob
#Or pipeline processing call
#$HostPools | New-AzAvdHostPoolSetup #-AsJob 

#Setting up the hostpool scaling plan
New-AzAvdScalingPlan -HostPool $HostPools -Verbose
#Or pipeline processing call
#$HostPools | New-AzAvdHostPoolSetup

#Running RDCMan to connect to all Session Hosts (for administration purpose if needed)
#New-AvdRdcMan -Credential $LocalAdminCredential -Install -Open -Verbose
New-AvdRdcMan -HostPool $HostPools -Install -Open -Verbose

#Remove-AzResourceGroup -Name $AzureComputeGallery.ResourceGroupName -Force -AsJob

$SessionHostNames = foreach ($CurrentHostPoolName in $HostPools.Name) { (Get-AzWvdSessionHost -HostPoolName $CurrentHostPoolName -ResourceGroupName "rg-avd-$CurrentHostPoolName" -ErrorAction Ignore).ResourceId -replace ".*/" | Where-Object -FilterScript { -not([string]::IsNullOrEmpty($_)) } }

$Jobs = foreach ($CurrentSessionHostName in $SessionHostNames) {
    Write-Host -Object "Restarting '$CurrentSessionHostName' Azure VM ..."
    Get-AzVM -Name $CurrentSessionHostName | Restart-AzVM -AsJob -Verbose
}
Write-Host -Object "Waiting for all restarts ..."
$Jobs | Wait-Job | Out-Null
$Jobs | Remove-Job -Force

#region Adding Test Users (under the OrgUsers OU) as HostPool Users (for all HostPools)
Get-ADGroup -Filter "Name -like 'hp*-*Users'" | Add-ADGroupMember -Members "AVD Users"
Start-MicrosoftEntraIDConnectSync -Verbose
#endregion


$EndTime = Get-Date
$TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
Write-Host -Object "Overall Processing Time: $($TimeSpan.ToString())"
#endregion
<#
Get-Job | Remove-Job -Force
Stop-Transcript
#Looking for error in the log files
$LogFiles = Get-ChildItem -Path $CurrentDir -Filter New*.txt -File | Where-Object -FilterScript {$_.LastWriteTime -ge $StartTime}
Select-String -Pattern "~~" -Path $LogFiles -Context 1
#Doing some cleanups
Remove-Item -Path $LogFiles -Force
#>
Stop-Transcript