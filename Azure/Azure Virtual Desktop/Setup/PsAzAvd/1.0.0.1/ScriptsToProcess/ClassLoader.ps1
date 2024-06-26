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
        [boolean] $Intune
        [boolean] $Spot
        [boolean] $ScalingPlan
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
            $this.DisableSpotInstance()
            $this.DisableIntune()            
            $this.EnableScalingPlan()
            $this.KeyVault = $KeyVault
            $this.IdentityProvider = [IdentityProvider]::ActiveDirectory
        }

        [string] GetAzAvdWorkSpaceName() {
            return "ws-{0}" -f $($this.Name.ToLower())
        }

        [string] GetAzAvdScalingPlanName() {
            return "sp-avd-{0}" -f $($this.Name.ToLower())
        }

        [string] GetLogAnalyticsWorkSpaceName() {
            return "log{0}" -f $($this.Name.ToLower() -replace "\W")
        }

        [string] GetResourceGroupName() {
            return "rg-avd-{0}" -f $($this.Name.ToLower())
        }

        [string] GetKeyVaultName() {
            return "kv{0}" -f $($this.Name.ToLower() -replace "\W")
        }

        [object] GetPropertyForJSON() {
            return $this | Select-Object -Property *, @{Name = "ResourceGroupName"; Expression = { $_.GetResourceGroupName() } }, @{Name = "KeyVaultName"; Expression = { $_.GetKeyVaultName() } }, @{Name = "LogAnalyticsWorkSpaceName"; Expression = { $_.GetLogAnalyticsWorkSpaceName() } } -ExcludeProperty "KeyVault"
        }


        [HostPool] SetVMNumberOfInstances([int] $VMNumberOfInstances) {
            $this.VMNumberOfInstances = $VMNumberOfInstances
            return $this
        }

        [HostPool]DisableIntune() {
            $this.Intune = $false
            return $this
        }

        [HostPool]EnableIntune() {
            $this.Intune = $true
            $this.SetIdentityProvider([IdentityProvider]::MicrosoftEntraID)
            return $this
        }

        <#
        [bool] IsIntuneEnrolled() {
            return $this.Intune
        }
        #>

        [HostPool]DisableScalingPlan() {
            $this.ScalingPlan = $false
            return $this
        }

        [HostPool]EnableScalingPlan() {
            $this.ScalingPlan = $true
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
            if ($IdentityProvider -eq [IdentityProvider]::ActiveDirectory) {
                $this.DisableIntune()
            }
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
        hidden [ValidateRange(0, 999)] static [int] $Index = 0
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

        [string] GetFSLogixStorageAccountName() {
            if ($this.FSlogix) {
                return "fsl{0}" -f $($this.Name.ToLower() -replace "\W")
            }
            else {
                return $null
            }
        }

        [string] GetMSIXStorageAccountName() {
            if ($this.MSIX) {
                return "msix{0}" -f $($this.Name.ToLower() -replace "\W")
            }
            else {
                return $null
            }
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

            $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PooledHostPool]::Index
        }
    }

    class PersonalHostPool : HostPool {
        hidden [ValidateRange(0, 999)] static [int] $Index = 0
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

        [PersonalHostPool]EnableSpotInstance() {
            ([HostPool]$this).EnableSpotInstance()
            #$this.Spot = $true
            $this.DisableHibernation()
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

            $this.Name = "{0}-{1}-{2:D3}" -f $TempName, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
            $this.NamePrefix = "{0}{1}{2:D3}" -f $TempNamePrefix, [HostPool]::AzLocationShortNameHT[$this.Location].shortname, [PersonalHostPool]::Index
        }
    }
}
#endregion

. $ClassDefinitionScriptBlock