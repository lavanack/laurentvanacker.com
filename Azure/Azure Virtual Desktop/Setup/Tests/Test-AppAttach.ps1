Clear-Host

#region Function definitions
#From https://github.com/sdoubleday/GetCallerPreference/blob/master/GetCallerPreference.psm1
#From https://www.powershellgallery.com/packages/AsgGroup/2.0.6/Content/Private%5CGet-CallerPreference.ps1
function Get-CallerPreference {
    <#
        .SYNOPSIS
        Fetches "Preference" variable values from the caller's scope.
        .DESCRIPTION
        Script module functions do not automatically inherit their caller's variables, but they can be obtained
        through the $PSCmdlet variable in Advanced Functions. This function is a helper function for any script
        module Advanced Function; by passing in the values of $ExecutionContext.SessionState and $PSCmdlet,
        Get-CallerPreference will set the caller's preference variables locally.
        .PARAMETER Cmdlet
        The $PSCmdlet object from a script module Advanced Function.
        .PARAMETER SessionState
        The $ExecutionContext.SessionState object from a script module Advanced Function. This is how the
        Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
        script module.
        .PARAMETER Name
        Optional array of parameter names to retrieve from the caller's scope. Default is to retrieve all preference
        variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0). This parameter may
        also specify names of variables that are not in the about_Preference_Variables help file, and the function
        will retrieve and set those as well.
       .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Imports the default PowerShell preference variables from the caller into the local scope.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference', 'SomeOtherVariable'
        Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
        .EXAMPLE
        'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Same as Example 2, but sends variable names to the Name parameter via pipeline input.
       .INPUTS
        System.String
        .OUTPUTS
        None.
        This function does not produce pipeline output.
        .LINK
        about_Preference_Variables
    #>
    #Requires -Version 2
    [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
    param (
        [Parameter(Mandatory)]
        [ValidateScript( { $PSItem.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,
        [Parameter(Mandatory)][System.Management.Automation.SessionState]$SessionState,
        [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)][string[]]$Name
    )
    begin {
        $FilterHash = @{ }
    }
    
    process {
        if ($null -ne $Name) {
            foreach ($String in $Name) {
                $FilterHash[$String] = $true
            }
        }
    }
    end {
        # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
        $Vars = @{
            'ErrorView'                     = $null
            'FormatEnumerationLimit'        = $null
            'LogCommandHealthEvent'         = $null
            'LogCommandLifecycleEvent'      = $null
            'LogEngineHealthEvent'          = $null
            'LogEngineLifecycleEvent'       = $null
            'LogProviderHealthEvent'        = $null
            'LogProviderLifecycleEvent'     = $null
            'MaximumAliasCount'             = $null
            'MaximumDriveCount'             = $null
            'MaximumErrorCount'             = $null
            'MaximumFunctionCount'          = $null
            'MaximumHistoryCount'           = $null
            'MaximumVariableCount'          = $null
            'OFS'                           = $null
            'OutputEncoding'                = $null
            'ProgressPreference'            = $null
            'PSDefaultParameterValues'      = $null
            'PSEmailServer'                 = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName'      = $null
            'PSSessionConfigurationName'    = $null
            'PSSessionOption'               = $null
            'ErrorActionPreference'         = 'ErrorAction'
            'DebugPreference'               = 'Debug'
            'ConfirmPreference'             = 'Confirm'
            'WhatIfPreference'              = 'WhatIf'
            'VerbosePreference'             = 'Verbose'
            'WarningPreference'             = 'WarningAction'
        }
        foreach ($Entry in $Vars.GetEnumerator()) {
            if (([string]::IsNullOrEmpty($Entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($Entry.Value)) -and
                ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $FilterHash.ContainsKey($Entry.Name))) {
                $Variable = $Cmdlet.SessionState.PSVariable.Get($Entry.Key)
                
                if ($null -ne $Variable) {
                    if ($SessionState -eq $ExecutionContext.SessionState) {
                        Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                    }
                    else {
                        $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                    }
                }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq 'Filtered') {
            foreach ($VarName in $FilterHash.Keys) {
                if (-not $Vars.ContainsKey($VarName)) {
                    $Variable = $Cmdlet.SessionState.PSVariable.Get($VarName)
                
                    if ($null -ne $Variable) {
                        if ($SessionState -eq $ExecutionContext.SessionState) {
                            Set-Variable -Scope 1 -Name $Variable.Name -Value $Variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else {
                            $SessionState.PSVariable.Set($Variable.Name, $Variable.Value)
                        }
                    }
                }
            }
        }
    }
}

function Add-PsAvdAzureAppAttach {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Parameter(Mandatory = $true)]
        [HostPool[]] $HostPool,

        [Parameter(Mandatory = $false)]
        [string] $StorageEndpointSuffix = 'core.windows.net'
    )
    
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $AzureAppAttachPooledHostPools = $HostPool | Where-Object { $_.AppAttach }
    $AzureAppAttachPooledHostPoolsPerLocation = $AzureAppAttachPooledHostPools | Group-Object -Property Location -AsHashTable -AsString
    $AzContext = Get-AzContext
    # Your subscription. This command gets your current subscription
    $subscriptionID = $AzContext.Subscription.Id
    foreach ($Location in $AzureAppAttachPooledHostPoolsPerLocation.Keys) {
        $AllHostPoolsInthisLocation = $AzureAppAttachPooledHostPoolsPerLocation[$Location]
        $FirstHostPoolInthisLocation = $AllHostPoolsInthisLocation | Select-Object -First 1
        $FirstHostPoolInthisLocationStorageAccountName = $FirstHostPoolInthisLocation.GetAppAttachStorageAccountName()
        $FirstHostPoolInthisLocationStorageAccountResourceGroupName = $FirstHostPoolInthisLocation.GetAppAttachStorageAccountResourceGroupName()

        #Temporary Allowing storage account key access (disabled due to SFI)
        $null = Set-AzStorageAccount -ResourceGroupName $FirstHostPoolInthisLocationStorageAccountResourceGroupName -Name $FirstHostPoolInthisLocationStorageAccountName -AllowSharedKeyAccess $true

        $StorageAccountCredentials = cmdkey /list | Select-String -Pattern "Target: Domain:target=$FirstHostPoolInthisLocationStorageAccountName\.file\.core\.windows\.net" -AllMatches
        if ($null -eq $StorageAccountCredentials.Matches) {
            #region Getting the Storage Account Key from the Storage Account
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Getting the Storage Account Key from the '$FirstHostPoolInthisLocationStorageAccountName' StorageAccount"
            $CurrentHostPoolStorageAccountKey = ((Get-AzStorageAccountKey -ResourceGroupName $FirstHostPoolInthisLocationStorageAccountResourceGroupName -AccountName $FirstHostPoolInthisLocationStorageAccountName) | Where-Object -FilterScript { $_.KeyName -eq "key1" }).Value
            #$CurrentHostPoolStorageAccountKey = $CurrentHostPoolStorageAccount | Get-AzStorageAccountKey | Where-Object -FilterScript { $_.KeyName -eq "key1" }).Value
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentHostPoolStorageAccountKey: $CurrentHostPoolStorageAccountKey"
            #endregion

            Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "cmdkey /add:`"$FirstHostPoolInthisLocationStorageAccountName.file.$StorageEndpointSuffix`" /user:`"localhost\$FirstHostPoolInthisLocationStorageAccountName`" /pass:`"$CurrentHostPoolStorageAccountKey`"" -Wait -NoNewWindow
            #endregion
        }


        $MSIXDemoPackages = Get-ChildItem -Path "\\$FirstHostPoolInthisLocationStorageAccountName.file.$StorageEndpointSuffix\msix" -File -Filter "*.vhd?"
        #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-powershell
        foreach ($CurrentMSIXDemoPackage in $MSIXDemoPackages.FullName) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Processing '$CurrentMSIXDemoPackage': $CurrentMSIXDemoPackage"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Get-AzWvdAppAttachPackage:`r`n$(Get-AzWvdAppAttachPackage | Out-String)"

            $AppAttachPackage = Get-AzWvdAppAttachPackage | Where-Object -FilterScript { $_.ImagePath -eq $CurrentMSIXDemoPackage }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackage: $($AppAttachPackage | Out-String)"
            if ($null -eq $AppAttachPackage) {
                #region Importing the App Attach Package
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Importing the MSIX Image '$CurrentMSIXDemoPackage'"
                #Temporary Allowing storage account key access (disabled due to SFI)
                #$null = Set-AzStorageAccount -ResourceGroupName $FirstHostPoolInthisLocationStorageAccountResourceGroupName -Name $FirstHostPoolInthisLocationStorageAccountName -AllowSharedKeyAccess $true
                $MyError = $null
                foreach ($CurrentHostPoolInthisLocation in $AllHostPoolsInthisLocation) {
                    try {
                        $AppAttachPackage = Import-AzWvdAppAttachPackageInfo -HostPoolName $CurrentHostPoolInthisLocation.Name -ResourceGroupName $CurrentHostPoolInthisLocation.GetResourceGroupName() -Path $CurrentMSIXDemoPackage -ErrorAction Stop
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: The MSIX Image '$CurrentMSIXDemoPackage' was imported for the '$($CurrentHostPoolInthisLocation.Name)' HostPool"
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackage: $($AppAttachPackage | Out-String)"
                        break
                    }
                    catch {
                        $AppAttachPackage = $null
                        Write-Warning -Message "AppAttach: The MSIX Image '$CurrentMSIXDemoPackage' can NOT be imported for the '$($CurrentHostPoolInthisLocation.Name)' HostPool"
                        Write-Warning -Message "Exception: $($_.Exception)"
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Exception: $($_.Exception)'"
                    }
                }
                #endregion

                if ($null -ne $AppAttachPackage) {
                    #region Adding the App Attach Package
                    $AppAttachPackageName = "{0}_{1}" -f $AppAttachPackage.ImagePackageAlias, [HostPool]::GetAzLocationShortName($FirstHostPoolInthisLocation.Location)
                    $AppAttachPackageName = $AppAttachPackage.ImagePackageAlias
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackageName: $AppAttachPackageName"

                    $DisplayName = "{0} (v{1})" -f $AppAttachPackage.ImagePackageApplication.FriendlyName, $AppAttachPackage.ImageVersion
                    #$DisplayName = "{0}" -f $AppAttachPackage.ImagePackageApplication.FriendlyName
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Adding the package '$CurrentMSIXDemoPackage' as '$DisplayName' ..."

                    $HostPoolReference = foreach ($CurrentHostPoolInthisLocation in $AllHostPoolsInthisLocation) {
                        $AzWvdHostPool = Get-AzWvdHostPool -Name $CurrentHostPoolInthisLocation.Name -ResourceGroupName $CurrentHostPoolInthisLocation.GetResourceGroupName()
                        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzWvdHostPool.Id: $($AzWvdHostPool.Id)"
                        $AzWvdHostPool.Id
                    }

                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolReference: $($HostPoolReference -join ', ')"
                    $parameters = @{
                        Name                            = $AppAttachPackage.Name
                        ResourceGroupName               = $FirstHostPoolInthisLocationStorageAccountResourceGroupName
                        Location                        = $FirstHostPoolInthisLocation.Location
                        FailHealthCheckOnStagingFailure = 'NeedsAssistance'
                        ImageIsRegularRegistration      = $false
                        ImageDisplayName                = $DisplayName
                        ImageIsActive                   = $true
                        HostPoolReference               = $HostPoolReference
                        AppAttachPackage                = $AppAttachPackage
                        PassThru                        = $true
                    }
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding the '$($AppAttachPackage.Name) AppAttach Package"
                    $AppAttachPackage = New-AzWvdAppAttachPackage @parameters
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackage: $($AppAttachPackage | Out-String)"
                    #endregion
                }
                else {
                    Write-Error -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$CurrentMSIXDemoPackage' could not be imported"
                }
            }
            else {
                $HostPoolReference = foreach ($CurrentHostPoolInthisLocation in $AllHostPoolsInthisLocation) {
                    $AzWvdHostPool = Get-AzWvdHostPool -Name $CurrentHostPoolInthisLocation.Name -ResourceGroupName $CurrentHostPoolInthisLocation.GetResourceGroupName()
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzWvdHostPool.Id: $($AzWvdHostPool.Id)"
                    $AzWvdHostPool.Id
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolReference: $($HostPoolReference -join ', ')"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating the '$($AppAttachPackage.Name) AppAttach Package"
                $AppAttachPackage | Update-AzWvdAppAttachPackage -HostPoolReference $($AppAttachPackage.HostPoolReference + $HostPoolReference)
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackage: $($AppAttachPackage | Out-String)"
            }

            #region HostPool configuration
            foreach ($CurrentHostPool in $HostPool) {
                #region Groups and users
                $CurrentHostPoolDAGUsersADGroupName = "$($CurrentHostPool.Name) - Desktop Application Group Users"
                $CurrentHostPoolRAGUsersADGroupName = "$($CurrentHostPool.Name) - Remote Application Group Users"
                $CurrentHostPoolAGUsersADGroupName = $CurrentHostPoolDAGUsersADGroupName, $CurrentHostPoolRAGUsersADGroupName
                foreach ($CurrentHostPoolAGUsersADGroupName in $CurrentHostPoolDAGUsersADGroupName, $CurrentHostPoolRAGUsersADGroupName) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AppAttachPackage: $($AppAttachPackage | Out-String)"
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the Application to Group '$CurrentHostPoolAGUsersADGroupName' to the '$($AppAttachPackage.Name)' AppAttach Application"
                    $CurrentHostPoolDAGUsersAzADGroup = Get-MgBetaGroup -Filter "DisplayName eq '$CurrentHostPoolAGUsersADGroupName'"
                    foreach ($objId in $CurrentHostPoolDAGUsersAzADGroup.Id) {
                        $DesktopVirtualizationUserRole = Get-AzRoleDefinition "Desktop Virtualization User"
                        $Scope = $AppAttachPackage.Id
                        if (-not(Get-AzRoleAssignment -ObjectId $objId -RoleDefinitionName $DesktopVirtualizationUserRole.Name -Scope $Scope)) {
                            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] AppAttach: Assigning the '$($DesktopVirtualizationUserRole.Name)' RBAC role to the '$objId' Entra ID Group on the '$($AppAttachPackage.Name)' AppAttach Application"
                            $null = New-AzRoleAssignment -ObjectId $objId -RoleDefinitionName $DesktopVirtualizationUserRole.Name -Scope $Scope
                        }
                    }
                }
                #endregion

                #region Publishing AppAttach application to a RemoteApp application group
                #From https://learn.microsoft.com/en-us/azure/virtual-desktop/app-attach-setup?tabs=powershell&pivots=app-attach#publish-an-msix-or-appx-application-with-a-remoteapp-application-group
                if ($CurrentHostPool.PreferredAppGroupType -eq "RailApplications") {
                    $CurrentHostPoolStorageAccountResourceGroupName = $CurrentHostPool.GetAppAttachStorageAccountResourceGroupName()
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentHostPoolResourceGroupName: $CurrentHostPoolResourceGroupName"
                    $CurrentHostPoolResourceGroupName = $CurrentHostPool.GetResourceGroupName()
                    $ApplicationGroupName = "{0}-RAG" -f $CurrentHostPool.Name
                    $CurrentAzRemoteApplicationGroup = Get-AzWvdApplicationGroup -Name $ApplicationGroupName -ResourceGroupName $CurrentHostPoolResourceGroupName
                    $null = New-AzWvdApplication -ResourceGroupName $CurrentHostPoolResourceGroupName -SubscriptionId $SubscriptionId -Name $AppAttachPackage.ImagePackageName -ApplicationType MsixApplication -ApplicationGroupName $CurrentAzRemoteApplicationGroup.Name -MsixPackageFamilyName $AppAttachPackage.ImagePackageFamilyName -CommandLineSetting 0 -MsixPackageApplicationId $AppAttachPackage.ImagePackageApplication.AppId

                }
                #endregion 
            }
            #endregion 
        }    }
}
#endregion

$Global:MaximumFunctionCount = 32768
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -Force
Connect-MgGraph -NoWelcome

#region Creating Host Pools
#region ADJoin User
$AdJoinUserName = 'adjoin'
$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$AdJoinPassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
#endregion

#region Getting Current Azure location (based on the Subnet location of this DC) to deploy the Azure compute Gallery in the same location that the other resources
$ThisDomainControllerSubnet = Get-AzVMSubnet
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
$SecondaryRegionResourceGroupName = "rg-avd-ad-usc-002"
$SecondaryRegionVNetName          = "vnet-avd-avd-usc-002"
$SecondaryRegionSubnetName        = "snet-avd-avd-usc-002"
$SecondaryRegionVNet              = Get-AzVirtualNetwork -Name $SecondaryRegionVNetName -ResourceGroupName $SecondaryRegionResourceGroupName
$SecondaryRegionSubnet            = $SecondaryRegionVNet  | Get-AzVirtualNetworkSubnetConfig -Name $SecondaryRegionSubnetName
$SecondaryRegion                  = $SecondaryRegionVNet.Location
#$SecondaryRegion                  = [HostPool]::GetAzurePairedRegion($PrimaryRegion)
#endregion
#endregion

#region Azure Key Vault for storing ADJoin Credentials
#Doesn't return a PSKeyVault object but a PSKeyVaultIdentityItem
#$HostPoolSessionCredentialKeyVault = Get-AzKeyVault -Name kvavdhpcred* | Select-Object -First 1
#Returns a PSKeyVault object
$VaultName = (Get-AzKeyVault).VaultName | Select-Object -First 1
if (-not([string]::IsNullOrEmpty($VaultName))) {
    $HostPoolSessionCredentialKeyVault = Get-AzKeyVault -VaultName $VaultName
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
$SecondaryRegionAzureEphemeralOsDiskSku = [HostPool]::GetAzureEphemeralOsDiskSku($SecondaryRegion)
#endregion

[int] $RandomNumber = ((Get-AzWvdHostPool | Where-Object -FilterScript { $_.Name -match "^hp-np|pd"}).Name -replace ".*-(\d+)", '$1' | Sort-Object | Select-Object -First 1)-1
[PooledHostPool]::SetIndex($RandomNumber, $PrimaryRegion)
[PersonalHostPool]::SetIndex($RandomNumber, $PrimaryRegion)

[PooledHostPool]::SetIndex($RandomNumber, $SecondaryRegion)
[PersonalHostPool]::SetIndex($RandomNumber, $SecondaryRegion)


[PooledHostPool]::AppAttachStorageAccountNameHT[$PrimaryRegion] = $(Get-AzStorageAccount | Where-Object -FilterScript { $_.PrimaryLocation -eq $PrimaryRegion -and $_.StorageAccountName -match "^saavdappattachpoc"} | Select-Object -First 1).StorageAccountName
[PooledHostPool]::AppAttachStorageAccountNameHT[$SecondaryRegion] = $(Get-AzStorageAccount | Where-Object -FilterScript { $_.PrimaryLocation -eq $SecondaryRegion -and $_.StorageAccountName -match "^saavdappattachpoc"} | Select-Object -First 1).StorageAccountName

$HostPools = @(
    # Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (AD Domain joined) with FSLogix and AppAttach
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetPreferredAppGroupType("RailApplications").EnableAppAttach()
    # Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts for RemoteApp (Azure AD/Microsoft Entra ID joined) with FSLogix and AppAttach
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault, $PrimaryRegionSubnet.Id).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).SetPreferredAppGroupType("RailApplications").EnableAppAttach()
)
#endregion


#region Pre-init
$HostPool = $HostPools
$PooledHostPools = $HostPool | Where-Object -FilterScript { ($null -ne $_ ) -and ($_.Type -eq [HostPoolType]::Pooled) }
#endregion

Add-PsAvdAzureAppAttach -HostPool $PooledHostPools -Verbose
