#region Function 
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

#From https://azure.github.io/azure-monitor-baseline-alerts/patterns/specialized/avd/
function New-PsAvdAzureMonitorBaselineAlertsDeployment {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [HostPool[]] $HostPool,

        [Parameter(Mandatory = $false)]
        [string] $Location = "EastUs",
        
        [switch] $PassThru
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $StartTime = Get-Date
    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    $Index = 1
    $ResourceGroupName = "rg-avd-amba-poc-{0}-{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index
    $LogAnalyticsWorkSpaceName = "logavdambapoc{0}{1:D3}" -f $AzLocationShortNameHT[$Location].shortName, $Index

    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }

    $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroupName -Force


    #region AMBA Template Download
    $AMBAAVDURI = "https://raw.githubusercontent.com/Azure/azure-monitor-baseline-alerts/main/patterns/avd/avdArm.json"
    $TemplateFileName = Split-Path -Path $AMBAAVDURI -Leaf
    $TemplateFile = Join-Path -Path $CurrentDir -ChildPath $TemplateFileName
    Invoke-RestMethod -Uri $AMBAAVDURI -OutFile $TemplateFile
    Write-Verbose -Message "`$TemplateFilePath: $TemplateFilePath ..."
    #endregion

    #region AMBA Template Deployment
    $hostPoolInfo = @()
    $storageAccountResourceIds =  @()
    foreach ($CurrentHostPool in $HostPools) {
        Write-Verbose "Processing '$($CurrentHostPool.Name)' HostPool ..."
        $colHostPoolName = (Get-AzWvdHostPool -Name $CurrentHostPool.Name -ResourceGroupName $CurrentHostPool.GetResourceGroupName()).Id
        $colVMresGroup = (Get-AzResourceGroup -Name $CurrentHostPool.GetResourceGroupName() -Location $CurrentHostPool.Location).ResourceId
        $hostPoolInfo += @{colHostPoolName = $colHostPoolName; colVMresGroup = $colVMresGroup}

        if ($CurrentHostPool.MSIX) {
            Write-Verbose "'$($CurrentHostPool.Name)' MSIX: $($CurrentHostPool.MSIX)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }
        if ($CurrentHostPool.AppAttach) {
            Write-Verbose "'$($CurrentHostPool.Name)' AppAttach: $($CurrentHostPool.AppAttach)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetMSIXStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }
        if ($CurrentHostPool.FSlogix) {
            Write-Verbose "'$($CurrentHostPool.Name)' FSlogix: $($CurrentHostPool.FSlogix)"
            $StorageAccount = Get-AzStorageAccount -Name $CurrentHostPool.GetFSLogixStorageAccountName() -ResourceGroupName $CurrentHostPool.GetResourceGroupName()
            $storageAccountResourceIds += $StorageAccount.Id
        }

    }
    $TemplateParameterObject = @{
        "optoutTelemetry" = $false
        "AlertNamePrefix" = "AVD"
        "AllResourcesSameRG" = $false
        "AutoResolveAlert" = $true
        "DistributionGroup" = (Get-AzContext).Account.Id
        "Environment" = "t"
        "hostPoolInfo" = $hostPoolInfo
        "location" = $Location
        "logAnalyticsWorkspaceResourceId" = $LogAnalyticsWorkSpace.ResourceId
        "resourceGroupName" = $ResourceGroup.ResourceGroupName
        "resourceGroupStatus" = "Existing"
        "storageAccountResourceIds" = $storageAccountResourceIds
    }
    $TemplateParameterObject | ConvertTo-Json -Depth 100 | Set-Clipboard
    Write-Host -Object "Starting Subscription Deployment from '$TemplateFile' ..."
    $Attempts = 0
    Do {
        $Attempts++
        Write-Verbose "Attempts: $Attempts"
        #Don't know why but the first deployment always fails
        $SubscriptionDeployment = New-AzDeployment -Location $Location -TemplateFile $TemplateFile -TemplateParameterObject $TemplateParameterObject -ErrorAction Ignore #-Verbose
    }  while (($SubscriptionDeployment.ProvisioningState -ne "Succeeded") -or ($Attempts -ge 3))
    #endregion

    $EndTime = Get-Date
    $TimeSpan = New-TimeSpan -Start $StartTime -End $EndTime
    Write-Host -Object "Azure Subscription Deployment Processing Time: $($TimeSpan.ToString())"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    if ($PassThru) {
        return $ResourceGroup
    }
}
#endregion

Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$Global:MaximumFunctionCount = 32768
$null = Remove-Module -Name PSAzureVirtualDesktop -Force -ErrorAction Ignore
Import-Module -Name PSAzureVirtualDesktop -Force
$Location = "EastUS2"

#region Creating Host Pools
#region ADJoin User
$AdJoinUserName = 'adjoin'
$ClearTextPassword = 'I@m@JediLikeMyF@therB4Me'
$AdJoinPassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$AdJoinCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinPassword)
#endregion
#region Azure Key Vault for stroing ADJoin Credentials
$HostPoolSessionCredentialKeyVault = Get-AzKeyVault -VaultName kvavdhpcreduse2* | Select-Object -First 1
if (-not($HostPoolSessionCredentialKeyVault)) {
    $HostPoolSessionCredentialKeyVault = New-PsAvdHostPoolSessionHostCredentialKeyVault -ADJoinCredential $ADJoinCredential -Location $Location #-AzFileShareACEManagerCredential $AzFileShareACEManagerCredential
}
#endregion

[int] $RandomNumber = ((Get-AzWvdHostPool).Name -replace ".*-(\d+)", '$1' | Sort-Object | Select-Object -First 1)-1
[PooledHostPool]::Index = $RandomNumber
[PersonalHostPool]::Index = $RandomNumber

$HostPools = @(
    # Use case 1: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and MSIX
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetPreferredAppGroupType([Microsoft.Azure.PowerShell.Cmdlets.DesktopVirtualization.Support.PreferredAppGroupType]::RailApplications)#.EnableSpotInstance()
    # Use case 2: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix, MSIX, Ephemeral OS Disk (ResourceDisk mode) and a Standard_D8ds_v5 size (compatible with Ephemeral OS Disk)
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMSize('Standard_D8ds_v5').EnableEphemeralOSDisk([DiffDiskPlacement]::ResourceDisk)
    # Use case 3: Deploy a Pooled HostPool with 3 (default value) Session Hosts (AD Domain joined) with FSLogix and AppAttach
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).EnableAppAttach()
    # Use case 4: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined) with FSLogix and Spot Instance VMs and setting the LoadBalancer Type to DepthFirst
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableSpotInstance().SetLoadBalancerType([Microsoft.Azure.PowerShell.Cmdlets.DesktopVirtualization.Support.LoadBalancerType]::DepthFirst)
    # Use case 5: Deploy a Pooled HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined, enrolled with Intune) with FSLogix and a Scaling Plan
    [PooledHostPool]::new($HostPoolSessionCredentialKeyVault).EnableIntune().EnableScalingPlan()#.SetVMNumberOfInstances(1).EnableSpotInstance()
    # Use case 6: Deploy a Personal HostPool with 2 Session Hosts (AD Domain joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and Hibernation enabled 
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetVMNumberOfInstances(2).EnableHibernation()
    # Use case 7: Deploy a Personal HostPool with 3 (default value) Session Hosts (Azure AD/Microsoft Entra ID joined and without FSLogix and MSIX - Not necessary for Personal Desktops) and a Scaling Plan 
    [PersonalHostPool]::new($HostPoolSessionCredentialKeyVault).SetIdentityProvider([IdentityProvider]::MicrosoftEntraID).EnableScalingPlan()
)
#endregion

Remove-AzResourceGroup -Name rg-avd-amba-poc-use2-001 -Force -Verbose -ErrorAction Ignore
$AMBAResourceGroup = New-PsAvdAzureMonitorBaselineAlertsDeployment -Location $Location -HostPool $HostPools -PassThru -Verbose

#region Cleanup
$Job = Get-AzMetricAlertRuleV2 | Where-Object -FilterScript { $_.Scopes -match $($HostPools.Name -join "|") } | Remove-AzMetricAlertRuleV2 -Verbose -AsJob
Get-AzScheduledQueryRule | Where-Object -FilterScript { $_.CriterionAllOf.Query -match $($HostPools.Name -join "|") } | Remove-AzScheduledQueryRule -Verbose
$Job | Receive-Job -Wait -AutoRemoveJob
#endregion