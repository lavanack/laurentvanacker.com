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

#Prerequisite: Windows 365 Enterprise Demo Tenant - 90 days: https://cdx.transform.microsoft.com/experience-detail/bf3b6577-d944-416c-ad35-26763c7aef32

#requires -PSEdition Core #-Modules Az.Accounts, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users, PSCloudPC
#From https://www.nielskok.tech/windows-365/deploy-windows-365-via-powershell/

#region Function Definitions
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

function Set-PsAvdMgUsersGroupLicense {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        #Validating only available intune licenses
        #[ValidateScript({$_ -in $((Get-MgSubscribedSku -All | Where-Object -FilterScript { ($_.ServicePlans.ServicePlanName -match "intune") -and (($_.PrepaidUnits.Enabled - $_.ConsumedUnits) -gt 0)}).SkuPartNumber)})]
        [ValidateSet('CPC_E_2C_4GB_128GB​', 'CPC_E_2C_8GB_256GB​​')]
        [string] $SkuPartNumber = 'CPC_E_2C_4GB_128GB​',
        [Parameter(Mandatory)]
        [ValidateScript({ $_ -in $((Get-MgGroup).DisplayName) })]
        [string] $GroupDisplayName, 
        [switch] $Remove
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $SubscribedSku = Get-MgSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $SkuPartNumber }
    if (($SubscribedSku.PrepaidUnits.Enabled - $SubscribedSku.ConsumedUnits) -gt 0) {
        $Group = Get-MgGroup -Filter "DisplayName eq '$GroupDisplayName'"
    
        #https://developer.microsoft.com/en-us/graph/known-issues/?search=20454
        #$SkuId = (Get-MgSubscribedSku -All -Search "SkuPartNumber:'$SkuPartNumber'").SkuId 
        $SkuId = (Get-MgSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $SkuPartNumber }).SkuId
        if ($Remove) {
            #Bug April 2025 : https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3201
            #Set-MgGroupLicense -GroupId $Group.Id -AddLicenses @{ } -RemoveLicenses @($SkuId)
            # Create JSON payload for license removal
            $body = @{
                "addLicenses"    = @()
                "removeLicenses" = @($SkuId)
            }
        }
        else {
            #Bug April 2025 : https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3201
            #Set-MgGroupLicense -GroupId $Group.Id -AddLicenses @{SkuId = $SkuId } -RemoveLicenses @()
            # Create JSON payload for adding license 
            $Body = @{
                "addLicenses"    = @(
                    @{
                        "skuId" = $SkuId
                    }
                )
                "removeLicenses" = @()
            } 
        }
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/groups/$($Group.Id)/assignLicense" -Body $Body -ContentType "application/json"
    }
    else {
        Write-Warning -Message "No more licenses available for '$SkuPartNumber' ($($SubscribedSku.ConsumedUnits) consumed out of $($SubscribedSku.PrepaidUnits.Enabled))"
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
}
#endregion

#region Powershell Module Setup
$null = Get-PackageProvider -Name NuGet -Force -Verbose
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$RequiredModules = 'Az.Accounts', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Users', 'PSCloudPC'
$InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
if (-not([String]::IsNullOrEmpty($InstalledModule))) {
    $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject $InstalledModule.Name).InputObject
}
else {
    $MissingModules = $RequiredModules
}
if (-not([String]::IsNullOrEmpty($MissingModules))) {
    Install-Module -Name $MissingModules -Scope AllUsers -Force -Verbose
}
#endregion

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount -UseDeviceAuthentication
}
#endregion

#Get-CPCSupportedRegion
$RegionName = "centralus"
$RegionGroup = "usCentral"
$CPCProvisioningPolicyName = "Cloud PC Provisioning Policy - AzureADJoin"
$CPCProvisioningPolicyAssignmentName = "Cloud PC Provisioning Policy - UserSettings"
$FrequencyInHours = 6
$W365GroupName = 'Windows365 Users'
$MailNickname = $($W365GroupName -replace "\s" -replace "\W").ToLower()
$CurrentUser = (Get-MgContext).Account

#region EntraID Group Management
if (-not(Get-MgGroup -Filter "DisplayName eq '$W365GroupName'" -ErrorAction Ignore)) {
    Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Group.ReadWrite.All", "User.Read.All" -UseDeviceCode
    New-MgGroup -DisplayName $W365GroupName -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
}

$W365Group = Get-MgGroup -Filter "DisplayName eq '$W365GroupName'"
if ((Get-MgUser -UserId $CurrentUser).Id -notin (Get-MgGroupMember -GroupId $W365Group.Id)) {
    New-MgGroupMember -GroupId $W365Group.Id -DirectoryObjectId (Get-MgUser -UserId $CurrentUser).Id
}
else {
    Write-Warning -Message "'$CurrentUser' is already member of the '$W365GroupName' Group ..."
}
#endregion

#region PSCloudPC Module
Connect-Windows365 -DeviceCode
New-CPCProvisioningPolicy -Name $CPCProvisioningPolicyName -Description $CPCProvisioningPolicyName -RegionName $RegionName -RegionGroup $RegionGroup -ImageId "microsoftwindowsdesktop_windows-ent-cpc_win11-25h2-ent-cpc-m365" -EnableSingleSignOn $true -DomainJoinType azureADJoin
New-CPCUserSettingsPolicy -Name $CPCProvisioningPolicyAssignmentName -LocalAdminEnabled $false -UserRestoreEnabled $true -FrequencyInHours $FrequencyInHours
Set-CPCProvisioningPolicyAssignment -Name $CPCProvisioningPolicyName -GroupName $W365GroupName
Set-CPCUserSettingsPolicyAssignment -Name $CPCProvisioningPolicyAssignmentName -GroupName $W365GroupName
#endregion

#region Assigning E5 and Teams licenses (if available) to the 'Windows365 Users' Entra ID Group
#$SkuPartNumber = 'CPC_E_2C_8GB_256GB​​'
$SkuPartNumber = 'CPC_E_2C_4GB_128GB​'
foreach ($CurrentSkuPartNumber in $SkuPartNumber) {
    #https://developer.microsoft.com/en-us/graph/known-issues/?search=20454
    #$SubscribedSku = Get-MgSubscribedSku -All -Search "CurrentSkuPartNumber:'$CurrentSkuPartNumber'"
    $SubscribedSku = Get-MgSubscribedSku -All | Where-Object -FilterScript { $_.SkuPartNumber -eq $CurrentSkuPartNumber }
    $SubscribedSkuAvailableLicenses = $SubscribedSku.PrepaidUnits.Enabled - $SubscribedSku.ConsumedUnits
    Write-Verbose -Message "'$CurrentSkuPartNumber' Available License Number: $SubscribedSkuAvailableLicenses"
    if ($SubscribedSkuAvailableLicenses -gt 0) {
        Set-PsAvdMgUsersGroupLicense -GroupDisplayName $W365GroupName -SkuPartNumber $CurrentSkuPartNumber -Verbose
    }
    else {
        Write-Verbose -Message "No more licenses availables for '$CurrentSkuPartNumber'"
        $AssignedLicenses = Get-MgUser -Filter "assignedLicenses/any(x:x/skuId eq $($SubscribedSku.SkuId) )" -ConsistencyLevel eventual -CountVariable e5licensedUserCount -All
        Write-Verbose -Message "Assigned Licenses for '$CurrentSkuPartNumber': $($AssignedLicenses.DisplayName -join ', ')"
        $AVDUserGroupMembersWithoutAssignedLicenses = Get-MgUser -Filter "not(assignedLicenses/any(x:x/skuId eq $($SubscribedSku.SkuId))) and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable e5licensedUserCount -All | Where-Object -FilterScript { $_.Id -in $((Get-MgGroupMember -GroupId $(Get-MgGroup -Filter "DisplayName eq '$W365GroupName'").Id).Id) }
        Write-Verbose -Message "'$W365GroupName' Group Members Without Assigned Licenses for '$CurrentSkuPartNumber': $($AVDUserGroupMembersWithoutAssignedLicenses.DisplayName -join ', ')"
    }
}
#endregion