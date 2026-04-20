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

#requires -Version 5 -Modules Microsoft.Graph.Beta.Identity.SignIns
#region Function definitions
function New-AVDEntraIDGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string] $GroupName
    )
    $AVDInternetEntraIDGroup = Get-MgBetaGroup -Filter "displayName eq '$GroupName'"
    $MailNickname = $($GroupName -replace "\s" -replace "\W").ToLower()
    if (-not($AVDInternetEntraIDGroup)) {
        Write-Verbose -Message "Creating '$GroupName' Entra ID Group ..."
        $AVDInternetEntraIDGroup = New-MgGroup -DisplayName $GroupName -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
    }
    $AVDInternetEntraIDGroup
}

function New-AVDInternetConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [string[]] $GroupName = "AVD - Internet Users",
        [string] $DisplayName = "[AVD] Internet Access",
        [Parameter(Mandatory = $True)]
        [ValidateScript({ $_ -in (Get-MgIdentityConditionalAccessNamedLocation).DisplayName })]
        [string] $NamedLocation
    )
    $IncludeGroups = foreach ($CurrentEntraIDGroupName in $GroupName) {
        Get-MgBetaGroup -Filter "displayName eq '$CurrentEntraIDGroupName'"
    }
    $CAPNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -All | Where-Object -FilterScript { $_.DisplayName -eq $NamedLocation }
    $ConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
    if (-not($ConditionalAccessPolicy)) {
        # Define the policy properties
        $policyProperties = @{
            DisplayName = $DisplayName
            State = "Enabled"
            Conditions = @{
                clientAppTypes = @("All")
                Applications = @{
                    IncludeApplications = @("All")
                }
                Users = @{
                    IncludeGroups = $IncludeGroups.Id
                }
                Locations      = @{
                    includeLocations = @($CAPNamedLocation.Id)
                }
            }
            GrantControls = @{
                BuiltInControls = @("block")
                Operator = "OR"
            }
        }

        # Create the policy
        Write-Verbose -Message "Creating '$DisplayName' Conditional Access Policy ..."
        $ConditionalAccessPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyProperties -Verbose
    }
    else {
        Write-Warning "'$DisplayName' Conditional Access Policy already exists (and has not be overwritten)"
    }
    $ConditionalAccessPolicy
}

function New-AVDInternalConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [string[]] $GroupName = "AVD - Internal Users",
        [string] $DisplayName = "[AVD] Internal Access",
        [Parameter(Mandatory = $True)]
        [ValidateScript({ $_ -in (Get-MgIdentityConditionalAccessNamedLocation).DisplayName })]
        [string] $NamedLocation
    )
    $IncludeGroups = foreach ($CurrentEntraIDGroupName in $GroupName) {
        Get-MgBetaGroup -Filter "displayName eq '$CurrentEntraIDGroupName'"
    }
    $CAPNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -All | Where-Object -FilterScript { $_.DisplayName -eq $NamedLocation }
    $ConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
    if (-not($ConditionalAccessPolicy)) {
        # Define the policy properties
        $policyProperties = @{
            DisplayName = $DisplayName
            State = "Enabled"
            Conditions = @{
                clientAppTypes = @("All")
                Applications = @{
                    IncludeApplications = @("All")
                }
                Users = @{
                    IncludeGroups = $IncludeGroups.Id
                }
                Locations      = @{
                    includeLocations = @("All")
                    excludeLocations = @($CAPNamedLocation.Id)
                }
            }
            GrantControls = @{
                BuiltInControls = @("block")
                Operator = "OR"
            }
        }

        # Create the policy
        Write-Verbose -Message "Creating '$DisplayName' Conditional Access Policy ..."
        $ConditionalAccessPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyProperties -Verbose
    }
    else {
        Write-Warning "'$DisplayName' Conditional Access Policy already exists (and has not be overwritten)"
    }
    $ConditionalAccessPolicy
}
#endregion


#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion

#region Microsoft Graph Connection
try {
    $null = Get-MgDevice -All -ErrorAction Stop
}
catch {
    Connect-MgGraph -NoWelcome
}
#endregion

$AVDInternetEntraIDGroupName = "AVD - Internet Users"
$AVDInternetEntraIDGroup = New-AVDEntraIDGroup -GroupName $AVDInternetEntraIDGroupName -Verbose
$MFAForAllUsersConditionalAccessPolicy = New-AVDInternetConditionalAccessPolicy -GroupName $AVDInternetEntraIDGroup.DisplayName -NamedLocation AVDP2VPN -Verbose

$AVDInternalEntraIDGroupName = "AVD - Internal Users"
$AVDInternalEntraIDGroup = New-AVDEntraIDGroup -GroupName $AVDInternalEntraIDGroupName -Verbose
$MFAForAllUsersConditionalAccessPolicy = New-AVDInternalConditionalAccessPolicy -GroupName $AVDInternalEntraIDGroup.DisplayName -NamedLocation AVDP2VPN -Verbose
#endregion