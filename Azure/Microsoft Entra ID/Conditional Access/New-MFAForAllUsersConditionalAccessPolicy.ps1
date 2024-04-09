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

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

# Connect to Microsoft Graph
Connect-MgGraph -NoWelcome

#region Function definitions
function New-NoMFAUserEntraIDGroup {
    [CmdletBinding()]
    param (
        [string] $NoMFAEntraIDGroupName = 'No-MFA Users'
    )
    $NoMFAEntraIDGroup = Get-MgBetaGroup -Filter "displayName eq '$NoMFAEntraIDGroupName'"
    $MailNickname = $($NoMFAEntraIDGroupName -replace "\s" -replace "\W").ToLower()
    if (-not($NoMFAEntraIDGroup)) {
        Write-Verbose -Message "Creating '$NoMFAEntraIDGroupName' Entra ID Group ..."
        $NoMFAEntraIDGroup = New-MgGroup -DisplayName $NoMFAEntraIDGroupName -MailEnabled:$False -MailNickname $MailNickname -SecurityEnabled
    }
    $NoMFAEntraIDGroup
}

function New-MFAForAllUsersConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [string[]] $ExcludeGroupName = 'No-MFA Users',
        [string] $DisplayName = "[AVD] Require multifactor authentication for all users"
    )
    $ExcludeGroups = foreach ($CurrentExcludeGroupName in $ExcludeGroupName) {
        Get-MgBetaGroup -Filter "displayName eq '$CurrentExcludeGroupName'"
    }

    $MFAForAllUsersConditionalAccessPolicy = Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq '$DisplayName'"
    if (-not($MFAForAllUsersConditionalAccessPolicy)) {
        # Define the policy properties
        $policyProperties = @{
            DisplayName = $DisplayName
            State = "Enabled"
            Conditions = @{
                Applications = @{
                    IncludeApplications = @("All")
                }
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeGroups = $ExcludeGroups.Id
                }
            }
            GrantControls = @{
                BuiltInControls = @("Mfa")
                Operator = "OR"
            }
        }

        # Create the policy
        Write-Verbose -Message "Creating '$DisplayName' Conditional Access Policy ..."
        $MFAForAllUsersConditionalAccessPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyProperties -Verbose
    }
    $MFAForAllUsersConditionalAccessPolicy
}
#endregion

$NoMFAEntraIDGroupName = "No-MFA Users"
$NoMFAEntraIDGroup = New-NoMFAUserEntraIDGroup -NoMFAEntraIDGroupName $NoMFAEntraIDGroupName -Verbose
$MFAForAllUsersConditionalAccessPolicy = New-MFAForAllUsersConditionalAccessPolicy -ExcludeGroupName $NoMFAEntraIDGroup.DisplayName -Verbose