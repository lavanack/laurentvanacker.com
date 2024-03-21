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
#requires -Version 5 -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param
(
    [switch] $Filter,
    [ValidateScript({$_ -in 1..8})]
    [int] $Hour = 8
)

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentScriptName = Split-Path -Path $CurrentScript -Leaf
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

# Login to your Azure subscription.
While (-not(Get-AzContext)) {
    Connect-AzAccount
}

#region Getting Eligible assignements for Azure Resource
$scope = "/subscriptions/{0}" -f $($(Get-AzContext).Subscription.Id)
$Principal = (Get-AzADUser -ObjectId (Get-AzContext).Account)
if ($Filter) {
    $AzRoleEligibilitySchedule = Get-AzRoleEligibilitySchedule -Scope $scope -Filter "asTarget()" | Select-Object -Property * | Out-GridView -PassThru
}
else {
    $AzRoleEligibilitySchedule = Get-AzRoleEligibilitySchedule -Scope $scope -Filter "asTarget()"
}
#endregion

#region Activating Eligible assignements for Azure Resource
$Justification = "'{0}' script run by '{1} for {2}'" -f $CurrentScriptName, $(whoami), $Principal.UserPrincipalName
$ExpirationDuration = "PT{0}H" -f $Hour
$AzRoleEligibilitySchedule | ForEach-Object -Process {
    Write-Host "[$($Principal.UserPrincipalName)] Activating '$($_.RoleDefinitionDisplayName)' Role on '$($_.ScopeDisplayName)' Azure Resource for $Hour hours ..."
    $startTime = Get-Date -Format o 
    try {
        $null = New-AzRoleAssignmentScheduleRequest -Name $((New-Guid).Guid) -Scope $_.ScopeId -ExpirationDuration $ExpirationDuration -ExpirationType AfterDuration -PrincipalId $Principal.Id -RequestType SelfActivate -RoleDefinitionId $_.RoleDefinitionId -Justification $Justification -TicketNumber $null -TicketSystem $null -ErrorAction Stop
    }
    catch {
        Write-Warning -Message "$($_.Exception.Message)"
    }
}
#endregion