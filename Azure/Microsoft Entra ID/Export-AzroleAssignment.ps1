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


#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$TimeStamp = "{0:yyyyMMddHHmmss}" -f $(Get-Date)
$CurrentSubScription = (Get-Azcontext).SubScription
$DisplayName = "AVD Users"
$AzADGroup = Get-AzADGroup -DisplayName $DisplayName

#Going through all subscriptions
foreach ($Subscription in Get-AzSubscription) {
    #Creating a CSV File per Subscription for exporting data
    $CSVFile = Join-Path -Path $CurrentDir -ChildPath $("{0} - {1} - {2}.csv" -f $Subscription.Name, $AzADGroup.DisplayName, $Timestamp)
    $CurrentScript -replace "\.ps1", $("_{0:yyyyMMddHHmmss}.csv" -f $Timestamp)
    Write-Host "Switching to '$($Subscription.Name) ..."
    Select-AzSubscription -Subscription $Subscription
    $RoleAssignment = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.Id)" -ObjectId $AzADGroup.Id
    $RoleAssignment | Export-Csv -Path $CSVFile -NoTypeInformation
    & $CSVFile
}

#Switching back to the original Subscription
$CurrentSubScription | Select-AzSubscription 
#endregion