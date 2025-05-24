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
#requires -Version 5 -Modules Az.Accounts, Az.Resources, Az.Resources

#region Function Definitions
function Get-AzDeletedStorageAccount {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    # Define your subscription ID
    $subscriptionId = (Get-AzContext).Subscription.Id

    # Define the API version
    $apiVersion = "2021-04-01"

    # Define the URL for the REST API
    $url = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Storage/deletedAccounts?api-version=$apiVersion"

    # Get the access token
    $token = (Get-AzAccessToken).Token

    # Make the REST API call
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers @{Authorization = "Bearer $token" }

    # Return the deleted storage accounts
    $response.value
}

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
$CSVFile = $CurrentScript -replace ".ps1$", $("_{0:yyyyMMddHHmmss}.csv" -f (Get-Date))

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$Result = Get-AzDeletedStorageAccount #-Verbose
$Result | Export-Csv -Path $CSVFile -NoTypeInformation
& $CSVFile

#endregion