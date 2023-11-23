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
[CmdletBinding()]
Param ()
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$Extension = (Get-ItemProperty -Path $CurrentScript).Extension
$CSVFile = $CurrentScript -replace "$Extension", $("_{0:yyyyMMddHHmmss}.csv" -f (Get-Date))

Set-Location -Path $CurrentDir

$azContext = Get-AzContext
$SubscriptionID = $azContext.Subscription.Id
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.AccessToken
}
#endregion

$URI = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Consumption/pricesheets/default?api-version=2023-05-01"

$Items = Do {
    Write-Verbose $URI
    $PriceSheet = Invoke-RestMethod -Method GET -Uri $URI -Headers $authHeader
    $PriceSheet.properties.pricesheets
    Write-Verbose "Count: $($PriceSheet.properties.pricesheets.Count)"
    #Write-Verbose "Last Item: $($PriceSheet.properties.pricesheets[-1] | Out-String)"
    $URI = $PriceSheet.properties.NextLink
} While (-not([string]::IsNullOrEmpty($URI)))
$Items | Export-Csv -Path $CSVFile -NoTypeInformation
Write-Host "Azure Prices have been exported to '$CSVFile' ..."