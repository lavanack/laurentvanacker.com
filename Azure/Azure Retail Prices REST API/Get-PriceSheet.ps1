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

$uri = "https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview&meterRegion='primary'&currencyCode=EUR"
$Items = Do {
    Write-Verbose $uri
    $PriceSheet = Invoke-RestMethod -Method GET -Uri $uri -ContentType "application/json"
    $PriceSheet.Items
    Write-Verbose "Count: $($PriceSheet.Count)"
    #Write-Verbose "Last Item: $($PriceSheet.Items[-1] | Out-String)"
    $uri = $PriceSheet.NextPageLink
} While ($null -ne $uri)
$Items | Export-Csv -Path $CSVFile -NoTypeInformation
Write-Host "Azure Retail Prices have been exported to '$CSVFile' ..."
#Limit on November, 20th 2023 = https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview&meterRegion=%27primary%27&$skip=579870