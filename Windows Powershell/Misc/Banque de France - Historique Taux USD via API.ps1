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
Clear-Host
# To get the directory of this script
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$CSVFile = Join-Path -Path $CurrentDir -ChildPath $("BanqueDeFrance_USD_ExchangeRates_{0:yyyyMMddHHmmss}.csv" -f (Get-Date))


#From https://webstat.banque-france.fr/fr/catalogue/exr/EXR.D.USD.EUR.SP00.A
$URI = "https://webstat.banque-france.fr/api/explore/v2.1/catalog/datasets/observations/exports/json/?where=series_key+IN+%28%22EXR.D.USD.EUR.SP00.A%22%29&order_by=-time_period_start"
#Get you API Key from https://webstat.banque-france.fr/account/api-keys/
$ApiKey = "PutYourOwnAPIKeyHere"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Apikey {0}' -f $ApiKey
}

try {
    # Invoke the REST API
    $Response = Invoke-RestMethod -Method GET -Headers $authHeader -Uri $URI -ErrorVariable ResponseError
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
    if (-not([string]::IsNullOrEmpty($Response.message))) {
        Write-Warning -Message $Response.message
    }
}
finally {
}
$Response | Export-Csv -Path $CSVFile -NoTypeInformation
& $CSVFile