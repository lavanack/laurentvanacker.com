<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment. THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free
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
#requires -Version 5 -RunAsAdministrator
Clear-Host
Get-Variable -Scope Script | Remove-Variable -ErrorAction Ignore

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
#region Secrets
$APIKey          = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$AdminPassword   = "I@m@JediLikeMyF@therB4Me"
$AZNamingToolURI = "http://ant314159265359.westus3.cloudapp.azure.com"
#endregion

#region Admin: GET Admin Log
$Headers = @{ APIKey = $APIKey}
$GeneratedNamesLog = Invoke-RestMethod -Method GET -Header $Headers -ContentType "application/json" -Uri $AZNamingToolURI/api/Admin/GetGeneratedNamesLog
$GeneratedNamesLog
#endregion

#region CustomComponents: GET Custom Components
$Headers = @{ APIKey = $APIKey}
$CustomComponents = Invoke-RestMethod -Method GET -Header $Headers -ContentType "application/json" -Uri $AZNamingToolURI/api/CustomComponents
$CustomComponents
#endregion

#region ImportExport: Export
$Headers = @{ APIKey = $APIKey}
$Configuration = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ImportExport/ExportConfiguration?includeAdmin=true
$Configuration | ConvertTo-Json | Set-Content -Path "$CurrentDir\globalconfig_$("{0:yyyyMMddHHmmss}" -f (GET-Date)).json"
#endregion

#region ResourceTypes: GET ResourceTypes
$Headers = @{ APIKey = $APIKey}
$ResourceTypes = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceTypes
$ResourceTypes
$FilteredResourceTypes = $ResourceTypes | Where-Object -FilterScript {$_.shortName -in "mg", "rg", "subcr"}
#endregion

#region ResourceOrgs: GET ResourceOrgs
$Headers = @{ APIKey = $APIKey}
$ResourceOrgs = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceOrgs
$ResourceOrgs
#endregion

#region ResourceProjAppSvc: GET ResourceProjAppSvcs
$Headers = @{ APIKey = $APIKey}
$ResourceProjAppSvcs = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceProjAppSvcs
$ResourceProjAppSvcs
#endregion

#region ResourceEnvironments: GET ResourceEnvironments
$Headers = @{ APIKey = $APIKey}
$ResourceEnvironments = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceEnvironments
$ResourceEnvironments
#endregion

#region ResourceNamingRequests: POST RequestName
#region Subscription Group
$Headers = @{ APIKey = $APIKey }
$Body = @{ 
    "resourceType" = "subcr"
    "resourceOrg" = "cibus"
    "ResourceProjAppSvc" = "avd"
    "ResourceEnvironment" = "dev"
    "customComponents" = @{
        "region" = "in"
    }
}

try
{
    $Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $AZNamingToolURI/api/ResourceNamingRequests/RequestName -ErrorVariable ResponseError
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Verbose -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Verbose -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
}
finally 
{
    $Response
}
#endregion

#region Management Group
$Headers = @{ APIKey = $APIKey }
$Body = @{ 
    "resourceType" = "mg"
    "resourceOrg" = "itgdw"
    "ResourceProjAppSvc" = "hvd"
    "ResourceEnvironment" = "prd"
    "customComponents" = @{
        "region" = "in"
    }
}

try
{
    $Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $AZNamingToolURI/api/ResourceNamingRequests/RequestName -ErrorVariable ResponseError
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Verbose -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Verbose -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
}
finally 
{
    $Response
}
#endregion

#region Resource Group
$Headers = @{ APIKey = $APIKey }
$Body = @{ 
    "resourceType" = "rg"
    "resourceOrg" = "bp2i"
    "ResourceProjAppSvc" = "hvd"
    "ResourceEnvironment" = "prd"
    "customComponents" = @{
        "region" = "ua"
    }
}

try
{
    $Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $AZNamingToolURI/api/ResourceNamingRequests/RequestName -ErrorVariable ResponseError
}
catch [System.Net.WebException] {   
    # Dig into the exception to get the Response details.
    # Note that value__ is not a typo.
    Write-Verbose -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
    Write-Verbose -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
    $respStream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($respStream)
    $Response = $reader.ReadToEnd() | ConvertFrom-Json
}
finally 
{
    $Response
}
#endregion

#region Random Request Name
1..10 | ForEach-Object -Process {
    $Headers = @{ APIKey = $APIKey }
    $Body = @{ 
        "resourceType" = Get-Random $FilteredResourceTypes.shortName
        "resourceOrg" = Get-Random $ResourceOrgs.shortName
        "ResourceProjAppSvc" = Get-Random $ResourceProjAppSvcs.shortName
        "ResourceEnvironment" = Get-Random $ResourceEnvironments.shortName
        "customComponents" = @{
            "region" = Get-Random $CustomComponents.shortName
        }
    }

    try
    {
        $Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $AZNamingToolURI/api/ResourceNamingRequests/RequestName -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Verbose -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Verbose -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
    }
    finally 
    {
        $Response
    }
}

#endregion
#endregion
