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
#requires -Version 5

[CmdletBinding()]
param
(
	[parameter(Mandatory = $false)]
	[switch]$Transcript
)

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
$Timestamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
if ($Transcript)
{
    $TranscriptFile = $CurrentScript -replace ".ps1$", "_$Timestamp.txt"
    Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader
}

#region Secrets
$APIKey          = "replace0-with-your-own0-apikey000000"
$AdminPassword   = "ReplaceWithYourOwnAdminPassword"
$AZNamingToolURI = "ReplaceWithYourOwnURL"
#endregion


#region ImportExport: Export
$Headers = @{ APIKey = $APIKey}
$Configuration = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ImportExport/ExportConfiguration?includeAdmin=true
$Configuration | ConvertTo-Json -Depth 100 | Set-Content -Path "$CurrentDir\globalconfig_$Timestamp.json"
#endregion

<#
#WARNING : Be careful if you uncomment this because it will reset everything !!!! (But the code above made a backup ...)
#region Admin: POST ResetSiteConfiguration
$Headers = @{ APIKey = $APIKey; AdminPassword=$AdminPassword }
$ResetSiteConfiguration = Invoke-RestMethod -Method POST -Header $Headers -ContentType "application/json" -Uri $AZNamingToolURI/api/Admin/ResetSiteConfiguration
$ResetSiteConfiguration
#endregion
#>

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

#region ResourceTypes: GET ResourceTypes
$Headers = @{ APIKey = $APIKey}
$ResourceTypes = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceTypes
$ResourceTypes
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

#region ResourceEnvironments: GET ResourceLocation
$Headers = @{ APIKey = $APIKey}
$ResourceLocations = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceLocations
$ResourceLocations
#endregion

#region ResourceEnvironments: GET ResourceFunctions
$Headers = @{ APIKey = $APIKey}
$ResourceFunctions = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceFunctions
$ResourceFunctions
#endregion

#region ResourceEnvironments: GET ResourceUnitDepts
$Headers = @{ APIKey = $APIKey}
$ResourceUnitDepts = Invoke-RestMethod -Method GET -Header $Headers -Uri $AZNamingToolURI/api/ResourceUnitDepts
$ResourceUnitDepts
#endregion

#region ResourceNamingRequests: POST RequestName
#region Random Request Name for every resource type
$CurrentResourceIndex = 0
$ResourceTypes | ForEach-Object -Process {
    $CurrentResource = $_.resource
    $CurrentResourceIndex++
    Write-Verbose "Processing '$CurrentResource' ..."
    Write-Progress -Activity "[$($CurrentResourceIndex)/$($ResourceTypes.Count)] Processing '$CurrentResource'" -Status "Percent : $('{0:N0}' -f $($CurrentResourceIndex/($ResourceTypes.Count) * 100)) %" -PercentComplete ($CurrentResourceIndex / $ResourceTypes.Count * 100)
    $Headers = @{ APIKey = $APIKey }
    $Body = [ordered]@{ 
        "resourceType" = $_.shortName
        "resourceId" = $_.Id
        "resourceOrg" = $ResourceOrgs.shortName | Get-Random 
        "resourceUnitDept" = $ResourceUnitDepts.shortName | Get-Random
        "resourceProjAppSvc" = $ResourceProjAppSvcs.shortName | Get-Random 
        "resourceFunction" = $ResourceFunctions.shortName | Get-Random 
        "resourceEnvironment" = $ResourceEnvironments.shortName | Get-Random 
        "resourceLocation" = $ResourceLocations.shortName | Get-Random 
        "resourceInstance" = '{0:D3}' -f $(Get-Random -Minimum 0 -Maximum 999)
<#
        "customComponents" = @{
            "region" = Get-Random $CustomComponents.shortName
        }
#>
    }
    $Body | Format-Table
    try
    {
        $Response = Invoke-RestMethod -Method POST -Headers $Headers -Body $($Body | ConvertTo-Json) -ContentType "application/json" -Uri $AZNamingToolURI/api/ResourceNamingRequests/RequestName -ErrorVariable ResponseError
    }
    catch [System.Net.WebException] {   
        # Dig into the exception to get the Response details.
        # Note that value__ is not a typo.
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $respStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $Response = $reader.ReadToEnd() | ConvertFrom-Json
        Write-Warning -Message $Response.message
    }
    finally 
    {
        $Response | Format-List
    }
}
Write-Progress -Activity 'Completed !' -Status 'Completed !' -Completed

#endregion
#endregion

if ($Transcript)
{
    Stop-Transcript
    & $TranscriptFile
}