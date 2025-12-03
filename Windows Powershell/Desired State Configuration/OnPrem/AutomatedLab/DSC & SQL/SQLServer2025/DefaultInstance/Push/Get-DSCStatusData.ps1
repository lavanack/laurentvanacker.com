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

#region Function Definition(s)
#From https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/reportserver?view=powershell-7
function Get-DSCReport {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        $AgentId = "$((Get-DscLocalConfigurationManager).AgentId)", 
        $serviceURL = "$((Get-DscLocalConfigurationManager).ReportManagers.ServerUrl)"
    )

    $requestUri = "$serviceURL/Nodes(AgentId= '$AgentId')/Reports"
    $request = Invoke-WebRequest -Uri $requestUri  -ContentType "application/json;odata=minimalmetadata;streaming=true;charset=utf-8" `
        -UseBasicParsing -Headers @{Accept = "application/json"; ProtocolVersion = "2.0" } `
        -ErrorAction SilentlyContinue -ErrorVariable ev
    $object = ConvertFrom-Json $request.content
    return $object.value
}

function Get-DSCStatusData {
    param
    (
        $AgentId = "$((Get-DscLocalConfigurationManager).AgentId)", 
        $serviceURL = "$((Get-DscLocalConfigurationManager).ReportManagers.ServerUrl)"
    )

    $DSCReport = Get-DSCReport
    $StatusData = $DSCReport.StatusData | ConvertFrom-Json
    return $StatusData
}
#endregion

#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

Get-DSCStatusData | Out-GridView
#endregion