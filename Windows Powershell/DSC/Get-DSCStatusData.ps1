#From https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/reportserver?view=powershell-7
function Get-DSCReport
{
    param
    (
        $AgentId = "$((glcm).AgentId)", 
        $serviceURL = "$((glcm).ReportManagers.ServerUrl)"
    )

    $requestUri = "$serviceURL/Nodes(AgentId= '$AgentId')/Reports"
    $request = Invoke-WebRequest -Uri $requestUri  -ContentType "application/json;odata=minimalmetadata;streaming=true;charset=utf-8" `
               -UseBasicParsing -Headers @{Accept = "application/json";ProtocolVersion = "2.0"} `
               -ErrorAction SilentlyContinue -ErrorVariable ev
    $object = ConvertFrom-Json $request.content
    return $object.value
}

function Get-DSCStatusData
{
    param
    (
        $AgentId = "$((glcm).AgentId)", 
        $serviceURL = "$((glcm).ReportManagers.ServerUrl)"
    )

    $DSCReport = Get-DSCReport
    $StatusData = $DSCReport.StatusData | ConvertFrom-Json
    return $StatusData
}

Get-DSCStatusData | Out-GridView