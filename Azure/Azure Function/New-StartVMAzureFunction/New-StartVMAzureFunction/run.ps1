using namespace System.Net
 
# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
 
# Interact with query parameters or the body of the request.
$rgname = $Request.Query.resourcegroup
if (-not $rgname) {
    $rgname = $Request.Body.resourcegroup
}
$action = $Request.Query.action
if (-not $action) {
    $action = $Request.Body.action
}
 
#Proceed if all request body parameters are found
if ($rgname -and $action) {
    $status = [HttpStatusCode]::OK
    if ($action -ceq "get"){
        $body = Get-AzVM -ResourceGroupName $rgname -Status | Select-Object -Property Name,PowerState
    }
    if ($action -ceq "start"){
        $body = $action
        $Job = Get-AzVM -ResourceGroupName $rgname | Start-AzVM -AsJob
        $body = $Job | Receive-Job -Wait -AutoRemoveJob
    }
}
else {
    $status = [HttpStatusCode]::BadRequest
    $body = "Please pass a name on the query string or in the request body."
}
 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
})