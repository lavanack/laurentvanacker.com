Clear-Host
# Log in first with Connect-AzAccount if not using Cloud Shell

$azContext = Get-AzContext
$SubscriptionId = $azContext.Subscription
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' + $token.AccessToken
}
$ResourcePrefix = "dscagc028"

# Invoke the REST API
$restUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/$($ResourcePrefix)-rg-eastus/providers/Microsoft.Compute/virtualMachines/$($ResourcePrefix)ws2019/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments?api-version=2020-06-25"
$response = Invoke-RestMethod -Uri $restUri -Method Get -Headers $authHeader
$guestConfigurationAssignments = $response.value
$guestConfigurationAssignments | Where-Object -FilterScript { $_.name -match "^$($ResourcePrefix)"} | ForEach-Object -Process {
    $restUri = "https://management.azure.com$($_.id)?api-version=2020-06-25"
    $restUri
    $response = Invoke-RestMethod -Uri $restUri -Method Get -Headers $authHeader
    $response | Format-List * -Force
}