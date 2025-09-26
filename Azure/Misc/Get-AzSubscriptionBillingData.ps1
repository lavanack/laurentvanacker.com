<#
.SYNOPSIS
    Retrieves Azure subscription billing data using the Azure Billing REST API.

.DESCRIPTION
    This script connects to the Azure Billing API to retrieve detailed billing information
    for the current Azure subscription. It uses the authenticated Azure context to make
    REST API calls to the Azure billing endpoints.
    
    The script automatically handles authentication using the current Azure PowerShell context
    and formats the response for easy consumption.

.EXAMPLE
    .\Get-AzSubscriptionBillingData.ps1
    
    Retrieves billing data for the current subscription using verbose output.

.EXAMPLE
    $BillingData = .\Get-AzSubscriptionBillingData.ps1
    $BillingData | ConvertTo-Json -Depth 10
    
    Retrieves billing data and formats it as JSON for analysis.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Object
    Returns billing data object from Azure Billing API, or $null if an error occurs.

.NOTES
    File Name      : Get-AzSubscriptionBillingData.ps1
    Author         : Laurent Vanacker
    Prerequisite   : PowerShell 5.1+, Azure PowerShell module (Az.Accounts, Az.Profile)
    
    This script requires:
    - Active Azure authentication (Connect-AzAccount)
    - Billing Reader or higher permissions on the subscription
    - Access to Azure Billing API endpoints
    
    The script uses the Azure Billing REST API endpoint:
    https://s2.billing.ext.azure.com/api/Billing/Subscription/Subscription
    
    API Version: 2019-01-14

.LINK
    https://learn.microsoft.com/en-us/rest/api/billing/

.COMPONENT
    Azure Billing

.FUNCTIONALITY
    Billing Data Retrieval, Cost Management, Azure Subscription Management

#>

<#
DISCLAIMER: This Sample Code is provided for the purpose of illustration only
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

#region Function definitions 
Function Get-AzSubscriptionBillingData {
    <#
    .SYNOPSIS
        Retrieves Azure subscription billing data from the Azure Billing API.

    .DESCRIPTION
        This function makes a REST API call to the Azure Billing service to retrieve
        detailed billing information for the current Azure subscription. It handles
        authentication automatically using the current Azure PowerShell context.

    .EXAMPLE
        Get-AzSubscriptionBillingData
        
        Retrieves billing data for the current subscription.

    .EXAMPLE
        $BillingData = Get-AzSubscriptionBillingData -Verbose
        
        Retrieves billing data with detailed verbose output.

    .OUTPUTS
        System.Object
        Returns the billing data response from the Azure Billing API.

    .NOTES
        - Requires active Azure authentication
        - Uses current Azure subscription context
        - Requires appropriate billing permissions
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param(
    )

    Write-Verbose -Message "Starting billing data retrieval for subscription"

    #region Azure Context and Authentication
    # Validate Azure context
    $azContext = Get-AzContext
    if (-not $azContext) {
        Write-Error -Message "No Azure context found. Please run Connect-AzAccount first." -ErrorAction Stop
        return $null
    }
    
    Write-Verbose -Message "Using Azure context: $($azContext.Account.Id)"
    Write-Verbose -Message "Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))"
    Write-Verbose -Message "Tenant: $($azContext.Tenant.Id)"
    
    $SubscriptionID = $azContext.Subscription.Id
    
    # Get access token using modern authentication method
    try {
        Write-Verbose -Message "Acquiring access token for Azure Billing API"
        $accessToken = Get-AzAccessToken -ErrorAction Stop
        
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer $($accessToken.Token)"
        }
        
        Write-Verbose -Message "Access token acquired successfully"
    }
    catch {
        Write-Error -Message "Failed to acquire access token: $($_.Exception.Message)" -ErrorAction Stop
        return $null
    }
    #endregion

    $Body = @{ 
        "subscriptionId" = $SubscriptionID
    } | ConvertTo-Json -Depth 100

    $BillingURI = "https://s2.billing.ext.azure.com/api/Billing/Subscription/Subscription?api-version=2019-01-14"
    
    Write-Verbose -Message "Making REST API call to: $BillingURI"
    Write-Verbose -Message "Request body: $Body"
    
    try {
        # Invoke the REST API with properly formatted JSON body
        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -Body $Body -ContentType "application/json" -Uri $BillingURI -ErrorVariable ResponseError
        Write-Verbose -Message "API call successful"
    }
    catch [System.Net.WebException] {   
        # Handle web exceptions (HTTP errors)
        Write-Error -Message "HTTP Error occurred while calling Azure Billing API"
        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__)"
        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
        
        try {
            $respStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($respStream)
            $errorResponse = $reader.ReadToEnd()
            
            if ($errorResponse) {
                $Response = $errorResponse | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($Response -and -not([string]::IsNullOrEmpty($Response.message))) {
                    Write-Warning -Message "API Error Message: $($Response.message)"
                }
                else {
                    Write-Warning -Message "Raw error response: $errorResponse"
                }
            }
        }
        catch {
            Write-Warning -Message "Could not parse error response: $($_.Exception.Message)"
        }
        
        # Return null to indicate failure
        return $null
    }
    catch {
        # Handle any other exceptions
        Write-Error -Message "Unexpected error occurred: $($_.Exception.Message)" -ErrorAction Stop
        return $null
    }
    # Validate and format response
    if ($Response) {
        Write-Verbose -Message "Billing data retrieved successfully"
        Write-Verbose -Message "Response type: $($Response.GetType().Name)"
        
        # Add subscription context to response for clarity
        if ($Response -is [PSCustomObject] -or $Response -is [hashtable]) {
            $Response | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $SubscriptionID -Force
            $Response | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $azContext.Subscription.Name -Force
            $Response | Add-Member -NotePropertyName "RetrievedAt" -NotePropertyValue (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") -Force
        }
        
        Write-Verbose -Message "Billing data retrieval completed successfully"
        return $Response
    }
    else {
        Write-Warning -Message "No billing data received from API"
        return $null
    }
}
#endregion

#region Main Script Execution
<#
    Main script logic:
    1. Initialize environment and ensure Azure authentication
    2. Retrieve billing data for the current subscription
    3. Display formatted results
#>

# Initialize script environment
Clear-Host
$Error.Clear()

# Set working directory to script location
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
Write-Verbose -Message "Script location: $CurrentDir"

#region Azure Authentication
# Ensure user is authenticated to Azure
Write-Host "Checking Azure authentication..." -ForegroundColor Cyan
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Write-Host "Azure authentication required. Please sign in..." -ForegroundColor Yellow
    Connect-AzAccount
}
Write-Host "✓ Azure authentication confirmed" -ForegroundColor Green

# Display current Azure context for verification
$AzContext = Get-AzContext
Write-Host "Connected to subscription: $($AzContext.Subscription.Name) ($($AzContext.Subscription.Id))" -ForegroundColor Green
#endregion

#region Retrieve Billing Data
Write-Host "`nRetrieving Azure subscription billing data..." -ForegroundColor Cyan

try {
    $BillingData = Get-AzSubscriptionBillingData -Verbose
    
    if ($BillingData) {
        Write-Host "✓ Billing data retrieved successfully" -ForegroundColor Green
        
        # Display key information
        Write-Host "`nBilling Information Summary:" -ForegroundColor Yellow
        if ($BillingData.PSObject.Properties['SubscriptionName']) {
            Write-Host "  Subscription: $($BillingData.SubscriptionName)" -ForegroundColor White
        }
        if ($BillingData.PSObject.Properties['SubscriptionId']) {
            Write-Host "  Subscription ID: $($BillingData.SubscriptionId)" -ForegroundColor White
        }
        if ($BillingData.PSObject.Properties['RetrievedAt']) {
            Write-Host "  Retrieved At: $($BillingData.RetrievedAt)" -ForegroundColor White
        }
        
        # Return the billing data for further processing
        Write-Host "`nReturning billing data object for further analysis..." -ForegroundColor Cyan
        return $BillingData
    }
    else {
        Write-Warning "No billing data was retrieved"
    }
}
catch {
    Write-Error "Failed to retrieve billing data: $($_.Exception.Message)"
}
#endregion

Write-Host "`nScript execution completed." -ForegroundColor Green
#endregion