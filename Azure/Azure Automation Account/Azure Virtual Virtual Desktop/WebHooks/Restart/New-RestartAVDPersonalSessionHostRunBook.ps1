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
<#
.SYNOPSIS
    Creates and configures a complete Azure Automation infrastructure for VM lifecycle management via webhooks.

.DESCRIPTION
    This script establishes a comprehensive Azure Automation solution for managing virtual machine lifecycle operations.
    It creates the necessary Azure resources including Resource Groups, Automation Accounts, Runbooks, and Webhooks,
    then configures RBAC permissions and deploys enterprise-ready PowerShell runbooks for VM management.
    
    Key Features:
    - Creates Azure Resource Group with standardized naming conventions
    - Deploys Azure Automation Account with Managed System Identity
    - Configures appropriate RBAC permissions for VM operations
    - Creates and publishes PowerShell runbooks from GitHub repository
    - Sets up secure webhooks with 10-year expiration
    - Includes comprehensive validation and testing framework
    - Supports enterprise naming conventions based on Cloud Adoption Framework

.PARAMETER Location
    The Azure region where resources will be deployed.
    Default: EastUS

.PARAMETER Project
    The project identifier for resource naming convention.
    Default: automation

.PARAMETER Role
    The role identifier for resource naming convention.
    Default: restartavdsessionhost

.PARAMETER SkipTesting
    When specified, skips the automated testing phase after deployment.

.PARAMETER Force
    When specified, removes existing resources with the same name without prompting.

.EXAMPLE
    .\New-RestartAVDPersonalSessionHostRunBook.ps1
    
    Creates the complete automation infrastructure using default settings in East US region.

.EXAMPLE
    .\New-RestartAVDPersonalSessionHostRunBook.ps1 -Location "West Europe" -Project "prod" -Role "vmops"
    
    Creates infrastructure in West Europe with custom project and role identifiers.

.EXAMPLE
    .\New-RestartAVDPersonalSessionHostRunBook.ps1 -SkipTesting -Force
    
    Creates infrastructure, removes existing resources without prompting, and skips testing.

.NOTES
    Author: Laurent Van Acker
    Version: 1.0.0
    Created: 2025
    Updated: 2025-11-07
    
    Requirements:
    - PowerShell 5.1 or later
    - Az.Automation module
    - Az.Resources module
    - Az.Accounts module (for authentication)
    - Appropriate Azure RBAC permissions
    
    This script follows Azure naming conventions based on the Cloud Adoption Framework.
    For more information, visit: https://github.com/microsoft/CloudAdoptionFramework

.LINK
    https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

.LINK
    https://docs.microsoft.com/en-us/azure/automation/

.LINK
    https://github.com/lavanack/laurentvanacker.com
#>

#Requires -Version 5.1
#Requires -Modules Az.Automation, Az.Resources, Az.Accounts

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
    [Parameter()]
    [ValidateScript({$_ -in (Get-AzLocation).Location})]
    [string]$Location = 'EastUS',
    
    [Parameter()]
    [ValidateLength(3, 20)]
    [ValidatePattern('^[a-z0-9]+$')]
    [string]$Project = 'automation',
    
    [Parameter()]
    [ValidateLength(3, 20)]
    [ValidatePattern('^[a-z0-9]+$')]
    [string]$Role = 'restartavdsessionhost',
    
    [Parameter()]
    [switch]$SkipTesting,
    
    [Parameter()]
    [switch]$Force
)


#region Function Definitions

<#
.SYNOPSIS
    Retrieves the PowerShell content of an Azure Automation runbook via REST API.

.DESCRIPTION
    This function uses the Azure REST API to fetch the complete PowerShell script content
    of a specified runbook from an Azure Automation Account. Useful for backup, analysis,
    or content verification purposes.

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group containing the Automation Account.

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account containing the runbook.

.PARAMETER RunbookName
    The name of the runbook whose content should be retrieved.

.OUTPUTS
    String containing the PowerShell script content of the runbook.

.EXAMPLE
    Get-AzAPIAutomationRunbookDefinition -ResourceGroupName "rg-automation" -AutomationAccountName "aa-prod" -RunbookName "Start-VM"

.LINK
    https://learn.microsoft.com/en-us/rest/api/automation/runbook/get-content
#>
function Get-AzAPIAutomationRunbookDefinition {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationAccountName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RunbookName
    )
    
    #region Azure Context and Authentication
    Write-Verbose "Acquiring Azure authentication context for runbook content retrieval..."
    
    # Ensure we have a valid Azure context
    $azContext = Get-AzContext
    if (-not $azContext) {
        throw "No Azure context found. Please run Connect-AzAccount first."
    }
    
    $SubscriptionID = $azContext.Subscription.Id
    Write-Verbose "Using Subscription: $($azContext.Subscription.Name) ($SubscriptionID)"
    
    try {
        # Get authentication token for REST API calls
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
        $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
        
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = 'Bearer ' + $token.AccessToken
        }
        Write-Verbose "Successfully acquired authentication token"
    }
    catch {
        throw "Failed to acquire authentication token: $($_.Exception.Message)"
    }
    #endregion

    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName/content?api-version=2023-11-01"
    
    try {
        Write-Verbose "Retrieving runbook content from: $URI"
        $Response = Invoke-RestMethod -Method GET -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorAction Stop
        Write-Verbose "Successfully retrieved runbook content ($(($Response -split "`n").Count) lines)"
    }
    catch [System.Net.WebException] {   
        # Handle web-specific exceptions with detailed error information
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        
        Write-Error "HTTP Error - StatusCode: $statusCode, StatusDescription: $statusDescription"
        
        if ($_.Exception.Response.GetResponseStream()) {
            $respStream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($respStream)
            $errorResponse = $reader.ReadToEnd()
            
            try {
                $errorObj = $errorResponse | ConvertFrom-Json
                if ($errorObj.error.message) {
                    Write-Error "API Error: $($errorObj.error.message)"
                }
            }
            catch {
                Write-Error "Raw Error Response: $errorResponse"
            }
        }
        throw
    }
    catch {
        Write-Error "Failed to retrieve runbook content: $($_.Exception.Message)"
        throw
    }
    
    return $Response
}

<#
.SYNOPSIS
    Retrieves metadata and properties of an Azure Automation runbook via REST API.

.DESCRIPTION
    This function uses the Azure REST API to fetch detailed metadata about a specified
    runbook including its properties, state, parameters, and configuration settings.
    Useful for validation, monitoring, and automation management tasks.

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group containing the Automation Account.

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account containing the runbook.

.PARAMETER RunbookName
    The name of the runbook whose metadata should be retrieved.

.OUTPUTS
    PSCustomObject containing runbook metadata and properties.

.EXAMPLE
    Get-AzAPIAutomationRunbook -ResourceGroupName "rg-automation" -AutomationAccountName "aa-prod" -RunbookName "Start-VM"

.LINK
    https://learn.microsoft.com/en-us/rest/api/automation/runbook/get
#>
function Get-AzAPIAutomationRunbook {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationAccountName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RunbookName
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$($RunbookName)?api-version=2023-11-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method GET -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
    return $Response
}

<#
.SYNOPSIS
    Creates and publishes a new PowerShell runbook in Azure Automation via REST API.

.DESCRIPTION
    This function creates a new PowerShell runbook in an Azure Automation Account using
    the Azure REST API. It automatically downloads the source code from a specified URI,
    calculates the content hash for integrity verification, and publishes the runbook
    with predefined parameters for VM management operations.

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group containing the Automation Account.

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account where the runbook will be created.

.PARAMETER RunbookName
    The name for the new runbook.

.PARAMETER Location
    The Azure region where the runbook will be deployed.

.PARAMETER RunBookPowerShellScriptURI
    The URI pointing to the PowerShell script content for the runbook.
    Must be accessible via HTTP/HTTPS.

.PARAMETER Description
    A description for the runbook explaining its purpose and functionality.

.OUTPUTS
    PSCustomObject containing the runbook creation response.

.EXAMPLE
    New-AzAPIAutomationPowerShellRunbook -ResourceGroupName "rg-automation" -AutomationAccountName "aa-prod" -RunbookName "Start-VM" -Location "EastUS" -RunBookPowerShellScriptURI "https://github.com/example/script.ps1" -Description "Starts Azure VMs"

.LINK
    https://learn.microsoft.com/en-us/rest/api/automation/runbook/create-or-update
#>
function New-AzAPIAutomationPowerShellRunbook {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AutomationAccountName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RunbookName,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Location,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^https?://')]
        [string]$RunBookPowerShellScriptURI,
        
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [switch] $LogVerbose
    )
    #region Azure Context
    # Log in first with Connect-AzAccount if not using Cloud Shell

    $azContext = Get-AzContext
    $SubcriptionID = $azContext.Subscription.Id
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }
    #endregion

    # Download and validate the runbook content
    Write-Verbose "Downloading runbook content from: $RunBookPowerShellScriptURI"
    try {
        $wc = [System.Net.WebClient]::new()
        $ContentHash = Get-FileHash -InputStream ($wc.OpenRead($RunBookPowerShellScriptURI)) -Algorithm SHA256
        Write-Verbose "Content hash calculated: $($ContentHash.Algorithm) - $($ContentHash.Hash)"
    }
    catch {
        throw "Failed to download or hash runbook content from URI '$RunBookPowerShellScriptURI': $($_.Exception.Message)"
    }
    finally {
        if ($wc) { $wc.Dispose() }
    }

    $Body = [ordered]@{ 
        properties = [ordered]@{
            description        = $Description
            logVerbose         = $false
            logProgress        = $false
            logActivityTrace   = 0
            runbookType        = "PowerShell"
            publishContentLink = @{
                uri         = $RunBookPowerShellScriptURI
                contentHash = [ordered]@{
                    "algorithm" = $ContentHash.Algorithm
                    "value"     = $ContentHash.Hash
                }
            }
        }
        name       = $RunbookName
        location   = $Location
    }

    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$($RunbookName)?api-version=2023-11-01"
    
    if ($PSCmdlet.ShouldProcess($RunbookName, "Create PowerShell runbook in $AutomationAccountName")) {
        try {
            Write-Verbose "Creating runbook via REST API: $URI"
            $jsonBody = $Body | ConvertTo-Json -Depth 100
            Write-Verbose "Request body size: $($jsonBody.Length) characters"
            
            $Response = Invoke-RestMethod -Method PUT -Headers $authHeader -Body $jsonBody -ContentType "application/json" -Uri $URI -ErrorAction Stop
            Write-Verbose "Successfully created runbook: $RunbookName"

            if ($LogVerbose) {
                Set-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -Name $RunbookName -LogVerbose $true -ResourceGroupName $ResourceGroupName
            }


        }
        catch [System.Net.WebException] {   
            # Handle web-specific exceptions with detailed error information
            $statusCode = $_.Exception.Response.StatusCode.value__
            $statusDescription = $_.Exception.Response.StatusDescription
            
            Write-Error "HTTP Error - StatusCode: $statusCode, StatusDescription: $statusDescription"
            
            if ($_.Exception.Response.GetResponseStream()) {
                $respStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($respStream)
                $errorResponse = $reader.ReadToEnd()
                
                try {
                    $errorObj = $errorResponse | ConvertFrom-Json
                    if ($errorObj.error.message) {
                        Write-Error "API Error: $($errorObj.error.message)"
                    }
                }
                catch {
                    Write-Error "Raw Error Response: $errorResponse"
                }
            }
            throw
        }
        catch {
            Write-Error "Failed to create runbook '$RunbookName': $($_.Exception.Message)"
            throw
        }
    }
    
    return $Response
}

#endregion

#region Script Initialization
Clear-Host
Write-Host "=== Azure Automation Account Setup Script ===" -ForegroundColor Cyan
Write-Host "Starting automation infrastructure deployment..." -ForegroundColor Green

# Clear any existing errors for clean execution
$Error.Clear()

# Set script location context
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

Write-Verbose "Script executing from: $CurrentDir"
Write-Verbose "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Verbose "Execution Policy: $(Get-ExecutionPolicy)"
#endregion

#region Variable Definitions and Azure Location Setup

Write-Host "Configuring Azure location mappings and naming conventions..." -ForegroundColor Yellow

#region Azure Location Short Name Mapping
# Building a hashtable to get the short name of every Azure location based on the Azure Naming Tool
try {
    Write-Verbose "Retrieving Azure locations..."
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    
    Write-Verbose "Downloading Azure Naming Tool resource locations..."
    $ANTResourceLocation = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json" -ErrorAction Stop
    
    $shortNameHT = $ANTResourceLocation | 
    Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | 
    Where-Object -FilterScript { $_.Location } | 
    Group-Object -Property Location -AsHashTable -AsString
    
    Write-Verbose "Successfully mapped $($shortNameHT.Count) Azure locations to short names"
}
catch {
    Write-Warning "Failed to retrieve Azure location mappings: $($_.Exception.Message)"
    Write-Warning "Using fallback location short name mapping"
    
    # Fallback short name mapping for common regions
    $shortNameHT = @{
        'eastus'      = @{shortName = 'use' }
        'eastus2'     = @{shortName = 'use2' }
        'westus'      = @{shortName = 'usw' }
        'westus2'     = @{shortName = 'usw2' }
        'centralus'   = @{shortName = 'usc' }
        'northeurope' = @{shortName = 'eun' }
        'westeurope'  = @{shortName = 'euw' }
    }
}
#endregion

#region Building an Hashtable to get the shortname of every Azure resource based on a JSON file on the Github repository of the Azure Naming Tool
try {
    Write-Verbose "Downloading Azure Naming Tool resource types ..."
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -in @('', 'Windows') } | Select-Object -Property resource, shortName, lengthMax | Group-Object -Property resource -AsHashTable -AsString

    Write-Verbose "Successfully mapped $($shortNameHT.Count) Azure types to short names"
}
catch {
    Write-Warning "Failed to retrieve Azure type mappings: $($_.Exception.Message)"
    Write-Warning "Using fallback type short name mapping"
    
    # Fallback short name mapping for common regions
    $ResourceTypeShortNameHT = @{
        'Automation/automationAccounts/webhooks' = @{shortName = 'wbhk' }
        'Automation/automationAccounts/runbooks' = @{shortName = 'runbk' }
        'Resources/resourcegroups'               = @{shortName = 'rg' }
        'Automation/automationAccounts'          = @{shortName = 'aa' }
    }
}
#endregion

#region Azure Authentication and Subscription Selection
Write-Host "Validating Azure authentication..." -ForegroundColor Yellow

# Ensure Azure authentication is established
$maxRetries = 3
$retryCount = 0

while (-not(Get-AzAccessToken -ErrorAction Ignore) -and $retryCount -lt $maxRetries) {
    $retryCount++
    Write-Host "Azure authentication required (Attempt $retryCount of $maxRetries)..." -ForegroundColor Cyan
    
    try {
        Connect-AzAccount -ErrorAction Stop
        
        # Allow user to select subscription if multiple are available
        $subscriptions = Get-AzSubscription
        if ($subscriptions.Count -gt 1) {
            Write-Host "Multiple subscriptions found. Please select one:" -ForegroundColor Yellow
            $selectedSubscription = $subscriptions | Out-GridView -OutputMode Single -Title "Select your Azure Subscription"
            if ($selectedSubscription) {
                Select-AzSubscription -SubscriptionId $selectedSubscription.Id | Out-Null
                Write-Host "Selected subscription: $($selectedSubscription.Name)" -ForegroundColor Green
            }
            else {
                throw "No subscription selected. Script cannot continue."
            }
        }
        elseif ($subscriptions.Count -eq 1) {
            Write-Host "Using subscription: $($subscriptions[0].Name)" -ForegroundColor Green
        }
        else {
            throw "No Azure subscriptions found. Please check your account permissions."
        }
    }
    catch {
        Write-Error "Azure authentication failed: $($_.Exception.Message)"
        if ($retryCount -ge $maxRetries) {
            throw "Failed to authenticate to Azure after $maxRetries attempts."
        }
        Start-Sleep -Seconds 5
    }
}

# Validate we have a valid context
$azContext = Get-AzContext
if (-not $azContext) {
    throw "No valid Azure context found. Please run Connect-AzAccount."
}

Write-Host "Successfully authenticated to Azure" -ForegroundColor Green
Write-Host "Subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -ForegroundColor Green
Write-Host "Tenant: $($azContext.Tenant.Id)" -ForegroundColor Green
#endregion

#region Resource Naming Configuration
Write-Host "Configuring resource naming conventions..." -ForegroundColor Yellow

# Validate location and get short name
$Location = $Location.ToLower()
if (-not $shortNameHT.ContainsKey($Location)) {
    Write-Warning "Location '$Location' not found in short name mapping. Using location as-is."
    $LocationShortName = $Location.Substring(0, [Math]::Min(4, $Location.Length))
}
else {
    $LocationShortName = $shortNameHT[$Location].shortName
}

# Naming convention based on Cloud Adoption Framework
# Reference: https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$WebhookPrefix = $ResourceTypeShortNameHT["Automation/automationAccounts/webhooks"].ShortName
$RunBookPrefix = $ResourceTypeShortNameHT["Automation/automationAccounts/runbooks"].ShortName
$ResourceGroupPrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
$AutomationAccountPrefix = $ResourceTypeShortNameHT["Automation/automationAccounts"].ShortName
$DigitNumber = 3

# Generate unique instance number
$Instance = Get-Random -Minimum 1 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))

# Construct resource names using standardized format: prefix-project-role-location-instance
$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$AutomationAccountName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AutomationAccountPrefix, $Project, $Role, $LocationShortName, $Instance
$WebhookName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $WebhookPrefix, $Project, $Role, $LocationShortName, $Instance                       
$SubscriptionId = $azContext.Subscription.Id

# Display resource names for confirmation
Write-Host "Generated Resource Names:" -ForegroundColor Cyan
Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "  Automation Account: $AutomationAccountName" -ForegroundColor White
Write-Host "  Webhook: $WebhookName" -ForegroundColor White
Write-Host "  Location: $Location ($LocationShortName)" -ForegroundColor White
Write-Host "  Instance: $Instance" -ForegroundColor White
#endregion

#region Azure Resource Deployment
Write-Host "Deploying Azure resources..." -ForegroundColor Yellow

# Check for existing resource group
$existingResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

if ($existingResourceGroup) {
    if ($Force) {
        Write-Host "Removing existing resource group: $ResourceGroupName" -ForegroundColor Yellow
        try {
            $existingResourceGroup | Remove-AzResourceGroup -Force -AsJob | Out-Null
            
            # Wait for deletion to complete
            do {
                Start-Sleep -Seconds 10
                $checkRG = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                Write-Host "Waiting for resource group deletion..." -ForegroundColor Yellow
            } while ($checkRG)
            
            Write-Host "Successfully removed existing resource group" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to remove existing resource group: $($_.Exception.Message)"
            throw
        }
    }
    else {
        $choice = Read-Host "Resource group '$ResourceGroupName' already exists. Remove it? (y/N)"
        if ($choice -eq 'y' -or $choice -eq 'Y') {
            Write-Host "Removing existing resource group..." -ForegroundColor Yellow
            $existingResourceGroup | Remove-AzResourceGroup -Force -AsJob | Out-Null
            
            do {
                Start-Sleep -Seconds 10
                $checkRG = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
                Write-Host "Waiting for resource group deletion..." -ForegroundColor Yellow
            } while ($checkRG)
        }
        else {
            throw "Cannot proceed with existing resource group. Use -Force to automatically remove it."
        }
    }
}

# Create new resource group
Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Cyan
try {
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force -ErrorAction Stop
    Write-Host "Successfully created resource group" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create resource group: $($_.Exception.Message)"
    throw
}

# Create automation account with managed system identity
Write-Host "Creating automation account: $AutomationAccountName" -ForegroundColor Cyan
try {
    $AutomationAccount = New-AzAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroupName -AssignSystemIdentity -ErrorAction Stop
    Write-Host "Successfully created automation account with managed identity" -ForegroundColor Green
    Write-Host "Principal ID: $($AutomationAccount.Identity.PrincipalId)" -ForegroundColor White
}
catch {
    Write-Error "Failed to create automation account: $($_.Exception.Message)"
    throw
}
#endregion

#region RBAC Assignment Configuration
Write-Host "Configuring RBAC permissions..." -ForegroundColor Yellow

# Allow time for managed identity propagation
Write-Host "Waiting for managed identity propagation..." -ForegroundColor Cyan
Start-Sleep -Seconds 60

$RBACRoles = 'Log Analytics Reader', 'Virtual Machine Contributor'
# Assign the 'Log Analytics Reader' and 'Virtual Machine Contributor' roles to the Automation Account's managed identity
$maxRbacRetries = 5
foreach ($RBACRole in $RBACRoles) {
    $rbacRetryCount = 0
    $rbacSuccess = $false

    while (-not $rbacSuccess -and $rbacRetryCount -lt $maxRbacRetries) {
        $rbacRetryCount++
        Write-Host "Attempting RBAC assignment (Attempt $rbacRetryCount of $maxRbacRetries)..." -ForegroundColor Cyan
    
        try {
            $roleAssignment = New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -RoleDefinitionName $RBACRole -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop
            Write-Host "Successfully assigned '$RBACRole' role to managed identity" -ForegroundColor Green
            Write-Host "Role Assignment ID: $($roleAssignment.RoleAssignmentId)" -ForegroundColor White
            $rbacSuccess = $true
        }
        catch {
            if ($_.Exception.Message -match "PrincipalNotFound") {
                Write-Warning "Managed identity not yet fully propagated. Retrying in 30 seconds..."
                Start-Sleep -Seconds 30
            }
            elseif ($_.Exception.Message -match "RoleAssignmentExists") {
                Write-Host "RBAC role assignment already exists" -ForegroundColor Yellow
                $rbacSuccess = $true
            }
            else {
                Write-Error "RBAC assignment failed: $($_.Exception.Message)"
                if ($rbacRetryCount -ge $maxRbacRetries) {
                    throw "Failed to assign RBAC role after $maxRbacRetries attempts."
                }
                Start-Sleep -Seconds 15
            }
        }
    }
}
#endregion

#region Runbook Deployment

Write-Host "Deploying PowerShell runbook..." -ForegroundColor Yellow

#region Runbook Configuration
$RunBookName = "{0}-RestartAVDPersonalSessionHostRunBook" -f $RunBookPrefix
$RunbookScriptURI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20Automation%20Account/Azure%20Virtual%20Virtual%20Desktop/WebHooks/Restart/RestartAVDPersonalSessionHostRunBook.ps1"
$RunbookDescription = "Enterprise PowerShell Azure Automation Runbook for AVD Session Host restart via webhooks"


Write-Host "Runbook Configuration:" -ForegroundColor Cyan
Write-Host "  Name: $RunBookName" -ForegroundColor White
Write-Host "  Source: $RunbookScriptURI" -ForegroundColor White
Write-Host "  Description: $RunbookDescription" -ForegroundColor White

# Deploy runbook using REST API for better control
try {
    Write-Host "Creating and publishing runbook..." -ForegroundColor Cyan
    $RunbookResult = New-AzAPIAutomationPowerShellRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -runbookName $RunBookName -ResourceGroupName $ResourceGroupName -Location $Location -RunBookPowerShellScriptURI $RunbookScriptURI -Description $RunbookDescription
    #$RunbookResult = New-AzAPIAutomationPowerShellRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -runbookName $RunBookName -ResourceGroupName $ResourceGroupName -Location $Location -RunBookPowerShellScriptURI $RunbookScriptURI -Description $RunbookDescription -LogVerbose -Verbose:$VerbosePreference
    
    if ($RunbookResult) {
        Write-Host "Successfully created runbook: $RunBookName" -ForegroundColor Green
        Write-Host "Runbook State: $($RunbookResult.properties.state)" -ForegroundColor White
    }
    else {
        throw "Runbook creation returned no result"
    }
}
catch {
    Write-Error "Failed to create runbook: $($_.Exception.Message)"
    throw
}

# Create a new variable(s)
$VariableName = "LogAnalyticsWorkspaceId"
#Replace by your own LAW Id(s)
$VariableValue = "00000000-0000-0000-0000-000000000000"
$Variable = New-AzAutomationVariable -AutomationAccountName $AutomationAccount.AutomationAccountName-Name $VariableName -Value $VariableValue -Encrypted $false -ResourceGroupName $ResourceGroupName -Description "LogAnalyticsWorkspace Id for AVD Host Pools"
#endregion 

#region Webhook Configuration
Write-Host "Configuring webhook..." -ForegroundColor Yellow

# Set webhook expiration to 10 years from now
$webhookExpiration = (Get-Date).AddYears(10)

try {
    Write-Host "Creating webhook: $WebhookName" -ForegroundColor Cyan
    $Webhook = New-AzAutomationWebhook -ResourceGroup $ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $WebhookName -RunbookName $RunBookName -IsEnabled $True -ExpiryTime $webhookExpiration -Force
    
    $WebhookURI = $Webhook.WebhookURI
    
    Write-Host "Successfully created webhook" -ForegroundColor Green
    Write-Host "Webhook Details:" -ForegroundColor Cyan
    Write-Host "  Name: $($Webhook.Name)" -ForegroundColor White
    Write-Host "  Expiration: $($Webhook.ExpiryTime)" -ForegroundColor White
    Write-Host "  Enabled: $($Webhook.IsEnabled)" -ForegroundColor White
    Write-Host "  URI: [SECURE - Display on demand]" -ForegroundColor Yellow
    
    # Securely store the webhook URI
    Write-Warning "IMPORTANT: Store the webhook URI securely. It will not be retrievable after this session."
    Write-Host "Webhook URI:" -ForegroundColor Red
    Write-Host $WebhookURI -ForegroundColor Yellow
    Write-Host "Please copy and store this URI securely!" -ForegroundColor Red
}
catch {
    Write-Error "Failed to create webhook: $($_.Exception.Message)"
    throw
}
#endregion
#endregion

#region Automated Testing Framework
if (-not $SkipTesting) {
    & "$CurrentDir\Test-RestartAVDPersonalSessionHostRunBook.ps1" -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -WebhookURI $WebhookURI
}
else {
    Write-Host "Testing skipped by user request" -ForegroundColor Yellow
}
#endregion

#region Deployment Summary
Write-Host ""
Write-Host "=== DEPLOYMENT SUMMARY ===" -ForegroundColor Green
Write-Host "Successfully deployed Azure Automation infrastructure!" -ForegroundColor Green
Write-Host ""
Write-Host "Deployed Resources:" -ForegroundColor Cyan
Write-Host "  ✓ Resource Group: $ResourceGroupName" -ForegroundColor Green
Write-Host "  ✓ Automation Account: $AutomationAccountName" -ForegroundColor Green
Write-Host "  ✓ Runbook: $RunBookName" -ForegroundColor Green
Write-Host "  ✓ Webhook: $WebhookName" -ForegroundColor Green
Write-Host "  ✓ RBAC Assignment: Virtual Machine Contributor" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Securely store the webhook URI for future use" -ForegroundColor White
Write-Host "  2. Test VM operations using the webhook" -ForegroundColor White
Write-Host "  3. Monitor automation account for job execution" -ForegroundColor White
Write-Host "  4. Configure additional runbooks as needed" -ForegroundColor White
Write-Host ""
Write-Host "Documentation: https://docs.microsoft.com/en-us/azure/automation/" -ForegroundColor Cyan
Write-Host "Script completed successfully!" -ForegroundColor Green
#endregion