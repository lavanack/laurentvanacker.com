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
#requires -Version 5.1 -Modules Az.Accounts, Az.DesktopVirtualization, Az.Resources, Az.Storage, Microsoft.Graph.Authentication
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, HelpMessage = "Webhook data object containing HostPool information")]
    [ValidateNotNull()]
    [object] $WebhookData
)
# Initialize error handling
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'
$VerbosePreference = 'Continue'
try {
    #region Initialization and Input Validation
    Write-Output -InputObject "=== Azure VM Start Runbook Initiated ==="
    Write-Output -InputObject "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    Write-Output -InputObject "Runbook: $($MyInvocation.MyCommand.Name)"
    # Log webhook data for debugging
    Write-Output -InputObject "Object Type: $($WebhookData.GetType().FullName)"
    Write-Output -InputObject "Webhook Data received: $($WebhookData | ConvertTo-Json -Depth 3 -Compress)"
    if (-not $WebhookData) {
        throw "No webhook data received. This runbook must be triggered via webhook."
    }
    Write-Output -InputObject "Webhook Name: $($WebhookData.WebhookName)"
    Write-Output -InputObject "Request Headers: $($WebhookData.RequestHeader | ConvertTo-Json -Compress)"
    # Handle test pane execution (when RequestBody is not present)
    if (-not $WebhookData.RequestBody) {
        Write-Warning "No RequestBody found. Assuming test pane execution - treating WebhookData as direct JSON input."
        $WebhookData = ConvertFrom-Json -InputObject $WebhookData
        Write-Output -InputObject "Test pane data: $($WebhookData | ConvertTo-Json -Compress)"
    }
    #endregion

    #region Request Body Validation and Processing
    if ($WebhookData.RequestBody) {
        Write-Output -InputObject "Processing webhook request body..."
        try {
            # Parse and validate VM data from request body
            $HostPoolData = ConvertFrom-Json -InputObject $WebhookData.RequestBody -ErrorAction Stop
            Write-Output -InputObject "HostPoolData: $($HostPoolData | Out-String)"

            if (-not $HostPoolData -or $HostPoolData.Count -eq 0) {
                throw "Request body contains no HostPool data or is empty."
            }
            if ($HostPoolData.Count -gt 1) {
                throw "More than one HostPool specified."
            }
            # Validate required properties for each VM
            if (-not $HostPoolData.VNET -or -not $HostPoolData.VMNumb) {
                throw "Invalid VM data: Each VM must have 'VNET' and 'VMNumb' properties. Received: $($HostPoolData | ConvertTo-Json -Compress)"
            }
            Write-Output -InputObject "HostPoolData: $($HostPoolData | ConvertTo-Json -Compress)"
        }
        catch {
            Write-Error "Failed to parse or validate request body: $($_.Exception.Message)"
            throw
        }
        #region Azure Authentication and Context Setup
        Write-Output -InputObject "Authenticating to Azure using managed identity..."
        try {
            #region Importing Modules
            Import-Module Az.Accounts, Az.DesktopVirtualization, Az.Resources, Az.Storage, Microsoft.Graph.Authentication -Force
            #endregion

            #region Azure connection
            # Ensures you do not inherit an AzContext in your dirbook
            $null = Disable-AzContextAutosave -Scope Process
            Write-Output -InputObject "Disabled Az context autosave"
            $connectionResult = Connect-AzAccount -Identity -ErrorAction Stop
            Write-Output -InputObject "Successfully authenticated using managed identity"
            Write-Output -InputObject "Connection details: Account=$($connectionResult.Context.Account.Id), Subscription=$($connectionResult.Context.Subscription.Name)"
            $AzureContext = (Connect-AzAccount -Identity).context
            Write-Output -InputObject "`$AzureContext: $($AzureContext | Out-String)"
            # set and store context
            $AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
            Write-Output -InputObject "`$AzureContext: $($AzureContext | Out-String)"
            $SubscriptionID = $AzureContext.Subscription.Id
            Write-Output -InputObject "`$SubscriptionID: $subscriptionID"
            #endregion
        }
        catch {
            Write-Error "Failed to authenticate to Azure: $($_.Exception.Message)"
            throw
        }
        #endregion
    }
    else {
        throw "Request body is empty or missing. Cannot process VM start request."
    }
    #endregion

    #region AVD Accelerator Deployment
    
    #region Variables
    if ($VNET -match '^([A-Za-z]+)(\d{2,})$') {
        $Letters = $matches[1]
        Write-Output -InputObject "`$Letters: $Letters"
        $Numb = $matches[2]
        Write-Output -InputObject "`$Numb: $Numb"
        $LastDigit = $Matches[2].Substring($Matches[2].Length-2,2)
        Write-Output -InputObject "`$LastDigit: $LastDigit"
        $TRN = ("tr"+$LastDigit).ToLower()
        Write-Output -InputObject "`$TRN: $TRN"
    }

    #$TemplateFile = Join-Path -Path $CurrentDir -ChildPath deploy-baseline.json
    #$TemplateFile = Join-Path -Path $CurrentDir -ChildPath "../avdaccelerator/workload/arm/deploy-baseline.json" -Resolve
    $TemplateURI = "https://raw.githubusercontent.com/Azure/avdaccelerator/main/workload/arm/deploy-baseline.json"
    Write-Output -InputObject "`$TemplateURI: $TemplateURI"
    #$TemplateFile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $TemplateURI -Leaf)
    #Invoke-WebRequest -Uri $TemplateURI -UseBasicParsing -OutFile $TemplateFile

     #$TemplateParameterFile = Join-Path -Path $CurrentDir -ChildPath parameters.json
    $DeploymentName = "AVDAcceleratorDeployment_ARM_{0:yyyyMMddHHmmss}" -f $(Get-Date)
    Write-Output -InputObject "`$DeploymentName: $DeploymentName"

    $AVDVmLocalAdminCredential = Get-AutomationPSCredential -Name "AVDVmLocalAdminCredential"
    
    $AVDUsersEntraIDGroupName = "AVD Users"
    Write-Output -InputObject "`$AVDUsersEntraIDGroupName: $AVDUsersEntraIDGroupName"
    $AVDUsersEntraIDGroup = Get-AzADGroup -DisplayName $AccessGroupName
    $avdSecurityGroups = @(@{"displayName" = $AVDUsersEntraIDGroup.DisplayName; "objectId" = $AVDUsersEntraIDGroup.Id})
    Write-Output -InputObject "`$AVDUsersEntraIDGroupName: $AVDUsersEntraIDGroupName"
    #endregion
    
    #endregion

}
catch {
    Write-Error "Runbook execution failed: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    throw
}
finally {
    Write-Output -InputObject "=== Runbook Execution Completed ==="
    Write-Output -InputObject "End time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
}
 
