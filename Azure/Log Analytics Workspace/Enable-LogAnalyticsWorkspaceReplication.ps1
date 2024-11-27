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
#requires -modules Az.Accounts -version 5

[CmdletBinding()]
param
(
)

#region Function definitions
function Enable-LogAnalyticsWorkspaceReplication {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$PrimaryLocation,
        [Parameter(Mandatory = $true)]
        [string]$SecondaryLocation,
        [Parameter(Mandatory = $true)]
        [string]$ResourcegroupName,
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

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

    $Body = [ordered]@{ 
        "properties" = [ordered]@{
            "replication" = [ordered]@{
                "enabled" = $true
                "location" = $SecondaryLocation
            }
        }
        "location" = $PrimaryLocation
    }

    $LAWReplicationURI = "https://management.azure.com/subscriptions/$SubcriptionID/resourcegroups/$ResourceGroupName/providers/microsoft.operationalinsights/workspaces/$($WorkspaceName)?api-version=2023-01-01-preview"
    try {
        # Invoke the REST API
        $Response = Invoke-AzRestMethod -Method PUT -Payload $($Body | ConvertTo-Json -Depth 100) -Uri $LAWReplicationURI -ErrorVariable ResponseError
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}

function Disable-LogAnalyticsWorkspaceReplication {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$PrimaryLocation
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

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

    $Body = [ordered]@{ 
        "properties" = [ordered]@{
            "replication" = [ordered]@{
                "enabled" = $false
            }
        }
        "location" = $PrimaryLocation
    }

    $LAWReplicationURI = "https://management.azure.com/subscriptions/$SubcriptionID/resourcegroups/$ResourceGroupName/providers/microsoft.operationalinsights/workspaces/$($WorkspaceName)?api-version=2023-01-01-preview"
    try {
        # Invoke the REST API
        $Response = Invoke-AzRestMethod -Method PUT -Payload $($Body | ConvertTo-Json -Depth 100) -Uri $LAWReplicationURI -ErrorVariable ResponseError
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}

function Test-LogAnalyticsWorkspaceReplicationProvisioningState {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$ResourcegroupName,
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

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

    $LAWReplicationProvisioningStateURI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)?api-version=2023-01-01-preview"
    try {
        # Invoke the REST API
        $Response = Invoke-AzRestMethod -Method GET -Uri $LAWReplicationProvisioningStateURI -ErrorVariable ResponseError
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
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    return $Response
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    <#
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Verbose -Message "Account : $((Get-AzContext).Account)"
    Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
    #>
}
#endregion

#region Variable definitions for the replication (Customize them depending of your needs)
$PrimaryLocation = "EastUS2"
$SecondaryLocation = "CentralUS"
$ResourcegroupName = "rg-avd-hp-np-ad-poc-mp-use2-897"
$WorkspaceName = "loghpnpadpocmpuse2897"
#endregion

#Enabling the Log Analytics Workspace Replication
$HTTPResponse = Enable-LogAnalyticsWorkspaceReplication -PrimaryLocation $PrimaryLocation -SecondaryLocation $SecondaryLocation -ResourcegroupName $ResourcegroupName -WorkspaceName $WorkspaceName -Verbose

#Checking the Log Analytics Workspace Replication Provisioning State (Should be "Succeeded")
$HTTPResponse = Test-LogAnalyticsWorkspaceReplicationProvisioningState -ResourcegroupName $ResourcegroupName -WorkspaceName $WorkspaceName -Verbose
$ResponseObject = $HTTPResponse.Content | ConvertFrom-Json
Write-Host "Log Analytics Workspace Replication Provisioning State: $($ResponseObject.properties.provisioningState)"
#endregion