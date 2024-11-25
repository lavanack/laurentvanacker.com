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
#requires -Version 5 -Modules Az.Automation, Az.Resources

#From https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/
[CmdletBinding()]
param
(
)


#region function definitions 
#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/get-content?view=rest-automation-2023-11-01&tabs=HTTP
function Get-AzAPIAutomationRunbookDefinition {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName/content?api-version=2023-11-01"
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

#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/get?view=rest-automation-2023-11-01&tabs=HTTP
function Get-AzAPIAutomationRunbook {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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

#From https://learn.microsoft.com/en-us/rest/api/automation/runbook/create-or-update?view=rest-automation-2023-11-01&tabs=HTTP#create-or-update-runbook-and-publish-it
function New-AzAPIAutomationPowerShellRunbook {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$AutomationAccountName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$RunbookName,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Location
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

    $wc = [System.Net.WebClient]::new()
    $RunBookPowerShellScriptURI = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/master/Azure/Azure%20Automation%20Account/runbk-StartAzureVirtualMachine.ps1"
    $ContentHash = Get-FileHash -InputStream ($wc.OpenRead($RunBookPowerShellScriptURI)) -Algorithm SHA256

    $Body = [ordered]@{ 
        properties = [ordered]@{
            description        = "PowerShell Azure Automation Runbook for Starting Azure Virtual Machines" 
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
            parameters         = [ordered] @{
                TagName  = "AutoStart-Enabled"
                TagValue = "Enabled"
                Shutdown = $false
            }
        }
        name       = $RunbookName
        location   = $Location
    }

    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$($RunbookName)?api-version=2023-11-01"
    try {
        # Invoke the REST API
        $Response = Invoke-RestMethod -Method PUT -Headers $authHeader -Body $($Body | ConvertTo-Json -Depth 100) -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
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
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Defining variables 
#region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
$AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
$ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
$shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
#endregion

# Login to your Azure subscription.
While (-not(Get-AzContext)) {
    Connect-AzAccount
    Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    #$Subscription = Get-AzSubscription -SubscriptionName $SubscriptionName -ErrorAction Ignore
    #Select-AzSubscription -SubscriptionName $SubscriptionName | Select-Object -Property *
}

$Location = "EastUS"
$LocationShortName = $shortNameHT[$Location].shortName
#Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
$RunBookPrefix = "runbk"
$ResourceGroupPrefix = "rg"
$AutomationAccountPrefix = "aa"
$Project = "automation"
$Role = "startvm"
$DigitNumber = 3
$Instance = 1

$ResourceGroupName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $ResourceGroupPrefix, $Project, $Role, $LocationShortName, $Instance                       
$AutomationAccountName = "{0}-{1}-{2}-{3}-{4:D$DigitNumber}" -f $AutomationAccountPrefix, $Project, $Role, $LocationShortName, $Instance                       
#endregion

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
if ($ResourceGroup) {
    #Step 0: Remove previously existing Azure Resource Group with the same name
    $ResourceGroup | Remove-AzResourceGroup -Force -Verbose
}
Write-Verbose "`$ResourceGroupName: $ResourceGroupName"
Write-Verbose "`$AutomationAccountName: $AutomationAccountName"


#Step 1: Create Azure Resource Group
# Create Resource Groups
$ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
$AutomationAccount = New-AzAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroupName -AssignSystemIdentity

#region RBAC Assignment
Start-Sleep -Seconds 30
Write-Verbose -Message "Assigning the 'Virtual Machine Contributor' RBAC role to Automation Account Managed System Identity ..."
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -RoleDefinitionName 'Virtual Machine Contributor' -Scope "/subscriptions/$((Get-AzContext).Subscription.Id)"
#endregion

#region Schedule
$TimeZone = ([System.TimeZoneInfo]::Local).Id
$StartTime = Get-Date "07:00:00"
if ($(Get-Date) -gt $StartTime) {
    $StartTime = $StartTime.AddDays(1)
}
$Schedule = New-AzAutomationSchedule -AutomationAccountName $AutomationAccount.AutomationAccountName -Name "Azure Virtual Machine - Daily Start" -StartTime $StartTime -WeekInterval 1 -DaysOfWeek "Monday", "Tuesday", "Wednesday", "Thursday", "Friday" -ResourceGroupName $ResourceGroupName  -TimeZone $TimeZone
#endregion

#region RunBook
$RunBookName = "{0}-StopStartAzureVirtualMachine" -f $RunBookPrefix
#$Runbook = New-AzAutomationRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $RunBookName -ResourceGroupName $ResourceGroupName -Type PowerShell
# Publish the runbook
#Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $RunBookName -ResourceGroupName $ResourceGroupName

$Runbook = New-AzAPIAutomationPowerShellRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -runbookName $RunBookName -ResourceGroupName $ResourceGroupName -Location $Location -Verbose

# Create a new variable
$VariableName = "AbstractApiKey "
#Replace by your own API key
$VariableValue = "00000000-0000-0000-0000-00000000"
$Variable = New-AzAutomationVariable -AutomationAccountName $AutomationAccount.AutomationAccountName-Name $VariableName -Value $VariableValue -Encrypted $false -ResourceGroupName $ResourceGroupName -Description "Abstract (https://www.abstractapi.com) API Key, used by the runbook to check if the Date matches a FR Public Holiday"

#endregion 

# Link the schedule to the runbook
Register-AzAutomationScheduledRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $RunBookName -ScheduleName $Schedule.Name -ResourceGroupName $ResourceGroupName -Parameters @{"TagName" = "AutoStart-Enabled"; "TagValue" = "Enabled"; "Shutdown" = $false }
