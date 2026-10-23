<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

#requires -Version 5 #-Modules Az.Accounts

[CmdletBinding(PositionalBinding = $false)]
param
(
)

#region Function definitions
function New-AzAVDSREAgent {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({$_ -in (Get-AzLocation).Location })]
        [string] $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[\w().-]+$')]
        [string[]]$TargetResourceGroupName,

        [ValidateSet('MicrosoftFoundry', 'Anthropic')]
        [string]$ModelProvider = 'MicrosoftFoundry',

        [ValidateRange(1, 2147483647)]
        [int]$MonthlyAgentUnitLimit = 10000,

        [ValidateRange(1, 120)]
        [int]$TimeoutMinutes = 30
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    #region Building an Hashtable to get the shortname of every Azure location based on a JSON file on the Github repository of the Azure Naming Tool
    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $shortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString
    #endregion

    #region Building an Hashtable to get the prefix of every Azure resource type based on a JSON file on the Github repository of the Azure Naming Tool
    $Result = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/refs/heads/main/src/repository/resourcetypes.json 
    $ResourceTypeShortNameHT = $Result | Where-Object -FilterScript { $_.property -notin @('Linux') } | Select-Object -Property resource, shortName, property, lengthMax | Group-Object -Property resource -AsHashTable -AsString
    #endregion

    #region Resource Naming
    $AzureVMNameMaxLength = $ResourceTypeShortNameHT["Compute/virtualMachines"].lengthMax
    $LocationShortName = $shortNameHT[$Location].shortName
    #Naming convention based on https://github.com/microsoft/CloudAdoptionFramework/tree/master/ready/AzNamingTool
    $ResourceGroupNamePrefix = $ResourceTypeShortNameHT["Resources/resourcegroups"].ShortName
    $UserAssignedIdentityNamePrefix = $ResourceTypeShortNameHT["ManagedIdentity/userAssignedIdentities"].ShortName
    $LogAnalyticsWorkspaceNamePrefix = $ResourceTypeShortNameHT["OperationalInsights/workspaces"].ShortName
    $ApplicationInsightsNamePrefix = $ResourceTypeShortNameHT["Insights/components"].ShortName

    $AzureSREAgentNamePrefix = "sre"
    $DigitNumber = 3
    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $ResourceGroupName = "{0}-sreagent-avd-poc-{1}-{2:D3}" -f $ResourceGroupNamePrefix, $LocationShortName, $Instance
        $AzureSREAgentName = "{0}-avd-poc-{1}-{2:D3}" -f $AzureSREAgentNamePrefix, $LocationShortName, $Instance
    } while ((Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore) -or (Get-AzResource -ResourceGroupName $ResourceGroupName -Name $AzureSREAgentName -ErrorAction Ignore))
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentName: $AzureSREAgentName"
    #endregion 

    #region Variables
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $SubscriptionScope = "/subscriptions/{0}" -f $SubscriptionId
    $ResourceGroupScope = "{0}/resourceGroups/{1}" -f $SubscriptionScope, $ResourceGroupName
    $AzureSREAgentId = "{0}/providers/Microsoft.App/agents/{1}" -f $ResourceGroupScope, $AzureSREAgentName
    $AzureSREAgentApiVersion = '2025-05-01-preview'
    $AzureSREAgentPath = "${AzureSREAgentId}?api-version=$AzureSREAgentApiVersion"
    $AzureSREAgentIdentityId = "{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}-{2}" -f $ResourceGroupScope, $UserAssignedIdentityNamePrefix, $AzureSREAgentName
    $WorkspaceId = "{0}/providers/Microsoft.OperationalInsights/workspaces/{1}-{2}" -f $ResourceGroupScope, $LogAnalyticsWorkspaceNamePrefix, $AzureSREAgentName
    $AzureSREAgentInsightsId = "{0}/providers/Microsoft.Insights/components/{1}-{2}" -f $ResourceGroupScope, $ApplicationInsightsNamePrefix, $AzureSREAgentName
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$SubscriptionScope: $SubscriptionScope"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupScope: $ResourceGroupScope"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentId: $AzureSREAgentId"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentId: $AzureSREAgentId"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$WorkspaceId: $WorkspaceId"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentInsightsId: $AzureSREAgentInsightsId"
    #endregion 

    #region ResourceGroup
    $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    #endregion

    $TargetResourceGroupNameScopes = foreach ($CurrentTargetResourceGroupName in ($TargetResourceGroupName | Select-Object -Unique)) {
        (Get-AzResourceGroup -Name $CurrentTargetResourceGroupName).ResourceId
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$TargetResourceGroupNameScopes:`r`n$($TargetResourceGroupNameScopes | Out-String)"

    #region SRE Agent User Assigned Managed Identity
    $Parameters = @{
        ResourceId = $AzureSREAgentIdentityId
        Location = $Location
        Force = $true
        ApiVersion = '2024-11-30'
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $AzureSREAgentUserAssignedManagedIdentity = New-AzResource @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentUserAssignedManagedIdentity:`r`n$($AzureSREAgentUserAssignedManagedIdentity | Out-String)"
    #endregion

    #region SRE Agent Log Analytics Workspace
    $Parameters = @{
        ResourceId = $WorkspaceId
        Location = $Location
        Force = $true
        ApiVersion = '2023-09-01'
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $AzureSREAgentLAW = New-AzResource @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentLAW:`r`n$($AzureSREAgentLAW | Out-String)"
    #endregion

    #region SRE Agent Insights
    $Properties = @{ 
        Application_Type = 'web'
        Request_Source = 'SreAgent'
        WorkspaceResourceId = $WorkspaceId 
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Properties:`r`n$($Properties | Out-String)"
    $Parameters = @{
        ResourceId = $AzureSREAgentInsightsId
        Location = $Location
        Force = $true
        Properties = $Properties
        Kind = 'web'
        ApiVersion = '2020-02-02'
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    $AzureSREAgentInsights = New-AzResource @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgentInsights:`r`n$($AzureSREAgentInsights | Out-String)"
    #endregion

    #region RBAC Assignments
    $ReaderRole = Get-AzRoleDefinition -Name "Reader"
    $MonitoringReaderRole = Get-AzRoleDefinition -Name "Monitoring Reader"
    $LogAnalyticsReaderRole = Get-AzRoleDefinition -Name "Log Analytics Reader" 
    $SREAgentAdministratorRole = Get-AzRoleDefinition -Name "SRE Agent Administrator"

    $Parameters = @{
        ObjectId           = $AzureSREAgentUserAssignedManagedIdentity.Properties.principalId
        RoleDefinitionName = $MonitoringReaderRole.Name
        Scope              = $ResourceGroupScope
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' ObjectId on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters -ObjectType 'ServicePrincipal'

        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    foreach ($TargetResourceGroupNameScope in $TargetResourceGroupNameScopes) {
        foreach ($Role in $ReaderRole, $MonitoringReaderRole, $LogAnalyticsReaderRole) {
            $Parameters = @{
                ObjectId           = $AzureSREAgentUserAssignedManagedIdentity.Properties.principalId
                RoleDefinitionName = $Role.Name
                Scope              = $ResourceGroupScope
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
            while (-not(Get-AzRoleAssignment @Parameters)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' ObjectId on the '$($Parameters.Scope)' scope"
                $RoleAssignment = New-AzRoleAssignment @Parameters -ObjectType 'ServicePrincipal'
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                Start-Sleep -Seconds 30
            }
        }
    }
    #endregion

    #region Azure SRE Agent 
    $Body = @{
        location = $Location
        identity = @{
            type = 'SystemAssigned, UserAssigned'
            userAssignedIdentities = @{ $AzureSREAgentIdentityId = @{} }
        }
        properties = @{
            knowledgeGraphConfiguration = @{ identity = $AzureSREAgentIdentityId; managedResources = @($TargetResourceGroupNameScopes) }
            actionConfiguration = @{ accessLevel = 'Low'; identity = $AzureSREAgentIdentityId; mode = 'Review' }
            logConfiguration = @{
                applicationInsightsConfiguration = @{
                    appId = $AzureSREAgentInsights.Properties.AppId
                    connectionString = $AzureSREAgentInsights.Properties.ConnectionString
                    applicationInsightsResourceId = $AzureSREAgentInsightsId
                }
            }
            upgradeChannel = 'Preview'
            monthlyAgentUnitLimit = $MonthlyAgentUnitLimit
            defaultModel = @{ provider = $ModelProvider; name = 'Automatic' }
        }
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Body:`r`n$($Body | Out-String)"
    $Result = Invoke-AzRestMethod -Method PUT -Path $AzureSREAgentPath -Payload ($body | ConvertTo-Json -Depth 15 -Compress)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Result:`r`n$($Result | Out-String)"
    $Deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Deadline:`r`n$($Deadline | Out-String)"
    Do {
        $AzureSREAgent = (Invoke-AzRestMethod -Method GET -Path $AzureSREAgentPath).Content | ConvertFrom-Json
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzureSREAgent:`r`n$($AzureSREAgent | Out-String)"
        $ProvisioningState = $AzureSREAgent.properties.provisioningState
        if ($ProvisioningState -eq 'Succeeded') { break }
        if ($ProvisioningState -in @('Failed', 'Canceled', 'Cancelled', 'Deleting')) {
            throw "Agent creation interrupted ($ProvisioningState). Details : $($AzureSREAgent.properties | ConvertTo-Json -Depth 15 -Compress)"
        }
        if ((Get-Date) -ge $Deadline) {
            throw "Timed out for $AzureSREAgentId (state: $ProvisioningState). Creation may continue in Azure."
        }
        Start-Sleep -Seconds 10
    } while ($true)
    #endregion


    #region RBAC Assignments
    $ReaderRole = Get-AzRoleDefinition -Name "Reader"
    $MonitoringReaderRole = Get-AzRoleDefinition -Name "Monitoring Reader"
    $LogAnalyticsReaderRole = Get-AzRoleDefinition -Name "Log Analytics Reader" 
    $SREAgentAdministratorRole = Get-AzRoleDefinition -Name "SRE Agent Administrator"

    foreach ($TargetResourceGroupNameScope in $TargetResourceGroupNameScopes) {
        foreach ($Role in $ReaderRole, $MonitoringReaderRole, $LogAnalyticsReaderRole) {
            $Parameters = @{
                ObjectId           = $AzureSREAgent.Identity.principalId
                RoleDefinitionName = $Role.Name
                Scope              = $ResourceGroupScope
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
            while (-not(Get-AzRoleAssignment @Parameters)) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' ObjectId on the '$($Parameters.Scope)' scope"
                $RoleAssignment = New-AzRoleAssignment @Parameters -ObjectType 'ServicePrincipal'
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
                Start-Sleep -Seconds 30
            }
        }
    }

    $Parameters = @{
        SignInName         = (Get-AzContext).Account.Id
        RoleDefinitionName = $SREAgentAdministratorRole.Name
        Scope              = $AzureSREAgentId
    }
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Parameters:`r`n$($Parameters | Out-String)"
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters -ObjectType 'User'
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion


    [PSCustomObject] @{
        AgentId = $AzureSREAgentId
        PortalUrl = "https://sre.azure.com/agents/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/agents/{2}" -f $SubscriptionId, $ResourceGroupName, $AzureSREAgentName
        AgentEndpoint = $AzureSREAgent.properties.agentEndpoint
        ManagedIdentityId = $AzureSREAgentIdentityId
        ProvisioningState = $ProvisioningState
    }
}
#endregion


#region Main Code
Clear-Host
#$VerbosePreference = "continue"
$null = Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
# Resolve paths relative to this script rather than the caller's working directory.
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Prerequisites
#region Register required resource providers
$AzResourceProviders = 'Microsoft.App', 'Microsoft.ManagedIdentity', 'Microsoft.OperationalInsights', 'Microsoft.Insights'
$Jobs = foreach ($AzResourceProvider in $AzResourceProviders) {
    Register-AzResourceProvider -ProviderNamespace $AzResourceProvider -AsJob
}
$Jobs | Receive-Job -Wait -AutoRemoveJob | Select-Object -Property ProviderNamespace, RegistrationState
#endregion
#endregion

$Location = "CentralUS"
#Resourcegroup of the HostPool with enabled Diagnostic Settings
$TargetResourceGroupName = (Get-AzWvdHostPool | ForEach-Object -Process { Get-AzDiagnosticSetting -ResourceId $_.Id | Where-Object -FilterScript { $_.WorkspaceId }}).ResourceGroupName
if ($TargetResourceGroupName) {
    $AzAVDSREAgent = New-AzAVDSREAgent -Location $Location -TargetResourceGroupName $TargetResourceGroupName -Verbose
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$AzAVDSREAgent:`r`n$($AzAVDSREAgent | Out-String)"
    if ($AzAVDSREAgent.ProvisioningState -eq "Succeeded") {
        Start-Process $AzAVDSREAgent.PortalUrl
    }
    else {
        Write-Error "The '$($AzAVDSREAgent.AgentId)' State is '$($AzAVDSREAgent.ProvisioningState)'" -ErrorAction Stop
    }
}
else {
    Write-Warning -Message "No AVD Host Pool found ..."
}
#endregion

