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

#requires -Modules Az.Accounts, Az.DesktopVirtualization, Az.Monitor, Az.OperationalInsights, Az.Resources
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/deploy-azure-virtual-desktop-hybrid?tabs=arcaccess-portal%2Cdeployavd-portal%2Cvalidateavd-portal

#region function definitions 
function New-AzAvdHybridEntraIDPersonalHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "centralus"
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
    $DigitNumber = 3
    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $HostPoolName = "hp-pd-ei-hyb-mp-{0}-{1:D3}" -f $LocationShortName, $Instance
        $LogAnalyticsWorkSpaceName = "log{0}" -f $($HostPoolName -replace "\W")
        $ResourceGroupName = "{0}-{1}" -f $ResourceGroupNamePrefix, $HostPoolName
    } while (Get-AzResourceGroup -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolName: $HostPoolName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    #endregion 

    #region ResourceGroup
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$ResourceGroupName' ResourceGroup"
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }
    #endregion

    #region RBAC Assignments for myself
    #region 'Desktop Virtualization Contributor' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition -Name "Desktop Virtualization Contributor"
    foreach ($Scope in $Scopes) {
        $Parameters = @{
            SignInName         = (Get-AzContext).Account.Id
            RoleDefinitionName = $RoleDefinition.Name
            Scope              = $ResourceGroup.ResourceId
        }
        while (-not(Get-AzRoleAssignment @Parameters)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
            $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
            Start-Sleep -Seconds 30
        }
    }
    #endregion 

    #region 'Azure Connected Machine Onboarding' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition -Name "Azure Connected Machine Onboarding"
    foreach ($Scope in $Scopes) {
        $Parameters = @{
            SignInName         = (Get-AzContext).Account.Id
            RoleDefinitionName = $RoleDefinition.Name
            Scope              = $ResourceGroup.ResourceId
        }
        while (-not(Get-AzRoleAssignment @Parameters)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
            $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
            Start-Sleep -Seconds 30
        }
    }
    #endregion 
    #endregion

    #region Log Analytics WorkSpace
    $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroup.ResourceGroupName -Force
    #endregion

    #region HostPool Setup
    #region Create a HostPool
    $CurrentHostPool = [PSCustomObject] @{
        Name                            = $HostPoolName
        LoadBalancerType                = "Persistent"
        PreferredAppGroupType           = "Desktop"
        Location                        = $Location
        ResourceGroupName               = $ResourceGroupName
        WorkSpaceName                   = $ResourceGroupName -replace "^rg", "ws"
    }

    $CustomRdpProperty = "enablerdsaadauth:i:1;redirectcomports:i:0;redirectlocation:i:0;redirectprinters:i:0;drivestoredirect:s:;usbdevicestoredirect:s:;"
    $Parameters = @{
        Name                  = $CurrentHostPool.Name
        FriendlyName          = "{0} (HostPool Friendly Name)" -f $CurrentHostPool.Name
        ResourceGroupName     = $ResourceGroupName
        HostPoolType          = 'Personal'
        LoadBalancerType      = $CurrentHostPool.LoadBalancerType
        PreferredAppGroupType = $CurrentHostPool.PreferredAppGroupType
        Location              = $CurrentHostPool.Location
        StartVMOnConnect      = $true
        # From https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files?context=%2Fazure%2Fvirtual-desktop%2Fcontext%2Fcontext#device-redirection
        # No RDP redirection for COM ports, Local Drives and printers.
        ExpirationTime        = (Get-Date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        CustomRdpProperty     = $CustomRdpProperty
        IdentityType          = "SystemAssigned"
        #ValidationEnvironment = $true
        #Verbose               = $true
    }
    $CurrentAzWvdHostPool = New-AzWvdHostPool @Parameters
    #endregion

    #region RBAC Assignments for the HostPool System-Assigned Managed Identity
    #region 'Reader' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition -Name "Reader"
    $Parameters = @{
        ObjectId           = $CurrentAzWvdHostPool.IdentityPrincipalId
        RoleDefinitionName = $RoleDefinition.Name
        Scope              = $ResourceGroup.ResourceId
    }
    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' ObjectId on the '$($Parameters.Scope)' scope"
        $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion 
    #endregion

    #region Enabling Diagnostics Setting for the HostPool
    $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
    $HostPoolDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdHostPool.Name -ResourceId $CurrentAzWvdHostPool.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
    #endregion
    #endregion

    #region Desktop Application Group Setup
    #region Create a Desktop Application Group
    $Parameters = @{
        Name                 = "{0}-DAG" -f $CurrentHostPool.Name
        FriendlyName         = "{0}(DAG Friendly Name)" -f $CurrentHostPool.Name
        ResourceGroupName    = $CurrentHostPool.ResourceGroupName
        Location             = $CurrentHostPool.Location
        HostPoolArmPath      = $CurrentAzWvdHostPool.Id
        ApplicationGroupType = 'Desktop'
        ShowInFeed           = $true
        #Verbose              = $true
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$($CurrentHostPool.ResourceGroupName)' Resource Group)"
    $CurrentAzDesktopApplicationGroup = New-AzWvdApplicationGroup @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The Desktop Application Group for the '$($CurrentHostPool.Name)' Host Pool (in the '$($CurrentHostPool.ResourceGroupName)' Resource Group) is created"

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Updating the friendly name of the Desktop for the Desktop Application Group of the '$($CurrentHostPool.Name)' Host Pool (in the '$($CurrentHostPool.ResourceGroupName)' Resource Group) to '$($CurrentHostPool.Name)'"
    $Parameters = @{
        ApplicationGroupName = $CurrentAzDesktopApplicationGroup.Name
        ResourceGroupName    = $CurrentHostPool.ResourceGroupName
    }
    $FriendlyName = "{0} (Desktop Friendly Name)" -f $Parameters["ApplicationGroupName"]
    $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName $CurrentHostPool.Name
    #endregion

    #region Assign 'Desktop Virtualization User' RBAC role to application groups
    # Get the object ID of the user group you want to assign to the application group
    $EntraIDGroup = Get-AzADGroup -DisplayName "AVD Users"

    if ($EntraIDGroup) {
        $ObjectId = $EntraIDGroup.Id
    }
    else {
        $ObjectId = (Get-AzADUser -ObjectId  $((Get-AzContext).Account.Id)).Id
    }
    # Assign users to the application group
    #region 'Desktop Virtualization User' RBAC Assignment
    $RoleDefinition = Get-AzRoleDefinition -Name "Desktop Virtualization User"

    $Parameters = @{
        ObjectId           = $ObjectId
        ResourceName       = $CurrentAzDesktopApplicationGroup.Name
        ResourceGroupName  = $CurrentHostPool.ResourceGroupName
        RoleDefinitionName = $RoleDefinition.Name
        ResourceType       = 'Microsoft.DesktopVirtualization/applicationGroups'
    }

    while (-not(Get-AzRoleAssignment @Parameters)) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.ObjectId)' Identity on the '$($Parameters.ObjectId)' ObjectId"
        $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        $Seconds = 30
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping $Seconds Seconds"
        Start-Sleep -Seconds $Seconds
    }
    #endregion
    #endregion 

    #region Enabling Diagnostics Setting for the Desktop Application Group
    $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
    $DesktopApplicationGroupDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzDesktopApplicationGroup.Name -ResourceId $CurrentAzDesktopApplicationGroup.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
    #endregion
    #endregion

    #region Workspace Setup
    #region Create a Workspace
    $ApplicationGroupReference = $CurrentAzDesktopApplicationGroup.Id
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ApplicationGroupReference: $($ApplicationGroupReference -join ', ')"

    $Parameters = @{
        Name                      = $CurrentHostPool.WorkSpaceName
        FriendlyName              = "{0} (Workspace Friendly Name)" -f $CurrentHostPool.WorkSpaceName
        ResourceGroupName         = $CurrentHostPool.ResourceGroupName
        ApplicationGroupReference = $ApplicationGroupReference
        Location                  = $CurrentHostPool.Location
        #Verbose                   = $true
    }

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$($CurrentHostPool.ResourceGroupName)' Resource Group)"
    $CurrentAzWvdWorkspace = New-AzWvdWorkspace @Parameters
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The WorkSpace for the '$($CurrentHostPool.Name)' Host Pool (in the '$($CurrentHostPool.ResourceGroupName)' Resource Group) is created"
    #endregion

    #region Enabling Diagnostics Setting for the WorkSpace
    $Log = New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs 
    $WorkSpaceDiagnosticSetting = New-AzDiagnosticSetting -Name $CurrentAzWvdWorkspace.Name -ResourceId $CurrentAzWvdWorkspace.Id -WorkspaceId $LogAnalyticsWorkSpace.ResourceId -Log $Log
    #endregion
    #endregion

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"

    return $CurrentAzWvdHostPool
}
#endregion

#region Main code
Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$SubscriptionId = (Get-AzContext).Subscription.Id
$Location = "centralus"

#region Registering required Providers
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization
$null = Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
#endregion


$Parameters = @{
    Location             = $Location 
    Verbose              = $true
}
$PersonalHostPool = New-AzAvdHybridEntraIDPersonalHostPoolSetup @Parameters
#endregion