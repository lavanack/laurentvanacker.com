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

#requires -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Az.KeyVault, Az.Network, Az.Resources
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/deploy-azure-virtual-desktop?pivots=host-pool-session-host-configuration&tabs=portal-standard%2Cpowershell-session-host-configuration%2Cportal#create-a-host-pool-with-a-session-host-configuration

#region function definitions 
function New-AzAvdHybridEntraIDPersonalHostPoolSetup {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "centralus",
        [Parameter(Mandatory = $true)]
        [ValidatePattern("/subscriptions/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/resourceGroups/.+/providers/Microsoft\.Network/virtualNetworks/.+/subnets/.+")] 
        [string]$SubNetId = "/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-ad-usc-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-usc-002/subnets/snet-avd-avd-usc-002"
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
    $KeyVaultPrefix = $ResourceTypeShortNameHT["KeyVault/vaults"].ShortName
    $DigitNumber = 3
    Do {
        $Instance = Get-Random -Minimum 0 -Maximum $([long]([Math]::Pow(10, $DigitNumber)))
        $HostPoolName = "hp-pd-ei-hyb-mp-{0}-{1:D3}" -f $LocationShortName, $Instance
        $LogAnalyticsWorkSpaceName = "log{0}" -f $($HostPoolName -replace "\W")
        $KeyVaultName = "{0}{1}" -f $KeyVaultPrefix, $($HostPoolName -replace "\W")
        $ResourceGroupName = "{0}-{1}" -f $ResourceGroupNamePrefix, $HostPoolName
    } while (-not(Test-AzKeyVaultNameAvailability -Name $KeyVaultName).NameAvailable)
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPoolName: $HostPoolName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$KeyVaultName: $KeyVaultName"
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$ResourceGroupName: $ResourceGroupName"
    #endregion 

    #region ResourceGroup
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore 
    if ($null -eq $ResourceGroup) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating the '$ResourceGroupName' ResourceGroup"
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force
    }
    #endregion

    #region Log Analytics WorkSpace
    $LogAnalyticsWorkSpace = New-AzOperationalInsightsWorkspace -Location $Location -Name $LogAnalyticsWorkSpaceName -Sku pergb2018 -ResourceGroupName $ResourceGroup.ResourceGroupName -Force
    #endregion

    #region HostPool Setup
    #region Create a HostPool
    $CurrentHostPool = [PSCustomObject] @{
        Name                            = $HostPoolName
        GetSessionHostConfigurationName = $ResourceGroupName -replace "^rg", "shc"
        LoadBalancerType                = "Persistent"
        PreferredAppGroupType           = "Desktop"
        Location                        = $Location
        NamePrefix                      = "nem{0}{1:D3}" -f $LocationShortName, $Instance
        VMSize                          = "Standard_D2s_v5"
        SubnetId                        = $SubNetId
        ImagePublisherName              = "microsoftwindowsdesktop"
        ImageOffer                      = "office-365"
        ImageSku                        = "win11-24h2-avd-m365"
        VMNumberOfInstances             = 1
        ResourceGroupName               = $ResourceGroupName
        WorkSpaceName                   = $ResourceGroupName -replace "^rg", "ws"
        ScalingPlan                     = $true
        #Installing VS Code on All AVD Session Hosts
        CustomConfigurationScriptUrl    = "https://raw.githubusercontent.com/lavanack/laurentvanacker.com/refs/heads/master/Azure/Azure%20VM%20Image%20Builder/Install-VSCode.ps1"
    }

    $Parameters = @{
        Name                  = $CurrentHostPool.Name
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
        Tag                   = $Tag
        ManagementType        = 'Standard'
        ValidationEnvironment = $true
        #Verbose               = $true
    }
    $CurrentAzWvdHostPool = New-AzWvdHostPool @Parameters
    #endregion

    #region RBAC Assignments to the HostPool System-Assigned Managed Identity
    $ObjectId = $CurrentAzWvdHostPool.IdentityPrincipalId

    #region 'Desktop Virtualization Virtual Machine Contributor' RBAC Assignment
    $NsgId = (Get-AzVirtualNetworkSubnetConfig -ResourceId $SubNetId).NetworkSecurityGroup.Id
    $vNetId = $SubNetId -replace "/subnets/.*"
    $Scopes = (Get-AzResourceGroup -ResourceGroupName $CurrentHostPool.ResourceGroupName).ResourceId, $vNetId, $NsgId
    #/subscriptions/30c8d9eb-366e-4d2c-a723-95bc688f7c97/resourceGroups/rg-avd-aib-usc-1750417854/providers/Microsoft.Compute/galleries/acg_avd_usc_1750417854/images/win11-24h2-avd-json-vscode/versions/2025.06.20
    if ($CurrentHostPool.VMSourceImageId) {
        #$ACGResourceGroupId = $(Get-AzresourceGroup  -ResourceGroupName $((Get-AzResource -ResourceId $CurrentHostPool.VMSourceImageId).ResourceGroupName)).ResourceId
        $ACGResourceGroupId = $CurrentHostPool.VMSourceImageId -replace "/providers/.+"
        $Scopes += $ACGResourceGroupId
    }
    $RoleDefinition = Get-AzRoleDefinition -Name "Desktop Virtualization Virtual Machine Contributor"
    foreach ($Scope in $Scopes) {
        $Parameters = @{
            ObjectId           = $ObjectId
            RoleDefinitionName = $RoleDefinition.Name
            Scope              = $Scope
        }
        while (-not(Get-AzRoleAssignment @Parameters)) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Assigning the '$($Parameters.RoleDefinitionName)' RBAC role to the '$($Parameters.SignInName)' Identity on the '$($Parameters.Scope)' scope"
            $RoleAssignment = New-AzRoleAssignment @Parameters -ErrorAction Ignore
            Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Sleeping 30 seconds"
            Start-Sleep -Seconds 30
        }
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
        #FriendlyName         = $CurrentHostPool.Name
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
    $null = Get-AzWvdDesktop @parameters | Update-AzWvdDesktop -FriendlyName $CurrentHostPool.Name
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
        FriendlyName              = $FriendlyName
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


$Parameters = @{
    Location             = $Location 
    SubNetId             = "/subscriptions/{0}/resourceGroups/rg-avd-ad-usc-002/providers/Microsoft.Network/virtualNetworks/vnet-avd-avd-usc-002/subnets/snet-avd-avd-usc-002" -f $SubscriptionId
    Verbose              = $true
}
$PersonalHostPool = New-AzAvdHybridEntraIDPersonalHostPoolSetup @Parameters
#endregion