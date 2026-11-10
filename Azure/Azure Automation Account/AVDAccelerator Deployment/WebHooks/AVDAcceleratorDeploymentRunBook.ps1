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
    
    $Location = "CentralUs"
    Write-Output -InputObject "`$Location: $Location"
    $DeploymentName = "AVDAcceleratorDeployment_ARM_{0:yyyyMMddHHmmss}" -f $(Get-Date)
    Write-Output -InputObject "`$DeploymentName: $DeploymentName"
    $TemplateUri = "https://raw.githubusercontent.com/Azure/avdaccelerator/main/workload/arm/deploy-baseline.json"
    Write-Output -InputObject "`$TemplateUri: $TemplateUri"
    $Name = "AVDVmLocalAdminCredential"
    $avdVmLocalUserCredential = Get-AutomationPSCredential -Name $Name
    $VNET = $HostPoolData.VNET 
    $VMNumb = $HostPoolData.VMNumb

    if ($VNET -match '^([A-Za-z]+)(\d{2,})$') {
        $letters = $matches[1]
        $numb = $matches[2]
        $LastDigits = $Matches[2].Substring($Matches[2].Length-2,2)
        $trn= ("tr"+$LastDigits).ToLower()
    }
    else {
        Write-Error -Message "'$VNET' is not well formatted ..." -ErrorAction Stop
    }
    
    $TemplateParameterObject = @{ 
	    deploymentPrefix                              = "$trn"
	    deploymentEnvironment                         = "Test"
	    diskEncryptionKeyExpirationInDays             = 60
	    avdSessionHostLocation                        = $Location
	    avdManagementPlaneLocation                    = $Location
	    avdWorkloadSubsId                             = $SubscriptionId
	    avdServicePrincipalObjectId                   = $avdServicePrincipalObjectId
	    avdArmServicePrincipalObjectId                = ""
	    avdVmLocalUserName                            = $avdVmLocalUserCredential.UserName
	    avdVmLocalUserPassword                        = $avdVmLocalUserCredential.Password
	    avdIdentityServiceProvider                    = "ADDS"
	    createIntuneEnrollment                        = $False
	    avdSecurityGroups                             = $avdSecurityGroups
	    identityDomainName                            = "csa.fr"
	    identityDomainGuid                            = ""
	    avdDomainJoinUserName                         = $avdDomainJoinUserCredential.UserName
	    avdDomainJoinUserPassword                     = $avdDomainJoinUserCredential.Password
	    avdOuPath                                     = "OU=AVDAccelerator,OU=$Location,OU=AVD,DC=csa,DC=fr"
	    avdHostPoolType                               = "Pooled"
	    hostPoolPreferredAppGroupType                 = "Desktop"
	    hostPoolPublicNetworkAccess                   = "Enabled"
	    workspacePublicNetworkAccess                  = "Enabled"
	    avdPersonalAssignType                         = "Automatic"
	    avdHostPoolLoadBalancerType                   = "BreadthFirst"
	    hostPoolMaxSessions                           = 8
	    avdStartVmOnConnect                           = $True
	    avdHostPoolRdpProperties                      = "audiocapturemode:i:1;audiomode:i:0;drivestoredirect:s:;redirectclipboard:i:1;redirectcomports:i:1;redirectprinters:i:1;redirectsmartcards:i:1;screen mode id:i:2"
	    avdDeployScalingPlan                          = $True
	    createAvdVnet                                 = $True
	    existingVnetAvdSubnetResourceId               = ""
	    existingVnetPrivateEndpointSubnetResourceId   = ""
	    existingHubVnetResourceId                     = "/subscriptions/$SubscriptionId/resourcegroups/rg-avd-ad-usc-002/providers/microsoft.network/virtualnetworks/vnet-avd-ad-usc-002"
	    avdVnetworkAddressPrefixes                    = "10.201.0.0/16"
	    vNetworkAvdSubnetAddressPrefix                = "10.201.1.0/24"
	    vNetworkPrivateEndpointSubnetAddressPrefix    = "10.201.2.0/27"
	    customDnsIps                                  = "10.0.1.4"
	    deployDDoSNetworkProtection                   = $False
	    deployPrivateEndpointKeyvaultStorage          = $false
	    deployAvdPrivateLinkService                   = $False
	    createPrivateDnsZones                         = $false
	    avdVnetPrivateDnsZoneConnectionResourceId     = ""
	    avdVnetPrivateDnsZoneDiscoveryResourceId      = ""
	    avdVnetPrivateDnsZoneFilesId                  = ""
	    avdVnetPrivateDnsZoneKeyvaultId               = ""
	    vNetworkGatewayOnHub                          = $False
	    createAvdFslogixDeployment                    = $True
	    createAppAttachDeployment                     = $False
	    fslogixFileShareQuotaSize                     = 1
	    appAttachFileShareQuotaSize                   = 1
	    avdDeploySessionHosts                         = $True
	    deployGpuPolicies                             = $False
	    avdDeployMonitoring                           = $True
	    deployAlaWorkspace                            = $True
	    deployCustomPolicyMonitoring                  = $False
	    avdAlaWorkspaceDataRetention                  = 90
	    alaExistingWorkspaceResourceId                = ""
	    avdDeploySessionHostsCount                    = $VMNumb
	    avdSessionHostCountIndex                      = 1
	    availability                                  = "None"
	    availabilityZones                             = @()
	    zoneRedundantStorage                          = $False
	    fslogixStoragePerformance                     = "Premium"
	    appAttachStoragePerformance                   = "Premium"
	    diskZeroTrust                                 = $False
	    avdSessionHostsSize                           = "Standard_D4ads_v5"
	    avdSessionHostDiskType                        = "Premium_LRS"
	    customOsDiskSizeGB                            = 0
	    enableAcceleratedNetworking                   = $True
	    securityType                                  = "TrustedLaunch"
	    secureBootEnabled                             = $true
	    vTpmEnabled                                   = $true
	    useSharedImage                                = $False
	    mpImageOffer                                  = "office-365"
	    mpImageSku                                    = "win11-25h2-avd-m365"
	    avdCustomImageDefinitionId                    = ""
	    managementVmOsImage                           = "winServer_2022_Datacenter_smalldisk_g2"
	    storageOuPath                                 = "OU=AVDAccelerator,OU=$Location,OU=AVD,DC=csa,DC=fr"
	    avdUseCustomNaming                            = $False
	    avdServiceObjectsRgCustomName                 = ""
	    avdNetworkObjectsRgCustomName                 = ""
	    avdComputeObjectsRgCustomName                 = ""
	    avdStorageObjectsRgCustomName                 = ""
	    avdMonitoringRgCustomName                     = ""
	    avdVnetworkCustomName                         = ""
	    avdAlaWorkspaceCustomName                     = ""
	    avdVnetworkSubnetCustomName                   = ""
	    privateEndpointVnetworkSubnetCustomName       = ""
	    avdNetworksecurityGroupCustomName             = ""
	    privateEndpointNetworksecurityGroupCustomName = ""
	    avdRouteTableCustomName                       = ""
	    privateEndpointRouteTableCustomName           = ""
	    avdApplicationSecurityGroupCustomName         = ""
	    avdWorkSpaceCustomName                        = ""
	    avdWorkSpaceCustomFriendlyName                = ""
	    avdHostPoolCustomName                         = ""
	    avdHostPoolCustomFriendlyName                 = ""
	    avdScalingPlanCustomName                      = ""
	    avdApplicationGroupCustomName                 = ""
	    avdApplicationGroupCustomFriendlyName         = ""
	    avdSessionHostCustomNamePrefix                = ""
	    storageAccountPrefixCustomName                = ""
	    fslogixFileShareCustomName                    = ""
	    appAttachFileShareCustomName                  = ""
	    avdWrklKvPrefixCustomName                     = ""
	    ztDiskEncryptionSetCustomNamePrefix           = "des-zt"
	    ztKvPrefixCustomName                          = "kv-key"
	    createResourceTags                            = $False
	    workloadNameTag                               = ""
	    workloadTypeTag                               = "Light"
	    dataClassificationTag                         = "Non-business"
	    departmentTag                                 = ""
	    workloadCriticalityTag                        = "Low"
	    workloadCriticalityCustomValueTag             = "Low"
	    applicationNameTag                            = ""
	    workloadSlaTag                                = ""
	    opsTeamTag                                    = ""
	    ownerTag                                      = ""
	    costCenterTag                                 = ""
	    enableTelemetry                               = $True
	    enableKvPurgeProtection                       = $True
	    deployAntiMalwareExt                          = $True
	    customStaticRoutes                            = @()
	    deployDefender                                = $False
	    enableDefForServers                           = $False
	    enableDefForStorage                           = $False
	    enableDefForKeyVault                          = $False
	    enableDefForArm                               = $False
    }

    #region Cleaning up any existing resource group with same Deployment Prefix and Environment
    Write-Output -InputObject "Cleaning up any previously existing deployments ..."
    $null = Get-AzResourceGroup -ResourceGroupName $("rg-avd-{0}-{1}*" -f $TemplateParameterObject.deploymentPrefix, $TemplateParameterObject.deploymentEnvironment).ToLower() | Remove-AzResourceGroup -AsJob -Force | Receive-Job -Wait -AutoRemoveJob
    #endregion


    #$SubscriptionDeployment = New-AzSubscriptionDeployment -Name $DeploymentName -Location $Location -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile  -Verbose
    Write-Output -InputObject "Deploying ..."

    $SubscriptionDeploymentURI = "https://portal.azure.com/#view/Microsoft_Azure_Resources/DeploymentDetails.MenuView/~/overview/id/subscriptions/{0}/providers/Microsoft.Resources/deployments/{1}" -f $SubscriptionId, $DeploymentName
    Write-Output -InputObject "`$SubscriptionDeploymentURI: $SubscriptionDeploymentURI"

    #$SubscriptionDeployment = New-AzSubscriptionDeployment -Name $DeploymentName -Location $Location -TemplateFile $TemplateFile -TemplateParameterObject $TemplateParameterObject -Verbose #-DeploymentDebugLogLevel All
    $SubscriptionDeployment = New-AzSubscriptionDeployment -Name $DeploymentName -Location $Location -TemplateUri $TemplateUri -TemplateParameterObject $TemplateParameterObject -Verbose #-DeploymentDebugLogLevel All
    $SubscriptionDeployment.ProvisioningState
    Write-Output -InputObject "ProvisioningState: $($SubscriptionDeployment.ProvisioningState)"
    if ($SubscriptionDeployment.ProvisioningState -ne "Succeeded") {
        Write-Error -Message "Deployment Status: $($SubscriptionDeployment.ProvisioningState)" -ErrorAction Stop
    }

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
 
