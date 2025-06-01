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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Resources

#region function definitions 
#This function returns the available and non-available availablity zones for an Azure VM Size in an Azure Region
function Get-AzVMSkuAvailabilityZone {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string[]] $Location = "francecentral",
        [string[]] $SKU
    )
    # Get access token for authentication
    $SubscriptionId = (Get-AzContext).Subscription.Id

    #region  Register AvailabilityZonePeering feature if not registered
    $featureStatus = (Get-AzProviderFeature -ProviderNamespace "Microsoft.Resources" -FeatureName "AvailabilityZonePeering").RegistrationState

    if ($featureStatus -ne "Registered") {
        Write-Verbose -Message "Registering AvailabilityZonePeering feature"
        Register-AzProviderFeature -FeatureName "AvailabilityZonePeering" -ProviderNamespace "Microsoft.Resources"
        do {
            $featureStatus = (Get-AzProviderFeature -ProviderNamespace "Microsoft.Resources" -FeatureName "AvailabilityZonePeering").RegistrationState
            Write-Verbose -Message "Waiting for AvailabilityZonePeering feature to be registered....waiting 35 seconds"
            Start-Sleep -Seconds 35
        } until ($featureStatus -eq "Registered")
    }
    Write-Verbose -Message "AvailabilityZonePeering feature is Successfully registered."    
    #endregion

    #From https://www.seifbassem.com/blogs/posts/tips-get-region-availability-zones/
    $AzContext = Get-AzContext
    $AzProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $ProfileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($AzProfile)
    $Token = $ProfileClient.AcquireAccessToken($AzContext.Subscription.TenantId)
    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $Token.AccessToken
    }

    $LocationAvailabilityZone = foreach ($CurrentLocation in $Location) {
        # Generate the API endpoint body containing the Azure region and list of subscription Ids to get the information for
        Write-Verbose -Message "Processing '$CurrentLocation'"
        $body = @{
            location        = $CurrentLocation
            SubscriptionIds = @("subscriptions/$SubscriptionId")
        } | ConvertTo-Json

        # Calling the API endpoint and getting the supported availability zones
        try {
            $apiEndpoint = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Resources/checkZonePeers/?api-version=2022-12-01"
            $response = Invoke-RestMethod -Method Post -Uri $apiEndpoint -Body $body -Headers $headers
            $zones = $response.AvailabilityZonePeers.AvailabilityZone
            [PSCustomObject]@{Location = $CurrentLocation; Zone = $Zones }
            Write-Verbose -Message "The region '$CurrentLocation' supports availability zones: $($zones -join ', ')"
        }
        catch {
            Write-Verbose -Message $($_.ErrorDetails.Message)
        }
    }
    if ($null -eq $SKU) {
        return $LocationAvailabilityZone
    }
    else {
        $LocationAvailabilityZoneHT = $LocationAvailabilityZone | Group-Object -Property Location -AsHashTable -AsString
        #From https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-sku-not-available?tabs=azure-powershell#solution
        $SKUAvailabilityZone = foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation'"
            $VMSKUs = Get-AzComputeResourceSku -Location $CurrentLocation | Where-Object { $_.ResourceType -eq "virtualMachines" -and $_.Name -in $SKU } #| Select-Object -Property Locations, Name, @{Name="Zones"; Expression = {$_.Restrictions.RestrictionInfo.Zones}}
            foreach ($CurrentVMSKU in $VMSKUs) {
                Write-Verbose -Message "Processing '$($CurrentVMSKU.Name)'"
                $CurrentVMSKURestrictionType = $CurrentVMSKU.Restrictions.Type | Out-String
                $LocRestriction = if ($CurrentVMSKURestrictionType.Contains("Location")) {
                    "NotAvailableInRegion"
                }
                else {
                    "Available - No region restrictions applied"
                }

                $ZoneRestriction = if ($CurrentVMSKURestrictionType.Contains("Zone")) {
                    $NotAvailableInZone = ((($CurrentVMSKU.Restrictions.RestrictionInfo.Zones) | Where-Object -FilterScript { $_ } | Sort-Object))
                    [PSCustomObject] @{
                        NotAvailableInZone = $NotAvailableInZone
                        AvailableInZone    = (Compare-Object -ReferenceObject $LocationAvailabilityZoneHT[$CurrentLocation].Zone -DifferenceObject $NotAvailableInZone).InputObject
                    }
                }
                else {
                    [PSCustomObject] @{
                        NotAvailableInZone = $null
                        AvailableInZone    = $CurrentVMSKU.LocationInfo.Zones
                    }
                }
                [PSCustomObject] @{
                    "Name"                    = $SkuName
                    "Location"                = $CurrentLocation
                    "AppliesToSubscriptionId" = $SubId
                    "SubscriptionRestriction" = $LocRestriction
                    "ZoneRestriction"         = $ZoneRestriction
                }
            }
        }
        return $SKUAvailabilityZone
    }
}

#From https://learn.microsoft.com/en-us/azure/virtual-machines/move-virtual-machines-regional-zonal-powershell?tabs=PowerShell
#From https://4sysops.com/archives/move-resources-with-azure-resource-mover-using-powershell/
function Move-AzResource {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias("ResourceGroupName")]
        [string] $SourceResourceGroupName,
        [Parameter(Mandatory = $true)]
        [ValidateSet(1, 2, 3)]
        [Alias("AvailabilityZone")]
        [uint16] $TargetAvailabilityZone
    )

    #region Registering provider
    $null = Register-AzResourceProvider -ProviderNamespace Microsoft.Migrate
    While (((Get-AzResourceProvider -ProviderNamespace Microsoft.Migrate) | Where-Object -FilterScript { ($_.RegistrationState -eq "Registered") -and ($_.ResourceTypes.ResourceTypeName -eq "moveCollections") } | Measure-Object).Count -eq 0) {
        Start-Sleep -Seconds 5
        Write-Host "Waiting for registration to complete."
    }
    #endregion

    $SourceResourceGroup = Get-AzResourceGroup -ResourceGroupName $SourceResourceGroupName
    $MoveCollectionName = "RegionToZone-$SourceResourceGroupName"
    
    #Removing any existing MoveCollection with same Name and ResourceGroupName
    if (Get-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -ErrorAction Ignore) {
        $Result = Remove-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -PassThru
        if ($Result) {
            Write-Verbose -Message "$MoveCollectionName MoveCollection (ResourceGroupName: '$SourceResourceGroupName') successfully removed ..."
        }
        else {
            Write-Warning -Message "Unable to remove $MoveCollectionName MoveCollection (ResourceGroupName: '$SourceResourceGroupName') ..."
        }
    }
    #Creating a MoveCollection object
    $MoveCollection = New-AzResourceMoverMoveCollection -Name $MoveCollectionName -ResourceGroupName $SourceResourceGroupName -MoveRegion $SourceResourceGroup.Location -Location $SourceResourceGroup.Location -IdentityType "SystemAssigned" -MoveType "RegionToZone"

    $IdentityPrincipalId = $MoveCollection.IdentityPrincipalId
    $SubscriptionID = (Get-AzContext).Subscription.Id
    $Scope = "/subscriptions/$SubscriptionID"

    #region RBAC Role Assignment 
    #Granting access to the managed identity  

    $RBACRole = Get-AzRoleDefinition "Contributor"
    While (-not(Get-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope)) {
        Write-Verbose -Message "Assigning the '$($RBACRole.Name)' RBAC role to the '$identityPrincipalId' identity on the '$($Scope)' Subcription"
        $RoleAssignment = New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope -ErrorAction Ignore
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    $RBACRole = Get-AzRoleDefinition "User Access Administrator"
    While (-not(Get-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope)) {
        Write-Verbose -Message "Assigning the '$($RBACRole.Name)' RBAC role to the '$identityPrincipalId' identity on the '$($Scope)' Subcription"
        $RoleAssignment = New-AzRoleAssignment -ObjectId $identityPrincipalId -RoleDefinitionName $RBACRole.Name -Scope $Scope -ErrorAction Ignore
        Write-Verbose -Message "`$RoleAssignment:`r`n$($RoleAssignment | Out-String)"
        Write-Verbose -Message "Sleeping 30 seconds"
        Start-Sleep -Seconds 30
    }
    #endregion

    $SourceId = "/subscriptions/$SubscriptionID/resourcegroups/$SourceResourceGroupName/providers/Microsoft.Compute/virtualMachines/RegionToZone-demoSourceVm"
    #$MoveResourceName = "MoveResource-$SourceResourceGroupName"
    

    #region Adding regional VMs to the move collection
    $AzVMSkuAvailabilityZoneHT = @{}
    $SourceVMs = Get-AzVM -ResourceGroupName $SourceResourceGroupName
    $MoveResource = foreach ($CurrentSourceVM in $SourceVMs) {
        Write-Host -Object "Processing the '$($CurrentSourceVM.Name)' VM (ResourceGroupName: '$SourceResourceGroupName') ..."

        #region Getting the Availability Zones for this SKU in the Azure location (and using an Hashtable as cache)
        $AvailableInZone = $AzVMSkuAvailabilityZoneHT[$CurrentSourceVM.HardwareProfile.VmSize]
        if (-not($AvailableInZone)) {
            $AvailableInZone = (Get-AzVMSkuAvailabilityZone -SKU $CurrentSourceVM.HardwareProfile.VmSize -Location $CurrentSourceVM.Location).ZoneRestriction.AvailableInZone
            $AzVMSkuAvailabilityZoneHT[$CurrentSourceVM.HardwareProfile.VmSize] = $AvailableInZone
        }
        Write-Verbose -Message "`$AvailableInZone: $AvailableInZone"
        #endregion

        if ($TargetAvailabilityZone -notin $AvailableInZone) {
            Write-Error -Message "The '$($CurrentSourceVM.Name)' SKU ('$($CurrentSourceVM.HardwareProfile.VmSize)') is NOT available in the Availability Zone '$TargetAvailabilityZone'. Skipping this Azure VM"
        } else {
            Write-Verbose -Message "The '$($CurrentSourceVM.Name)' SKU ('$($CurrentSourceVM.HardwareProfile.VmSize)') is available in the Availability Zone '$TargetAvailabilityZone'."
            #region Creating target resource setting object 
            $TargetResourceSettings = New-Object Microsoft.Azure.PowerShell.Cmdlets.ResourceMover.Models.Api20230801.VirtualMachineResourceSettings
            $TargetResourceSettings.ResourceType = $CurrentSourceVM.Type
            #Default action and naming convention
            $TargetResourceGroupName = "{0}-{1}" -f $SourceResourceGroupName, $CurrentSourceVM.Location
            Write-Host -Object "Setting up the move of the '$($CurrentSourceVM.Name)' VM to another ResourceGroup ('$TargetResourceGroupName'). The VM name will be the same: '$($CurrentSourceVM.Name)' ..."
            $TargetResourceSettings.TargetResourceGroupName = $TargetResourceGroupName		
            $TargetResourceSettings.TargetResourceName = $CurrentSourceVM.Name
            $TargetResourceSettings.TargetAvailabilityZone = $TargetAvailabilityZone
            #endregion

            $MoveResourceName = "MoveResource-{0}" -f $CurrentSourceVM.Name

            try {
                Add-AzResourceMoverMoveResource -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -SourceId $CurrentSourceVM.Id -Name $MoveResourceName -ResourceSetting $TargetResourceSettings -ErrorAction Stop
            }
            catch {
                Write-Warning -Message "Unable to add the '$($CurrentSourceVM.Name)' VM (ResourceGroupName: '$SourceResourceGroupName') to the Resource Mover;`r`n:$($_.ErrorDetails.Message)"
            }
        }
    }
    #endregion

    #region Move Validation and Move if success
    if ($MoveResource) {
        Write-Verbose -Message "`$MoveResource:`r`n$($MoveResource | Out-String)"
        #Resolving dependencies
        Write-Host -Object "Resolving dependencies ..."
        $Resolve = Resolve-AzResourceMoverMoveCollectionDependency -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName
        Write-Verbose -Message "`$Resolve:`r`n$($Resolve | Out-String)"

        #Retrieving a list of all missing dependencies:
        $UnresolvedDependency = Get-AzResourceMoverUnresolvedDependency -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -DependencyLevel Descendant
        Write-Verbose -Message "`$UnresolvedDependency:`r`n$($UnresolvedDependency | Out-String)"

        if ($Resolve.Status -eq "Succeeded") {
            #Getting a list of resources added to the move collection:
            $List = Get-AzResourceMoverMoveResource -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName
            Write-Verbose -Message "List of resources added to the move collection:`r`n$($List | Out-String)"

            #Validating the dependencies before Initiate Move for the resources.
            $Validate = Invoke-AzResourceMoverInitiateMove -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name -MoveResourceInputType "MoveResourceId" -ValidateOnly
            Write-Verbose -Message "`$Validate:`r`n$($Validate | Out-String)"
            if ($Validate.Status -eq "Succeeded") {
                Write-Host -Object "Move Validation Completed !"
                try {
                    #Initiating move of VM resources
                    Write-Host -Object "Initiating the move ..."
                    $MoveStatus = Invoke-AzResourceMoverInitiateMove -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name -MoveResourceInputType "MoveResourceId" -ErrorAction Stop
                    Write-Verbose -Message "`$MoveStatus:`r`n$($MoveStatus | Out-String)"
                    #Committing
                    Write-Verbose -Message "Completing the move ..."
                    $CommitStatus = Invoke-AzResourceMoverCommit -ResourceGroupName $SourceResourceGroupName -MoveCollectionName $MoveCollectionName -MoveResource $MoveResource.Name
                    Write-Verbose -Message "`$CommitStatus:`r`n$($CommitStatus | Out-String)"
                }
                catch {
                    Write-Error -Message $($_.ErrorDetails.Message) -ErrorAction Stop
                }
                Write-Host -Object "Move Completed !"
            }
            else {
                Write-Error -Message "Unable to validate the dependencies before Initiate Move for the resources." -ErrorAction Stop
            }

        }
        else {
            Write-Error -Message "Unable to to Compute, resolve and validate the dependencies of the moveResources in the move collection." -ErrorAction Stop
        }

    }
    else {
        Write-Warning "No Azure VM to move"
    }
    #endregion
}
#endregion 

#region Main Cpode
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#$SourceResourceGroupName = (Get-AzResourceGroup -ResourceGroupName "rg-al-hypv*" | Where-Object { $_.ResourceGroupName -notmatch "744$"}).ResourceGroupName
#Excluding RG already processed for a move (ie. having a duplicate RG with a name ending with -<location>)
$SourceResourceGroupName = (Get-AzResourceGroup -ResourceGroupName "rg-vm-rand-*" | Where-Object -FilterScript { $_.ProvisioningState -eq "Succeeded" } | Select-Object -Property ResourceGroupName, @{Name="Prefix"; Expression = {$_.ResourceGroupName -replace "(rg-.*-\d+)-.*$", '$1'}} | Group-Object -Property Prefix -NoElement | Where-Object -FilterScript { $_.Count -eq 1 } | Get-Random).Name
if ($SourceResourceGroupName) {
    Write-Host -Object "ResourceGroupName: $SourceResourceGroupName"
    Move-AzResource -SourceResourceGroupName $SourceResourceGroupName -TargetAvailabilityZone 3 -Verbose
} else {
    Write-Warning -Message "No Resource Group available"
}
#endregion 