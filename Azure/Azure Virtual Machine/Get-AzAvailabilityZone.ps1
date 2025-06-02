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
#requires -Version 5 -Modules Az.Accounts

#region Function Definition
#From https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview?tabs=azure-powershell#physical-and-logical-availability-zones
#This function returns the physical and logical availability zones mapping in the current subscription
function Get-AzAvailabilityZoneMapping {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzContext).Subscription.Id
    )

    $AvailabilityZoneMappingHT = @{}
    $PreviousSubscriptionId = (Get-AzContext).Subscription.Id
    Write-Verbose -Message "The Current Subscription is '$PreviousSubscriptionId'"

    foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Switching from '$((Get-AzContext).Subscription.Id)' to '$CurrentSubscriptionId' Subscription ..."
        $null = Get-AzSubscription -SubscriptionId $CurrentSubscriptionId | Select-AzSubscription

        $response = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$CurrentSubscriptionId/locations?api-version=2022-12-01"
        $locations = ($response.Content | ConvertFrom-Json).value
        $AvailabilityZoneMapping = $locations | Where-Object { $null -ne $_.availabilityZoneMappings } | Select-Object -Property @{Name = "SubscriptionId"; Expression = { $CurrentSubscriptionId } }, Name, DisplayName, @{name = 'availabilityZoneMappings'; expression = { $_.availabilityZoneMappings } } | Sort-Object -Property Name
        $AvailabilityZoneMappingHT[$CurrentSubscriptionId] = $AvailabilityZoneMapping
    }

    Write-Verbose -Message "Switching from '$((Get-AzContext).Subscription.Id)' to '$PreviousSubscriptionId' Subscription ..."
    $null = Get-AzSubscription -SubscriptionId $PreviousSubscriptionId | Select-AzSubscription

    #If we proceed only one subscription we directly return the data else the hashtable.
    if ($AvailabilityZoneMappingHT.Count -eq 1) {
        $AvailabilityZoneMappingHT.Values
    }
    else {
        $AvailabilityZoneMappingHT
    }
}

function Get-AzAvailabilityZoneMappingComparison {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in $((Get-AzSubscription).Id) })]
        [string[]] $SubscriptionId = (Get-AzContext).Subscription.Id
    )

    $AvailabilityZoneMapping = Get-AzAvailabilityZoneMapping -SubscriptionId $SubscriptionId
    if ($AvailabilityZoneMapping -is [hashtable]) {
        $AvailabilityZoneMappingComparison = $AvailabilityZoneMapping.Values | ForEach-Object -Process { $_ } | Select-Object -Property SubscriptionId -ExpandProperty availabilityZoneMappings | Sort-Object -Property physicalZone
    }
    else {
        $AvailabilityZoneMappingComparison = $AvailabilityZoneMapping | ForEach-Object -Process { $_ } | Select-Object -Property SubscriptionId -ExpandProperty availabilityZoneMappings | Sort-Object -Property physicalZone
    }
    $AvailabilityZoneMappingComparison
}

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

#This function returns the less busy Availablity Zone for an Azure VM Size in an Azure Region
function Get-AzLeastBusyAvailabilityZone {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "francecentral",
        [string] $SKU
    )
    Write-Verbose -Message "`$Location: $Location"
    Write-Verbose -Message "`$SKU: $SKU"
    #Getting the Availability Zones for a specified SKU for a given Azure Region
    $SKUAvailabilityZone = Get-AzVMSkuAvailabilityZone -Location $Location -SKU $SKU

    #Getting the distribution data per Availability Zone
    $Data = Get-AzVM -Location $Location | Where-Object -FilterScript { $_.HardwareProfile.VmSize -eq $SKU } | Select-Object -Property @{Name = "Zone"; Expression = { if ($_.Zones) {
                $_.Zones
            }
            else {
                "unknown"
            } }
    }  | Group-Object -Property Zone -NoElement
    Write-Verbose -Message "`$Data:`r`n$($Data | Out-String)"

    #All Availability Zones are not used for the moment
    if ($Data.Count -lt $SKUAvailabilityZone.ZoneRestriction.AvailableInZone.Count) {
        #We pick up a non-used Availability Zone
        if ($null -eq $Data) {
            $LeastBusyAvailabilityZone = $SKUAvailabilityZone.ZoneRestriction.AvailableInZone | Get-Random
        }
        else {
            $LeastBusyAvailabilityZone = (Compare-Object -ReferenceObject $Data.Name -DifferenceObject $SKUAvailabilityZone.ZoneRestriction.AvailableInZone).InputObject | Get-Random
        }
    }
    else {
        #Getting the Less Busy Availability Zone
        $LeastBusyAvailabilityZone = ($Data | Sort-Object -Property Count | Select-Object -First 1).Name
    }
    Write-Verbose -Message "The less busy Availability Zone in '$Location' for '$SKU' is: $LeastBusyAvailabilityZone"
    return $LeastBusyAvailabilityZone
}

#This function returns the number of VMs deployed per VM Size, Azure Region and Availablity Zone 
function Get-AzVMNumberPerAvailabilityZone {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
    )
    Get-AzVM | Select-Object -Property Location, @{Name = "VMSize"; Expression = { $_.HardwareProfile.VmSize } }, @{Name = "Zone"; Expression = { if ($_.Zones) {
                $_.Zones
            }
            else {
                "unknown"
            } }
    }  | Group-Object -Property Location, VMSize, Zone -NoElement
}
#endregion

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

$Location = "francecentral" 
$SKU = "Standard_D8as_v5"
#$SKU = "Standard_B2S"

<#
$LocationAvailabilityZone = Get-AzVMSkuAvailabilityZone -Location $Location, "eastus" -Verbose
$LocationAvailabilityZone

$SKUAvailabilityZone = Get-AzVMSkuAvailabilityZone -Location $Location, "eastus" -SKU @("Standard_D4AS_v5", "Standard_D8AS_v5") -Verbose
$SKUAvailabilityZone
#>

#region Getting the Availability Zones Mapping for specified subscription (The Current by default)
$AvailabilityZoneMapping = Get-AzAvailabilityZoneMapping -Verbose
$AvailabilityZoneMapping | Format-Table -Property * -Force
$LogicalZone = $AvailabilityZoneMapping | Select-Object -Property Name, @{Name = "LogicalZone"; Expression = { $_.availabilityZoneMappings.logicalZone } }
$LogicalZone | Format-Table -Property * -Force
#endregion

#region Getting the Availability Zones Mapping for all subscriptions
$AvailabilityZoneMapping = Get-AzAvailabilityZoneMapping -SubscriptionId (Get-AzSubscription).Id -Verbose
$AvailabilityZoneMapping
#Comapring the physical zone mapping across the subscription
$AvailabilityZoneMappingComparison = Get-AzAvailabilityZoneMappingComparison -SubscriptionId (Get-AzSubscription).Id -Verbose
$AvailabilityZoneMappingComparison | Format-Table -Property * -Force
#endregion

#region Getting the Availability Zones for a specified SKU for a given Azure Region
$SKUAvailabilityZone = Get-AzVMSkuAvailabilityZone -Location $Location -SKU $SKU -Verbose
$SKUAvailabilityZone | ConvertTo-Json -Depth 100
$SKUAvailabilityZone.ZoneRestriction.AvailableInZone
#endregion

#region Getting VM Number per Azure Region, SKU and Availability Zone
$AzVMNumberPerAvailabilityZone = Get-AzVMNumberPerAvailabilityZone -Verbose
$AzVMNumberPerAvailabilityZone | Format-List -Property Name, Count -Force
#endregion

#region Generating 10 Azure VM to illustrate the round-robin mechanism we put in place for Availability Zone
$VMNumber = 10
1..$VMNumber | ForEach-Object -Process {
    $VMIndex = $_
    $LeastBusyAvailabilityZone = Get-AzLeastBusyAvailabilityZone -Location $Location -SKU $SKU -Verbose
    Write-Progress -Activity "[$VMIndex/$VMNumber] Creating a '$SKU' VM in '$Location' Azure Region in the '$LeastBusyAvailabilityZone' Availability Zone" -Status "Percent : $('{0:N0}' -f $($VMIndex/$VMNumber * 100)) %" -PercentComplete ($VMIndex / $VMNumber * 100)

    #.\New-AzVMInAvailabilityZone.ps1 -AvailabilityZone $LeastBusyAvailabilityZone -Location $Location -VMSize $SKU -Verbose
    .\New-AzRandomVM -AvailabilityZone $LeastBusyAvailabilityZone -Location $Location -Size $SKU -VMNumber 1 -Verbose
}
Write-Progress -Activity "Completed" -Completed
#endregion 