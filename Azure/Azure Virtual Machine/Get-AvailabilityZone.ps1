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
Clear-Host

#region Function Definition
#From https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview?tabs=azure-powershell#physical-and-logical-availability-zones
#This function returns the physical and logical availability zones mapping
function Get-AvailabilityZoneMapping {
    [CmdletBinding()]
    Param (
    )
    $subscriptionId = (Get-AzContext).Subscription.Id
    Write-Verbose -Message "Processing '$subscriptionId' Subscription"
    $response = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$subscriptionId/locations?api-version=2022-12-01"
    $locations = ($response.Content | ConvertFrom-Json).value
    $locations | Where-Object { $null -ne $_.availabilityZoneMappings } | Select-Object -Property Name, DisplayName, @{name = 'availabilityZoneMappings'; expression = { $_.availabilityZoneMappings } } | Sort-Object -Property Name
}

#This function returns the available and non-available availablity zones for an Azure VM Size in an Azure Region
function Get-AvailabilityZone {
    [CmdletBinding()]
    Param (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string[]] $Location = "francecentral",
        [string[]] $SKU
    )
    # Get access token for authentication
    $accessToken = (Get-AzAccessToken).Token
    $subscriptionId = (Get-AzContext).Subscription.Id

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
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }

    $LocationAvailabilityZone = foreach ($CurrentLocation in $Location) {
        # Generate the API endpoint body containing the Azure region and list of subscription Ids to get the information for
        Write-Verbose -Message "Processing '$CurrentLocation'"
        $body = @{
            location        = $CurrentLocation
            subscriptionIds = @("subscriptions/$subscriptionId")
        } | ConvertTo-Json

        # Calling the API endpoint and getting the supported availability zones
        try {
            $apiEndpoint = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Resources/checkZonePeers/?api-version=2022-12-01"
            $response = Invoke-RestMethod -Method Post -Uri $apiEndpoint -Body $body -Headers $headers
            $zones = $response.AvailabilityZonePeers.AvailabilityZone
            [PSCustomObject]@{Location = $CurrentLocation; Zone = $Zones }
            Write-Verbose -Message "The region '$CurrentLocation' supports availability zones: $($zones -join ', ')"
        }
        catch {
            Write-Verbose -Message "The region '$CurrentLocation' doesn't support availability zones!"
            [PSCustomObject] @{
                Location = $CurrentLocation
                Zone     = $null
            }
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
                    "AppliesToSubscriptionID" = $SubId
                    "SubscriptionRestriction" = $LocRestriction
                    "ZoneRestriction"         = $ZoneRestriction
                }
            }
        }
        return $SKUAvailabilityZone
    }
}

#This function returns the less busy Availablity Zone for an Azure VM Size in an Azure Region
function Get-LeastBusyAvailabilityZone {
    [CmdletBinding()]
    Param (
        [ValidateScript({ $_ -in (Get-AzLocation).Location })]
        [string] $Location = "francecentral",
        [string] $SKU
    )
    Write-Verbose -Message "`$Location: $Location"
    Write-Verbose -Message "`$SKU: $SKU"
    #Getting the Availability Zones for a specified SKU for a given Azure Region
    $SKUAvailabilityZone = Get-AvailabilityZone -Location $Location -SKU $SKU

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
    [CmdletBinding()]
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
$SKU = "Standard_D4S_v4"
#$SKU = "Standard_B2S"

<#
$LocationAvailabilityZone = Get-AvailabilityZone -Location $Location, "eastus" -Verbose
$LocationAvailabilityZone

$SKUAvailabilityZone = Get-AvailabilityZone -Location $Location, "eastus" -SKU @("Standard_D4AS_v5", "Standard_D8AS_v5") -Verbose
$SKUAvailabilityZone
#>

#region Getting the Availability Zones for a specified SKU for a given Azure Region
$AvailabilityZoneMapping = Get-AvailabilityZoneMapping
$AvailabilityZoneMapping
$LogicalZone = $AvailabilityZoneMapping | Select-Object -Property Name, @{Name = "LogicalZone"; Expression = { $_.availabilityZoneMappings.logicalZone } }
$LogicalZone
#endregion

#region Getting the Availability Zones for a specified SKU for a given Azure Region
$SKUAvailabilityZone = Get-AvailabilityZone -Location $Location -SKU $SKU -Verbose
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
    $LeastBusyAvailabilityZone = Get-LeastBusyAvailabilityZone -Location $Location -SKU $SKU -Verbose
    $LeastBusyAvailabilityZone
    Write-Progress -Activity "[$VMIndex/$VMNumber] Creating a '$SKU' VM in '$Location' Azure Region in the '$LeastBusyAvailabilityZone' Availability Zone" -Status "Percent : $('{0:N0}' -f $($VMIndex/$VMNumber * 100)) %" -PercentComplete ($VMIndex / $VMNumber * 100)

    .\New-AzVMInAvailabilityZone.ps1 -AvailabilityZone $LeastBusyAvailabilityZone -Location $Location -VMSize $SKU -Verbose
}
Write-Progress -Activity "Completed" -Completed
#endregion 