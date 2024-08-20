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
#This function returns the available and non-available availablity zones for an Azure VM Size in an Azure Region
function Get-AvailabilityZone {
    [CmdletBinding()]
    Param (
        [ValidateScript({$_ -in (Get-AzLocation).Location})]
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
            Write-Verbose -Message"Waiting for AvailabilityZonePeering feature to be registered....waiting 35 seconds"
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
            [PSCustomObject]@{Location=$CurrentLocation; Zone=$Zones}
            Write-Verbose -Message "The region '$CurrentLocation' supports availability zones: $($zones -join ', ')"
        } catch {
            Write-Verbose -Message "The region '$CurrentLocation' doesn't support availability zones!"
            [PSCustomObject] @{
                Location=$CurrentLocation
                Zone=$null
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
                else{
                    "Available - No region restrictions applied"
                }

                $ZoneRestriction = if ($CurrentVMSKURestrictionType.Contains("Zone")) {
                    $NotAvailableInZone = ((($CurrentVMSKU.Restrictions.RestrictionInfo.Zones) | Where-Object -FilterScript { $_ } | Sort-Object))
                    [PSCustomObject] @{
                        NotAvailableInZone = $NotAvailableInZone
                        AvailableInZone = (Compare-Object -ReferenceObject $LocationAvailabilityZoneHT[$CurrentLocation].Zone -DifferenceObject $NotAvailableInZone).InputObject
                    }
                }
                else {
                    [PSCustomObject] @{
                        NotAvailableInZone = $null
                        AvailableInZone = $CurrentVMSKU.LocationInfo.Zones
                    }
                }
                [PSCustomObject] @{
                    "Name" = $SkuName
                    "Location" = $CurrentLocation
                    "AppliesToSubscriptionID" = $SubId
                    "SubscriptionRestriction" = $LocRestriction
                    "ZoneRestriction" = $ZoneRestriction
                }
            }
        }
        return $SKUAvailabilityZone
    }
}

#This function returns the less busy Availablity Zone for an Azure VM Size in an Azure Region
function Get-LessBusyAvailabilityZone {
    [CmdletBinding()]
    Param (
        [ValidateScript({$_ -in (Get-AzLocation).Location})]
        [string] $Location = "francecentral",
        [string] $SKU
    )
    Write-Verbose -Message "`$Location: $Location"
    Write-Verbose -Message "`$SKU: $SKU"
    $SKUAvailabilityZone = Get-AvailabilityZone -Location $Location -SKU $SKU

    $Data = Get-AzVM -Location $Location | Where-Object -FilterScript {$_.HardwareProfile.VmSize -eq $SKU} | Select-Object -Property @{Name="Zone"; Expression={if ($_.Zones) {$_.Zones} else {"unknown"}}}  | Group-Object -Property Zone -NoElement
    Write-Verbose -Message "`$Data:`r`n$($Data | Out-String)"

    #All Availability Zones are not used for the moment
    if ($Data.Count -lt $SKUAvailabilityZone.ZoneRestriction.AvailableInZone.Count) {
        #We pick up a non-used Availability Zone
        if ($null -eq $Data) {
            $LessBusyAvailabilityZone = $SKUAvailabilityZone.ZoneRestriction.AvailableInZone | Get-Random
        }
        else
        {
            $LessBusyAvailabilityZone = (Compare-Object -ReferenceObject $Data.Name -DifferenceObject $SKUAvailabilityZone.ZoneRestriction.AvailableInZone).InputObject | Get-Random
        }
    }
    else {
        $LessBusyAvailabilityZone = ($Data | Sort-Object -Property Count | Select-Object -First 1).Name
    }
    Write-Verbose -Message "The less busy Availability Zone in '$Location' for '$SKU' is: $LessBusyAvailabilityZone"
    return $LessBusyAvailabilityZone
}

#This function returns the number of VMs deployed per VM Size, Azure Region and Availablity Zone 
function Get-AzVMNumberPerAvailabilityZone {
    [CmdletBinding()]
    Param (
    )
    Get-AzVM | Select-Object -Property Location, @{Name="VMSize"; Expression={$_.HardwareProfile.VmSize}}, @{Name="Zone"; Expression={if ($_.Zones) {$_.Zones} else {"unknown"}}}  | Group-Object -Property Location, VMSize, Zone -NoElement
}
#endregion

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$Location = "francecentral" 
$SKU = "Standard_D4S_v4"
#$SKU = "Standard_B2S"

<#
$LocationAvailabilityZone = Get-AvailabilityZone -Location $Location, "eastus" -Verbose
$LocationAvailabilityZone

$SKUAvailabilityZone = Get-AvailabilityZone -Location $Location, "eastus" -SKU @("Standard_D4AS_v5", "Standard_D8AS_v5") -Verbose
$SKUAvailabilityZone
#>

$SKUAvailabilityZone = Get-AvailabilityZone -Location $Location -SKU $SKU -Verbose
$SKUAvailabilityZone | ConvertTo-Json -Depth 100
$SKUAvailabilityZone.ZoneRestriction.AvailableInZone

$AzVMNumberPerAvailabilityZone = Get-AzVMNumberPerAvailabilityZone -Verbose
$AzVMNumberPerAvailabilityZone | Format-List -Property Name, Count -Force

$VMNumber = 10
1..$VMNumber | ForEach-Object -Process {
    $VMIndex = $_
    $LessBusyAvailabilityZone = Get-LessBusyAvailabilityZone -Location $Location -SKU $SKU -Verbose
    $LessBusyAvailabilityZone
    Write-Progress -Activity "[$VMIndex/$VMNumber] Creating a '$SKU' VM in '$Location' Azure Region in the '$LessBusyAvailabilityZone' Availability Zone" -Status "Percent : $('{0:N0}' -f $($VMIndex/$VMNumber * 100)) %" -PercentComplete ($VMIndex / $VMNumber * 100)

    .\New-AzVMInAvailabilityZone.ps1 -AvailabilityZone $LessBusyAvailabilityZone -Location $Location -VMSize $SKU -Verbose
}
Write-Progress -Activity "Completed" -Completed