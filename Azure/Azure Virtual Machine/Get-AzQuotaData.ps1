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
#requires -Version 5 -Modules Az.Accounts, Az.Compute, Az.Quota, Az.Resources

[CmdletBinding(PositionalBinding = $false)]
Param (
)


#region Function Definitions
function Get-AzVMQuota {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({$_ -in $((Get-AzLocation).Location)})]
        [string[]] $Location = $((Get-AzLocation).Location),
        #[ValidateScript({$_ -in $((Get-AzComputeResourceSku | Where-Object { $_.ResourceType -eq "virtualMachines" }).Family)})]
        [string[]] $ResourceName=@("virtualMachines"),
        [ValidateScript({$_ -in $((Get-AzSubscription).Id)})]
        [string[]] $SubscriptionId=(Get-AzSubscription).Id
    )

    $Quota = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentResourceName in $ResourceName) {
                Write-Verbose -Message "Processing '$CurrentResourceName' Azure Resource"
                $Scope = "/subscriptions/$CurrentSubscriptionId/providers/Microsoft.Compute/locations/$CurrentLocation"
                Write-Verbose -Message "`$Scope: $Scope"
                try {
                    $Limit = (Get-AzQuota -Scope $Scope -ResourceName $CurrentResourceName -ErrorAction Stop).Limit.Value
                    $Usage = (Get-AzQuotaUsage -Scope $Scope -Name $CurrentResourceName -ErrorAction Stop).UsageValue
                } catch {
                    Write-Warning "$($_.Exception.Message)"
                    $Limit = $null
                }
                if ([string]::IsNullOrEmpty($Limit)) {
                    $Limit = "N/A"
                    Write-Warning "No data for '$CurrentLocation'"
                }
                [PSCustomObject]@{"SubscriptionId"=$CurrentSubscriptionId; "Location"=$CurrentLocation; ResourceName = $CurrentResourceName; Limit = $Limit; Usage = $Usage; Available = $Limit-$Usage; PercentFree = $("{0:p2}" -f $(($Limit-$Usage)/$Limit))} 
            }
        }
    }
    $Quota
}

function Get-AzCoreQuota {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({$_ -in $((Get-AzLocation).Location)})]
        [string[]] $Location = $((Get-AzLocation).Location),
        [ValidateScript({$_ -in $((Get-AzSubscription).Id)})]
        [string[]] $SubscriptionId=(Get-AzSubscription).Id
    )

    [string] $ResourceName="cores"
    $Quota = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentResourceName in $ResourceName) {
                Write-Verbose -Message "Processing '$CurrentResourceName' Azure Resource"
                $Scope = "/subscriptions/$CurrentSubscriptionId/providers/Microsoft.Compute/locations/$CurrentLocation"
                Write-Verbose -Message "`$Scope: $Scope"
                try {
                    $Limit = (Get-AzQuota -Scope $Scope -ResourceName $CurrentResourceName -ErrorAction Stop).Limit.Value
                    $Usage = (Get-AzQuotaUsage -Scope $Scope -Name $CurrentResourceName -ErrorAction Stop).UsageValue
                } catch {
                    Write-Warning "$($_.Exception.Message)"
                    $Limit = $null
                }
                if ([string]::IsNullOrEmpty($Limit)) {
                    $Limit = "N/A"
                    Write-Warning "No data for '$CurrentLocation'"
                }
                [PSCustomObject]@{"SubscriptionId"=$CurrentSubscriptionId; "Location"=$CurrentLocation; ResourceName = $CurrentResourceName; Limit = $Limit; Usage = $Usage; Available = $Limit-$Usage; PercentFree = $("{0:p2}" -f $(($Limit-$Usage)/$Limit))} 
            }
        }
    }
    $Quota
}

function Get-AzAvailableComputeResourceSku {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({$_ -in $((Get-AzLocation).Location)})]
        [string[]] $Location = $((Get-AzLocation).Location),
        [ValidateScript({$_ -in $((Get-AzSubscription).Id)})]
        [string[]] $SubscriptionId=(Get-AzSubscription).Id,
		[Parameter(Mandatory = $True)]
        #[ValidateScript({$_ -in $((Get-AzComputeResourceSku -Location $Location).Name)})]
        [Alias("Sku")]
        [string[]] $ComputeResourceSku
    )

    
    $AvailableComputeResourceSku = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($CurrentComputeResourceSku in $ComputeResourceSku) {
                Write-Verbose -Message "`$CurrentComputeResourceSku :$CurrentComputeResourceSku"
                $Family = (Get-AzComputeResourceSku -Location $CurrentLocation | Where-Object -FilterScript { $_.Name -eq $ComputeResourceSku }).Family
                Write-Verbose -Message "`$Family :$Family"
                $vCPUs = ((Get-AzComputeResourceSku -Location $CurrentLocation | Where-Object -FilterScript { $_.Name -eq $ComputeResourceSku }).Capabilities | Where-Object -FilterScript { $_.Name -eq "vCPUs" }).Value
                Write-Verbose -Message "`$vCPUs :$vCPUs"

                $VMQuota = Get-AzVMQuota -Location $CurrentLocation -ResourceName $Family -SubscriptionId $CurrentSubscriptionId
                Write-Verbose -Message "`$VMQuota:`r`n$($VMQuota | Out-String)"
                $CoreQuota = Get-AzCoreQuota -Location $CurrentLocation -SubscriptionId $CurrentSubscriptionId
                Write-Verbose -Message "`$CoreQuota:`r`n$($CoreQuota | Out-String)"
                $AvailablePerVMQuota = $VMQuota.Available
                Write-Verbose -Message "`$AvailablePerVMQuota: $AvailablePerVMQuota"
                $AvailablePerCoreQuota = [math]::Floor($CoreQuota.Available/$vCPUs)
                Write-Verbose -Message "`$AvailablePerCoreQuota: $AvailablePerCoreQuota"
                $Available=[math]::min($AvailablePerVMQuota, $AvailablePerCoreQuota)
                Write-Verbose -Message "`$Available: $Available"
                [PSCustomObject]@{"SubscriptionId"=$CurrentSubscriptionId; "Location"=$CurrentLocation; ComputeResourceSku = $CurrentComputeResourceSku; AvailablePerVMQuota=$AvailablePerVMQuota; AvailablePerCoreQuota=$AvailablePerCoreQuota; Available=$Available} 
            }
        }
    }
    $AvailableComputeResourceSku
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
$ResourceName = "StandardDASv5Family"

#region VM Quota
Get-AzVMQuota -Location $Location -ResourceName $ResourceName -Verbose
#Get-AzVMQuota
#Get-AzVMQuota -Location francecentral, eastus2 -ResourceName StandardDASv5Family, StandardDv5Family -Verbose
#endregion

#region Core Quota
Get-AzCoreQuota -Location $Location -Verbose
#Get-AzCoreQuota
#endregion

#region VM SKU Number Availability
$ComputeResourceSku = "Standard_D8as_v5"
Get-AzAvailableComputeResourceSku -Location $Location -ComputeResourceSku $ComputeResourceSku -Verbose
#endregion
