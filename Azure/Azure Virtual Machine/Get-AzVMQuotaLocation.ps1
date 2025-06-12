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
function Get-AzVMQuotaLocation {
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [ValidateScript({$_ -in $((Get-AzLocation).Location)})]
        [string[]] $Location = $((Get-AzLocation).Location),
        #[ValidateScript({$_ -in $((Get-AzComputeResourceSku | Where-Object { $_.ResourceType -eq "virtualMachines" }).Family)})]
        [string[]] $ResourceName=@("virtualMachines"),
        [ValidateScript({$_ -in $((Get-AzSubscription).Id)})]
        [string[]] $SubscriptionId=(Get-AzSubscription).Id
    )

    $QuotaPerAzLocation = foreach ($CurrentSubscriptionId in $SubscriptionId) {
        Write-Verbose -Message "Processing '$CurrentSubscriptionId' Subscription"
        foreach ($CurrentLocation in $Location) {
            Write-Verbose -Message "Processing '$CurrentLocation' Azure Location"
            foreach ($currentResourceName in $ResourceName) {
                Write-Verbose -Message "Processing '$currentResourceName' Azure Resource"
                try {
                    $Limit = (Get-AzQuota -Scope "/subscriptions/$CurrentSubscriptionId/providers/Microsoft.Compute/locations/$CurrentLocation" -ResourceName $currentResourceName -ErrorAction Stop).Limit.Value
                } catch {
                    Write-Warning "$($_.Exception.Message)"
                    $Limit = $null
                }
                if ([string]::IsNullOrEmpty($Limit)) {
                    $Limit = "N/A"
                    Write-Warning "No data for '$CurrentLocation'"
                }
                [pscustomobject]@{"SubscriptionId"=$CurrentSubscriptionId; "Location"=$CurrentLocation; ResourceName = $currentResourceName; Limit = $Limit} 
            }
        }
    }
    $QuotaPerAzLocation
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

Get-AzVMQuotaLocation -Location francecentral -ResourceName StandardDASv5Family -Verbose
#Get-AzVMQuotaLocation
#Get-AzVMQuotaLocation -Location francecentral, eastus2 -ResourceName StandardDASv5Family, StandardDv5Family -Verbose