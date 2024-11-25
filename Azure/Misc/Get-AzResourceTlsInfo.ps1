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
#requires -version 5

[CmdletBinding()]
param
(
    [string[]] $ResourceType,
    [string[]] $SubscriptionId
)

Clear-Host
$Error.Clear()

#region Function Definition
function Get-AzResourceTlsInfo {
    [CmdletBinding()]
    param
    (
        [string[]] $ResourceType,
        [string[]] $SubscriptionId
    )

    $RegExPattern = "TLS|SSL"
    if (-not($SubscriptionId)) {
        $SubscriptionId = (Get-AzContext).Subscription.Id
    }
    
    $ResourceTlsInfoBySubscriptionId = @{}
    foreach ($CurrentSubscriptionId in $SubscriptionId) {
        $null = Set-AzContext -SubscriptionId $CurrentSubscriptionId
        $CurrentSubscriptionName = (Get-AzContext).Subscription.Name
        Write-Verbose $("Subscription : {0} ({1})" -f $CurrentSubscriptionName, $CurrentSubscriptionId)

        if ($ResourceType) {
            Write-Verbose "Listing '$ResourceType' Azure Resources with a '$RegExPattern' property name or value ..."
            $AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore | Where-Object { $_.ResourceType -in $ResourceType } | Select-Object -Property ResourceType, Id -ExpandProperty Properties | Where-Object -FilterScript { ($_.psobject.Properties.Name -match $RegExPattern) -or ($_.psobject.Properties.Value -match $RegExPattern) }
        }
        else {
            Write-Verbose "Listing Azure Resources with a '$RegExPattern' property name or value ..."
            $AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore | Select-Object -Property ResourceType, Id -ExpandProperty Properties | Where-Object -FilterScript { ($_.psobject.Properties.Name -match $RegExPattern) -or ($_.psobject.Properties.Value -match $RegExPattern) }
        }

        Write-Verbose "Impacted Azure Resources Grouped By Resource Type:`r`n$($AzResource | Group-Object -Property ResourceType -NoElement | Out-String)"

        $TlsInfo = foreach ($CurrentAzResource in $AzResource) {            
            Write-Verbose "Azure Resource: $($CurrentAzResource.Id) ..."
            $TLSSetting = $CurrentAzResource.psobject.Properties | Where-Object -FilterScript { ($_.Name -match $RegExPattern) -or ($_.Value -match $RegExPattern) }
            Write-Verbose "TLS Settings: '$($TLSSetting -join ', ')' ..."
            $Properties = @{Name = "SubscriptionId"; Expression = { $CurrentSubscriptionId } }, @{Name = "SubscriptionName"; Expression = { $CurrentSubscriptionName } }, "ResourceType", "Id"
            $Properties += $TLSSetting.Name
            $CurrentAzResource | Select-Object -Property $Properties
        }
        $ResourceTlsInfo = $TlsInfo | Group-Object -Property ResourceType -AsHashTable -AsString
        $ResourceTlsInfoBySubscriptionId.Add($CurrentSubscriptionId, $ResourceTlsInfo)
    }
    $ResourceTlsInfoBySubscriptionId
}
#endregion

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Azure Connection
if (-not(Get-AzContext)) {
    Connect-AzAccount
    <#
    Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
    Write-Verbose -Message "Account : $((Get-AzContext).Account)"
    Write-Verbose -Message "Subscription : $((Get-AzContext).Subscription.Name)"
    #>
}
#endregion

#Get TLS Info for all Azure resources in the current subscription (with verbose mode)
$ResourceTlsInfo = Get-AzResourceTlsInfo -Verbose

#Get TLS Info for all Storage Accounts (only) in the current subscription (with verbose mode)
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType "Microsoft.Storage/storageAccounts" -Verbose

#Get TLS Info for specified Azure resources in the specified subscriptions
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType $ResourceType -SubscriptionId $SubscriptionId -Verbose

#Get TLS Info for all Azure resources in all subscriptions (with verbose mode)
#$ResourceTlsInfo = Get-AzResourceTlsInfo -SubscriptionId (Get-AzSubscription).Id -Verbose

#region Data Export
$TimeStamp = Get-Date -Format 'yyyyMMddHHmmss'
foreach ($CurrentSubscriptionId in $ResourceTlsInfo.Keys) {
    $CurrentSubscriptionIdResourceTlsInfo = $ResourceTlsInfo[$CurrentSubscriptionId]

    foreach ($CurrentResourceType in $CurrentSubscriptionIdResourceTlsInfo.Keys) {
        #region CSV Export
        $CurrentSubscriptionIdDir = Join-Path -Path $CurrentDir -ChildPath $CurrentSubscriptionId 
        $CurrentSubscriptionIdTimeStampDir = Join-Path -Path $CurrentSubscriptionIdDir -ChildPath $TimeStamp 
        Write-Verbose -Verbose "`Subscription Directory: $CurrentSubscriptionIdTimeStampDir"
        $null = New-Item -Path $CurrentSubscriptionIdTimeStampDir -ItemType Directory -Force   
        $CurrentCSVFile = Join-Path -Path $CurrentSubscriptionIdTimeStampDir -ChildPath "$("{0}_{1}.csv" -f $($CurrentResourceType -replace "/", "_"), $TimeStamp)"
        Write-Verbose -Verbose "CSV File: $CurrentCSVFile"
        $CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Export-Csv -Path $CurrentCSVFile -NoTypeInformation
        #& $CurrentCSVFile
        #endregion

        #region JSON Export
        $CurrentJSONFile = Join-Path -Path $CurrentSubscriptionIdTimeStampDir -ChildPath "$("{0}_{1}.json" -f $($CurrentResourceType -replace "/", "_"), $TimeStamp)"
        Write-Verbose -Verbose "JSON File: $CurrentJSONFile"
        $CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | ConvertTo-Json | Out-File -FilePath $CurrentJSONFile
        #& $CurrentJSONFile
        #endregion

        $CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Out-GridView -Title $CurrentResourceType
    }
}

#endregion