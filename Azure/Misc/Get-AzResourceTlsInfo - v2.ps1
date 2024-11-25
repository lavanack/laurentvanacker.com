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
function Get-TLSSetting {
    [CmdletBinding()]
    param (
        [object] $Properties,
        [string] $ParentProperty = "",
        [string] $RegExPattern = "TLS|SSL",
        [ValidateSet('Name', 'Value', 'All')]
        [string] $Scope = "All"
    )

    foreach ($Property in $Properties.psobject.Properties.GetEnumerator()) {
        if ([string]::IsNullOrEmpty($ParentProperty)) {
            $Path = $Property.Name
        }
        else {
            $Path = "{0}.{1}" -f $ParentProperty, $Property.Name
        }
        Write-Verbose -Message $("Path: '{0}'" -f $Path)
        
        if ($Property.TypeNameOfValue -eq "System.string") {
            Write-Verbose -Message $("Type: String")
            Write-Verbose -Message $("Scope: $Scope")
            if ($Scope -eq 'Name') {
                $TLSSetting = $Property | Where-Object -FilterScript { ($_.Name -match $RegExPattern) }
            }
            elseif ($Scope -eq 'Value') {
                $TLSSetting = $Property | Where-Object -FilterScript { ($_.Value -match $RegExPattern) }
            }
            else {
                $TLSSetting = $Property | Where-Object -FilterScript { ($_.Name -match $RegExPattern) -or ($_.Value -match $RegExPattern) }
            }
            if ($TLSSetting) {
                Write-Verbose -Message $("Processing '{0}'" -f $Path)
                [PSCustomObject] @{Property= $Path;Value=$TLSSetting.value}
            }
            else {
                Write-Verbose -Message $("Skipping '{0}'" -f $Path)
            }
        }
        elseif ($Property.TypeNameOfValue -eq "System.Management.Automation.PSCustomObject") {
            Write-Verbose -Message $("Type: PSCustomObject")
            Get-TLSSetting -Properties $Property.Value -ParentProperty $Path -RegExPattern $RegExPattern -Scope $Scope
        }
        elseif ($Property.TypeNameOfValue -eq "System.Object[]") {
            Write-Verbose -Message $("Type: System.Object[]")
            foreach ($CurrentItem in $Property.value) {
                Write-Verbose -Message $("`$CurrentItem: $CurrentItem")
                if (($CurrentItem -is [string]) -and ($CurrentItem  -match $RegExPattern)) {
                    [PSCustomObject] @{Property= $Path;Value=$CurrentItem}
                }
                else {
                    Get-TLSSetting -Properties $CurrentItem -ParentProperty $Path -RegExPattern $RegExPattern -Scope:$Scope
                }
            }
        }
        else {
            Write-Verbose -Message $("Skipping '[{0}]{1}'" -f $Property.TypeNameOfValue, $Property.Name)
        }
    }
}

function Get-AzResourceTlsInfo {
    [CmdletBinding()]
    param
    (
        [string[]] $ResourceType,
        [string[]] $SubscriptionId,
        [string] $RegExPattern = "TLS|SSL",
        [ValidateSet('Name', 'Value', 'All')]
        [string] $Scope = "All"
    )

    if (-not($SubscriptionId)) {
        $SubscriptionId = (Get-AzContext).Subscription.Id
    }
    
    $ResourceTlsInfoBySubscriptionId = @{}
    foreach ($CurrentSubscriptionId in $SubscriptionId) {
        # Ensures you do not inherit an AzContext
        $null = Disable-AzContextAutosave -Scope Process
        $null = Set-AzContext -SubscriptionId $CurrentSubscriptionId
        $CurrentSubscriptionName = (Get-AzContext).Subscription.Name
        Write-Verbose $("Subscription : {0} ({1})" -f $CurrentSubscriptionName, $CurrentSubscriptionId)

        if ($ResourceType) {
            #$AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore | Where-Object { $_.ResourceType -in $ResourceType }
            #Faster than the line above
            <#
                #Try by yourself to compare ;)
                $ResourceType = "Microsoft.Storage/storageAccounts","Microsoft.Network/applicationGateways", "Microsoft.Automation/automationAccounts", "Microsoft.Compute/virtualMachines/extensions"
                Measure-Command -Expression { Get-AzResource -ExpandProperties -ErrorAction Ignore | Where-Object { $_.ResourceType -in $ResourceType }}
                Measure-Command -Expression { foreach ($CurrentResourceType in $ResourceType) { Get-AzResource -ResourceType $CurrentResourceType -ExpandProperties -ErrorAction Ignore } }
            #>
            $AzResource = foreach ($CurrentResourceType in $ResourceType) { 
                Write-Verbose "Listing '$CurrentResourceType' Azure Resources ..."
                Get-AzResource -ResourceType $CurrentResourceType -ExpandProperties -ErrorAction Ignore
            } 
        }
        else {
            Write-Verbose "Listing Azure Resources ..."
            $AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore 
        }

        Write-Verbose "Impacted Azure Resources Grouped By Resource Type:`r`n$($AzResource | Group-Object -Property ResourceType -NoElement | Out-String)"

        $TlsInfo = foreach ($CurrentAzResource in $AzResource) {            
            Write-Verbose "Azure Resource: $($CurrentAzResource.Id) ..."
            $TLSSetting = Get-TLSSetting -Properties $CurrentAzResource.Properties -RegExPattern $RegExPattern -Scope:$Scope #-Verbose
            if (-not([string]::IsNullOrEmpty($TLSSetting))) {
                Write-Verbose "TLS Settings:`r`n$($TLSSetting | Out-String)"
                [PSCustomObject]@{SubscriptionId = $CurrentSubscriptionId; SubscriptionName = $CurrentSubscriptionName; ResourceType = $CurrentAzResource.ResourceType; ResourceId = $CurrentAzResource.ResourceId; TLSSetting = $TLSSetting }
            }
            else {
                Write-Verbose $("No TLS Settings found for {0}" -f $CurrentAzResource.ResourceId)
            }
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



#Get TLS Info for all Azure resources in the current subscription where the property name match the specified regular expression pattern (with verbose mode)
#$RegExPattern = "minimumTlsVersion"
#$ResourceTlsInfo = Get-AzResourceTlsInfo -RegExPattern $RegExPattern -Scope Name -Verbose

#Get TLS Info for all Storage Accounts (only) in the current subscription (with verbose mode). The default regular expression pattern ("TLS|SSL") will be used and applied to the property names and values
#$RegExPattern = "TLS|SSL"
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType "Microsoft.Storage/storageAccounts" -Verbose

#Get TLS Info for all Storage Accounts (only) in the current subscription (with verbose mode) where the property value match the specified regular expression pattern (with verbose mode)
#$RegExPattern = "TLS1_0"
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType "Microsoft.Storage/storageAccounts" -RegExPattern $RegExPattern -Scope Value -Verbose

#Get TLS Info for Azure resources in the current subscription (with verbose mode) where the property value match the specified regular expression pattern (with verbose mode)
$RegExPattern = "TLS1_0"
$ResourceTlsInfo = Get-AzResourceTlsInfo -RegExPattern $RegExPattern -Scope Value -Verbose

#Get TLS Info for all Storage Accounts and Application Gateways in the current subscription (with verbose mode). The default regular expression pattern ("TLS|SSL") will be used and applied to the property names and values
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType "Microsoft.Storage/storageAccounts","Microsoft.Network/applicationGateways" -Verbose

#Get TLS Info for specified Azure resources in the specified subscriptions. The default regular expression pattern ("TLS|SSL") will be used and applied to the property names and values
#$ResourceTlsInfo = Get-AzResourceTlsInfo -ResourceType $ResourceType -SubscriptionId $SubscriptionId -Verbose

#Get TLS Info for all Azure resources in all subscriptions (with verbose mode). The default regular expression pattern ("TLS|SSL") will be used and applied to the property names and values
#$ResourceTlsInfo = Get-AzResourceTlsInfo -SubscriptionId (Get-AzSubscription).Id -Verbose

#region Data Export
$TimeStamp = Get-Date -Format 'yyyyMMddHHmmss'
foreach ($CurrentSubscriptionId in $ResourceTlsInfo.Keys) {
    $CurrentSubscriptionIdResourceTlsInfo = $ResourceTlsInfo[$CurrentSubscriptionId]

    foreach ($CurrentResourceType in $CurrentSubscriptionIdResourceTlsInfo.Keys) {
        #region CSV Export
        $CurrentSubscriptionIdDir = Join-Path -Path $CurrentDir -ChildPath $CurrentSubscriptionId 
        $CurrentSubscriptionIdTimeStampDir = Join-Path -Path $CurrentSubscriptionIdDir -ChildPath $TimeStamp 
        Write-Verbose "`Subscription Directory: $CurrentSubscriptionIdTimeStampDir"
        $null = New-Item -Path $CurrentSubscriptionIdTimeStampDir -ItemType Directory -Force   
        $CurrentCSVFile = Join-Path -Path $CurrentSubscriptionIdTimeStampDir -ChildPath "$("{0}_{1}.csv" -f $($CurrentResourceType -replace "/", "_"), $TimeStamp)"
        Write-Verbose "CSV File: $CurrentCSVFile"
        #$CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Select-Object -ExcludeProperty TLSSetting -Property *, @{Name="TLSSetting"; Expression = {"{0}={1}" -f $($_.TLSSetting.Property), $($_.TLSSetting.Value) }} | Export-Csv -Path $CurrentCSVFile -NoTypeInformation
        #$CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Select-Object -ExcludeProperty TLSSetting -Property *, @{Name="TLSSetting"; Expression = {$_.TLSSetting | Out-String }} | Export-Csv -Path $CurrentCSVFile -NoTypeInformation
        $CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Select-Object -ExcludeProperty TLSSetting -Property *, @{Name="TLSSetting"; Expression = { $(foreach ($CurrentTLSSetting in $_.TLSSetting) { "{0}={1}" -f $($CurrentTLSSetting.Property), $($CurrentTLSSetting.Value) }) -join '|' }} | Export-Csv -Path $CurrentCSVFile -NoTypeInformation
        #& $CurrentCSVFile
        #endregion

        #region JSON Export
        $CurrentJSONFile = Join-Path -Path $CurrentSubscriptionIdTimeStampDir -ChildPath "$("{0}_{1}.json" -f $($CurrentResourceType -replace "/", "_"), $TimeStamp)"
        Write-Verbose "JSON File: $CurrentJSONFile"
        $CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | ConvertTo-Json -Depth 100 | Out-File -FilePath $CurrentJSONFile
        #& $CurrentJSONFile
        #endregion

        #$CurrentSubscriptionIdResourceTlsInfo[$CurrentResourceType] | Out-GridView -Title $CurrentResourceType
        Start-Process -FilePath $CurrentSubscriptionIdTimeStampDir
    }
}

#endregion
