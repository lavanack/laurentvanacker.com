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
[CmdletBinding()]
param
(
    [string[]] $ResourceType
)

Clear-Host
$Error.Clear()

#region Function Definition
function Get-AzResourceMinimumTlsVersion {
    [CmdletBinding()]
    param
    (
        [string[]] $ResourceType
    )
    if ($ResourceType) {
        $AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore | Where-Object { $_.ResourceType -in $ResourceType } | Select-Object -Property Id -ExpandProperty Properties
    }
    else {
        $AzResource = Get-AzResource -ExpandProperties -ErrorAction Ignore | Select-Object -Property Id -ExpandProperty Properties
    }

    foreach ($CurrentAzResource in $AzResource) {
        Write-Verbose "Processing '$($CurrentAzResource.Id)' ..."
        $TLSSetting = $CurrentAzResource.psobject.Properties | Where-Object -FilterScript { $_.Name -match "TLS" }
        if ($TLSSetting) {
            $CurrentAzResource | Select-Object -Property Id, $TLSSetting.Name
        }
    }
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

$ResourceMinimumTlsVersion = Get-AzResourceMinimumTlsVersion -ResourceType $ResourceType #-Verbose
#$ResourceMinimumTlsVersion = Get-AzResourceMinimumTlsVersion -ResourceType "Microsoft.Storage/storageAccounts" -Verbose
$ResourceMinimumTlsVersion | Format-List -Property * -Force