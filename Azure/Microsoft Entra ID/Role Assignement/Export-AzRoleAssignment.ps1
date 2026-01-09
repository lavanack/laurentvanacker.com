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

#region Function Definitions
function Export-AzRoleAssignment {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphGroup[]]$AzADGroup,
        #To Open Excel (or the default action for CSV files)  after generating the CSV File
        [switch]$Open
    )
    begin {
        $TimeStamp = "{0:yyyyMMddHHmmss}" -f $(Get-Date)
        $CurrentSubScription = (Get-Azcontext).SubScription
        Write-Host -Object "Original Subscription '$($CurrentSubScription.Name) ..." -ForegroundColor ([System.ConsoleColor]::Green)
    }
    process {
        foreach ($CurrentAzADGroup in $AzADGroup) {
            Write-Host -Object "Processing '$($CurrentAzADGroup.DisplayName)' ..."
            #Going through all subscriptions
            foreach ($Subscription in Get-AzSubscription) {
                #Creating a timestamped CSV File per Subscription for exporting data
                $CSVFile = Join-Path -Path $CurrentDir -ChildPath $("{0} - Role Assignment Export - {1} - {2}.csv" -f $Timestamp, $Subscription.Name, $CurrentAzADGroup.DisplayName)
                Write-Host -Object "Switching to '$($Subscription.Name) ..."
                $null = Select-AzSubscription -Subscription $Subscription
                $RoleAssignment = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.Id)" -ObjectId $CurrentAzADGroup.Id
                $RoleAssignment | Export-Csv -Path $CSVFile -NoTypeInformation
                Write-Host -Object "Exporting Data to '$CSVFile' ..."
                if ($Open) {
                    & $CSVFile
                }
            }
        }
    }
    end {
        Write-Host -Object "Switching Back to the Original Subscription '$($CurrentSubScription.Name) ..." -ForegroundColor ([System.ConsoleColor]::Green)
        #Switching back to the original Subscription
        $CurrentSubScription | Select-AzSubscription 
    }

}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
#Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription

<#
$DisplayName = "AVD Users"
$AzADGroup = Get-AzADGroup -DisplayName $DisplayName
#>
$AzADGroup = Get-AzADGroup -SearchString "AVD"
$AzADGroup | Export-AzRoleAssignment -Verbose #-Open
#endregion
