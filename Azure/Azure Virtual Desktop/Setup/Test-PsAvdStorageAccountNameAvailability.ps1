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
#requires -Version 5 -Modules Az.Accounts, Az.Resources, Az.Resources

#region Function Definitions
function Write-MyProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Index,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Count,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [string] $Item,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [datetime] $StartTime,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [int] $Id = 1
    )
    Write-Verbose "`$Index: $Index"
    Write-Verbose "`$Count: $Count"
    Write-Verbose "`$Item: $Item"
    Write-Verbose "`$StartTime: $StartTime"
    Write-Verbose "`$Id: $Id"
    $Percent = ($Index / $Count * 100)
    Write-Verbose "`$Percent: $Percent"
    $ElapsedTime = New-TimeSpan -Start $StartTime -End $(Get-Date)
    $ElapsedTimeToString = $ElapsedTime.ToString('hh\:mm\:ss')
    Write-Verbose "`$ElapsedTime: $ElapsedTime"
    try {
        $RemainingTime = New-TimeSpan -Seconds $($ElapsedTime.Seconds / ($Index - 1) * ($Count - $Index + 1))
        $RemainingTimeToString = $RemainingTime.ToString('hh\:mm\:ss')
    }
    catch {
        $RemainingTimeToString = '--:--:--'
    }
    Write-Verbose "`$RemainingTime: $RemainingTime"
    Write-Progress -Id $Id -Activity "[$Index/$Count] Processing '$Item'" -Status "Percent : $('{0:N0}' -f $Percent)% - Elapsed Time: $ElapsedTimeToString - Remaining Time: $RemainingTimeToString" -PercentComplete $Percent
}

function Test-PsAvdStorageAccountNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [ValidateScript({ $_ -in $(Get-AzLocation).Location })]
        [string] $AzureRegion
    )

    $ShareType = "fsl", "apat"
    $HostPoolType = "np", "pd"
    $IdentityProviderType = "ad", "ei"
    $ImageType = "mp", "cg"
    $DigitNumber = 3
    $InstanceNumber = [math]::Pow(10, $DigitNumber) - 1

    $AzLocation = Get-AzLocation | Select-Object -Property Location, DisplayName | Group-Object -Property DisplayName -AsHashTable -AsString
    $ANTResourceLocation = Invoke-RestMethod -Uri https://raw.githubusercontent.com/mspnp/AzureNamingTool/main/src/repository/resourcelocations.json
    $AzLocationShortNameHT = $ANTResourceLocation | Select-Object -Property name, shortName, @{Name = 'Location'; Expression = { $AzLocation[$_.name].Location } } | Where-Object -FilterScript { $_.Location } | Group-Object -Property Location -AsHashTable -AsString

    if ($AzureRegion) {
        Write-Verbose -Message "'$AzureRegion' Azure Region was specified"
        $FilteredAzureRegions = $AzureRegion
    }
    else {
        $FilteredAzureRegions = $AzLocationShortNameHT.Keys
    }

    $StorageAccountNameNumber = $FilteredAzureRegions.Count * $InstanceNumber * $ShareType.Count * $HostPoolType.Count * $IdentityProviderType.Count * $ImageType.Count
    $StorageAccountNameIndex = 0
    $StartTime = Get-Date
    $Result = foreach ($CurrentAzRegion in $FilteredAzureRegions) {
        Write-Verbose -Message "Processing '$CurrentAzRegion' Azure Region"
        foreach ($CurrentShareType in $ShareType) {
            Write-Verbose -Message "Processing '$CurrentShareType' Share Type"
            foreach ($CurrentHostPoolType in $HostPoolType) {
                Write-Verbose -Message "Processing '$HostPoolType' HostPool Type"
                foreach ($CurrentIdentityProviderType in $IdentityProviderType) {
                    Write-Verbose -Message "Processing '$CurrentIdentityProviderType' IdentityProvider Type"
                    foreach ($CurrentImageType in $ImageType) {
                        Write-Verbose -Message "Processing '$CurrentImageType' CurrentImage Type"
                        foreach ($CurrentIndex in 1..$InstanceNumber) {
                            Write-Verbose -Message "Index : $CurrentIndex"
                            $StorageAccountName = "{0}hp{1}{2}poc{3}{4}{5:D$DigitNumber}" -f $CurrentShareType, $CurrentHostPoolType, $CurrentIdentityProviderType, $CurrentImageType, $AzLocationShortNameHT[$CurrentAzRegion].ShortName, $CurrentIndex
                            Write-Verbose -Message "StorageAccountName : $StorageAccountName"
                            $StorageAccountNameIndex++
                            #Write-Progress -Activity "[$($StorageAccountNameIndex)/$StorageAccountNameNumber] Processing '$StorageAccountName'" -Status "Percent : $('{0:N0}' -f $($StorageAccountNameIndex/$StorageAccountNameNumber * 100)) %" -PercentComplete ($StorageAccountNameIndex / $StorageAccountNameNumber * 100)
                            Write-MyProgress -Index $StorageAccountNameIndex -Count $StorageAccountNameNumber -Item $StorageAccountName -StartTime $StartTime #-Verbose
                            try {
                                $NameAvailable = (Get-AzStorageAccountNameAvailability -Name $StorageAccountName -ErrorAction Stop).NameAvailable
                                Write-Verbose -Message "NameAvailable : $NameAvailable"
                                [PSCustomObject]@{StorageAccountName = $StorageAccountName; NameAvailable = $NameAvailable }
                            }
                            catch {   
                                Write-Warning -Message "Exception: $_"
                            }
                        }
                    }
                }
            }
        }
    }
    $Result
    Write-Progress -Activity 'Completed !' -Status 'Completed !' -Completed
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
$CSVFile = $CurrentScript -replace ".ps1$", $("_{0:yyyyMMddHHmmss}.csv" -f (Get-Date))

#region Login to your Azure subscription.
While (-not(Get-AzContext)) {
    Connect-AzAccount
}
#endregion

$Result = Test-PsAvdStorageAccountNameAvailability -AzureRegion eastus2 #-Verbose
#$Result = Test-PsAvdStorageAccountNameAvailability -Verbose
$Result | Export-Csv -Path $CSVFile -NoTypeInformation
& $CSVFile

#endregion