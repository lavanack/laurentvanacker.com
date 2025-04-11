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
#requires -Version 7 -PSEdition Core -Modules Az.Accounts, Az.Resources, Az.Resources

#region Function Definitions
function Test-PsAvdStorageAccountNameAvailability {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [ValidateScript({ $_ -in $(Get-AzLocation).Location })]
        [string] $AzureRegion
    )

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
    
    $ShareType = "fsl", "apat"
    $HostPoolType = "np", "pd"
    $IdentityProviderType = "ad", "ei"
    $ImageType = "mp", "cg"
    $DigitNumber = 3
    $InstanceNumber = [math]::Pow(10, $DigitNumber) - 1

    $Result = $FilteredAzureRegions | ForEach-Object -Parallel {
        $CurrentAzRegion = $_
        Write-Verbose -Message "Processing '$CurrentAzRegion' Azure Region"

        $InstanceNumber = $using:InstanceNumber
        $AzLocationShortNameHT = $using:AzLocationShortNameHT
        $ShareType = $using:ShareType
        $HostPoolType = $using:HostPoolType
        $IdentityProviderType = $using:IdentityProviderType
        $ImageType = $using:ImageType

        $ShareType | ForEach-Object -Parallel { 
            $CurrentShareType = $_
            Write-Verbose -Message "Processing '$CurrentShareType' Share Type"
            $CurrentAzRegion = $using:CurrentAzRegion

            $InstanceNumber = $using:InstanceNumber
            $AzLocationShortNameHT = $using:AzLocationShortNameHT
            $HostPoolType = $using:HostPoolType
            $IdentityProviderType = $using:IdentityProviderType
            $ImageType = $using:ImageType

            $HostPoolType | ForEach-Object -Parallel { 
                $CurrentHostPoolType = $_ 
                Write-Verbose -Message "Processing '$CurrentHostPoolType' HostPool Type"
                $CurrentShareType = $using:CurrentShareType
                $CurrentAzRegion = $using:CurrentAzRegion

                $InstanceNumber = $using:InstanceNumber
                $AzLocationShortNameHT = $using:AzLocationShortNameHT
                $IdentityProviderType = $using:IdentityProviderType
                $ImageType = $using:ImageType

                $IdentityProviderType | ForEach-Object -Parallel { 
                    $CurrentIdentityProviderType = $_ 
                    Write-Verbose -Message "Processing '$CurrentIdentityProviderType' IdentityProvider Type"
                    $CurrentHostPoolType = $using:CurrentHostPoolType
                    $CurrentShareType = $using:CurrentShareType
                    $CurrentAzRegion = $using:CurrentAzRegion

                    $InstanceNumber = $using:InstanceNumber
                    $AzLocationShortNameHT = $using:AzLocationShortNameHT
                    $ImageType = $using:ImageType

                    $ImageType | ForEach-Object -Parallel { 
                        $CurrentImageType = $_
                        Write-Verbose -Message "Processing '$CurrentImageType' Image Type"
                        
                        $CurrentIdentityProviderType = $using:CurrentIdentityProviderType 
                        $CurrentAzRegion = $using:CurrentAzRegion
                        $CurrentShareType = $using:CurrentShareType
                        $CurrentHostPoolType = $using:CurrentHostPoolType

                        $InstanceNumber = $using:InstanceNumber
                        $AzLocationShortNameHT = $using:AzLocationShortNameHT

                        Write-Verbose -Message "Processing '$CurrentImageType' CurrentImage Type"
                        1..$InstanceNumber | ForEach-Object -Parallel {
                            $CurrentIndex = $_
                            Write-Verbose -Message "Index : $CurrentIndex"

                            $CurrentImageType = $using:CurrentImageType
                            $CurrentIdentityProviderType = $using:CurrentIdentityProviderType 
                            $CurrentAzRegion = $using:CurrentAzRegion
                            $CurrentShareType = $using:CurrentShareType
                            $CurrentHostPoolType = $using:CurrentHostPoolType

                            $InstanceNumber = $using:InstanceNumber
                            $AzLocationShortNameHT = $using:AzLocationShortNameHT
                            $StorageAccountName = "{0}hp{1}{2}poc{3}{4}{5:D$DigitNumber}" -f $CurrentShareType, $CurrentHostPoolType, $CurrentIdentityProviderType, $CurrentImageType, $AzLocationShortNameHT[$CurrentAzRegion].ShortName, $CurrentIndex
                            Write-Verbose -Message "StorageAccountName : $StorageAccountName"
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