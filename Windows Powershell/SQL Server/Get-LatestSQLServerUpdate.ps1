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
#requires -Version 5

#region Function Definition(s)
Function Get-LatestSQLServerUpdate {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [ValidateSet('SQLServer2019', 'SQLServer2022')]
        [Alias('SQLServerVersion')]
        [string[]] $Version = @('SQLServer2019', 'SQLServer2022'),
        [string] $DownloadFolder
    )
    $DataURI = @{
        "SQLServer2019" = "https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/refs/heads/main/support/sql/releases/sqlserver-2019/build-versions.md"
        "SQLServer2022" = "https://raw.githubusercontent.com/MicrosoftDocs/SupportArticles-docs/refs/heads/main/support/sql/releases/sqlserver-2022/build-versions.md"
    }
    $LatestSQLServerUpdate = foreach ($CurrentVersion in $Version) {
        $CurrentDataURI = $DataURI[$CurrentVersion]
        $LatestCUData = $LatestCUData = (Invoke-RestMethod -Uri $CurrentDataURI) -split "`r|`n" | Select-String -Pattern "(?<CU>CU\d+)\s+\(Latest\)(.*)\[(?<KB>KB\d+)\]\((?<Link>.*)\).*\|(?<Date>.*)\|"
        $LatestCU = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'CU' }).Value
        $LatestCUKB = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'KB' }).Value
        $LatestCUKBURI = ($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Link' }).Value
        $LatestCUDate = [datetime]::Parse(($LatestCUData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Date' }).Value)
        $LatestGDRData = (Invoke-RestMethod -Uri $CurrentDataURI) -split "`r|`n" | Select-String -Pattern "\|\s+GDR\s+\|(.*)\[(?<KB>KB\d+)\]\((?<Link>.*)\).*\|(?<Date>.*)\|" | Select-Object -First 1
        $LatestGDRKB = ($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'KB' }).Value
        $LatestGDRKBURI = ($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Link' }).Value
        $LatestGDRDate = [datetime]::Parse(($LatestGDRData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'Date' }).Value)

        $LatestCUKBURI = ($(Split-Path -Path $CurrentDataURI -Parent) + "/" + $LatestCUKBURI) -replace "\\", "/"
        $LatestCUKBURIData = (Invoke-RestMethod -Uri $LatestCUKBURI) -split "`r|`n" | Select-String -Pattern "\((?<LatestCUURI>https://www.microsoft.com/download/details.aspx.*)\)"
        $LatestCUURI = ($LatestCUKBURIData.Matches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'LatestCUURI' }).Value
        $LatestGDRURI = ((Invoke-WebRequest  -Uri $LatestGDRKBURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "Download the package now" }).href

        #Sometimes Invoke-WebRequest returns a WebException
        Do {
            try {
                $LatestCUURI = ($(Invoke-WebRequest -Uri $LatestCUURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
                $Success = $true
            }
            catch {
                $Success = $false
            }
        } While (-not($Success))

        #Sometimes Invoke-WebRequest returns a WebException
        Do {
            try {
                $LatestGDRURI = ($(Invoke-WebRequest -Uri $LatestGDRURI -UseBasicParsing).Links | Where-Object -FilterScript { $_.outerHTML -match "KB.*\.exe" } | Select-Object -Unique).href
            }
            catch {
                $Success = $false
            }
        } While (-not($Success))


        if ($DownloadFolder) {
            [PSCustomObject]@{
                Version = $CurrentVersion
                GDR = [PSCustomObject]@{
                    KB = $LatestGDRKB
                    Date = $LatestGDRDate
                    URI = $LatestGDRURI
                    LocalFile = Join-Path -Path $DownloadFolder -ChildPath $(Split-Path -Path $LatestGDRURI -Leaf)
                }
                CU = [PSCustomObject]@{
                    Number = $LatestCU
                    KB = $LatestCUKB
                    Date = $LatestCUDate
                    URI = $LatestCUURI; 
                    LocalFile = Join-Path -Path $DownloadFolder -ChildPath $(Split-Path -Path $LatestCUURI -Leaf)
                }
            }
        }
        else {
            [PSCustomObject]@{
                Version = $CurrentVersion
                GDR = [PSCustomObject]@{
                    KB = $LatestGDRKB
                    Date = $LatestGDRDate
                    URI = $LatestGDRURI; 
                }
                CU = [PSCustomObject]@{
                    Number = $LatestCU
                    KB = $LatestCUKB
                    Date = $LatestCUDate
                    URI = $LatestCUURI; 
                }
            }
        }
    }
    $LatestSQLServerUpdate

    if ($DownloadFolder) {
        [string[]]$Source = $LatestSQLServerUpdate.CU.URI
        $Source += $LatestSQLServerUpdate.GDR.URI

        [string[]]$Destination = $LatestSQLServerUpdate.CU.LocalFile
        $Destination += $LatestSQLServerUpdate.GDR.LocalFile

        Start-BitsTransfer -Source $Source -Destination $Destination
    }

}
#endregion

#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#Get-LatestSQLServerUpdate -DownloadFolder $CurrentDir -Verbose
$LatestSQLServerUpdate = Get-LatestSQLServerUpdate -DownloadFolder $CurrentDir -Verbose
$LatestSQLServerUpdate | Format-List -Property * -Force
#endregion