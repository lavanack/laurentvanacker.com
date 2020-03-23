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
#requires -Version 5 -Modules MsrcSecurityUpdates
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#CSV file for exporting data
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '.csv')

Import-Module -Name MsrcSecurityUpdates

#Setting the API Key for Ms RC
Set-MSRCApiKey -ApiKey "4378e032dc6843d8b92685ad3a42d14f"

function Get-HotfixSupercedence {
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'ID', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        #Validating the specified IDs are later than January 2016
        #The format is "yyyy-MMM" like 2016-Jan except for particular case like 2017-May-B (2 releases)
        [ValidateScript( { (($_ -match "20\d{2}-Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec(-\w)?") -and ([datetime]($_.Substring(0, 8)) -ge [datetime]"2016-Jan")) })]
        #[ValidateScript({ $_ -in $((Get-MsrcSecurityUpdate).ID)})]
        [string[]]$ID
    )
    begin {
    }
    process {
        Write-Verbose "Processing $ID ..."
        #Looping through the specified ID
        $ID | ForEach-Object {
            $CurrentID = $_
            #Getting data for the processed data
            $CVRFDoc = Get-MsrcCvrfDocument -ID $CurrentID
            #Getting the affected products
            $ProductID = $CVRFDoc.ProductTree.FullProductname | Group-Object -Property ProductID -AsHashTable -AsString
            #Getting only data with supercedence
            $CVRFDoc.Vulnerability.Remediations | Where-Object -FilterScript { ($_.SubType) -and ($_.Supercedence) } | Select-Object @{Name = "Month"; Expression = { $CurrentID } }, @{Name = "Description"; Expression = { $_.Description.Value } }, Supercedence, SubType, @{Name = "ProductName"; Expression = { $ProductID[$_.ProductID].Value } } -Unique
        }
    }
    end {
    }
}

#Getting the hotfix supercedence list for January 2019
#Get-HotfixSupercedence -ID '2020-Jan'
#Getting the hotfix supercedence for all updates on Windows Server 2012 R2 later than January 2016
$HotfixSupercedence = Get-MsrcSecurityUpdate -Verbose | Get-HotfixSupercedence -Verbose | Where-Object -FilterScript { "Windows Server 2012 R2" -in $_.ProductName } #| Out-GridView -PassThru
#Exporting data to a CSV file
$HotfixSupercedence | Export-Csv -Path $CSVFile -NoTypeInformation
