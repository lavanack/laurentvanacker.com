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
$HotfixSupercedenceChainCSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '.csv')
$HotfixSupercedenceChainJSONFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '.json')
$HotfixCSVFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfix.csv"

Import-module -Name MsrcSecurityUpdates
Set-MSRCApiKey -ApiKey "4378e032dc6843d8b92685ad3a42d14f"

function Get-MsrcHotfix {
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
            $MaximumSeverityRatingHT = $CVRFDoc | Get-MsrcCvrfCVESummary | Select CVE, @{Name = "MaximumSeverityRating"; Expression={$_."Maximum Severity Rating"}} | Group-Object -Property CVE -AsHashTable -AsString
            #Getting only data with supercedence
            $CVRFDoc.Vulnerability | Select-Object -Property CVE -ExpandProperty Remediations | Where-Object -FilterScript { ($_.SubType) }| Select-Object @{Name = "Month"; Expression = { $CurrentID } }, @{Name = "Description"; Expression = { $_.Description.Value } }, Supercedence, SubType, @{Name = "ProductName"; Expression = { $ProductID[$_.ProductID].Value } }, CVE, @{Name = "MaximumSeverityRating"; Expression = { $MaximumSeverityRatingHT[$_.CVE].MaximumSeverityRating } } -Unique
        }
    }
    end {
    }
}

function Get-MsrcHotfixSupercedence {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Hotfix
    )
    begin {
    }
    process {
        $Hotfix | ForEach-Object -Process {
            $CurrentHotfix = $_
            $CurrentHotfix.Supercedence -split ',|;' | ForEach-Object -Process {
                $CurrentHotfixSupercedence = $_.Trim()
                #We skip Microsoft Security Bulletin MSYY-XXX because the related KBID is the item after the comma
                if ($CurrentHotfixSupercedence -notmatch "^MS")
                {
                    $CurrentHotfix | Select-Object -ExcludeProperty Supercedence -Property *,@{Name="Supercedence"; Expression={$CurrentHotfixSupercedence}} 
                }
            }
        }
    }
    end {
    }
}

Function Get-MsrcHotfixSupercedenceChain {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotfixSupercedence
    )
    $FilteredHotfixSupercedence = $HotfixSupercedence | Sort-Object -Property Description -Descending | Select-Object -Property Description, Supercedence -Unique | Where-Object -FilterScript { (($_.Description -in $HotfixSupercedence.Supercedence) -or ($_.Supercedence -in $HotfixSupercedence.Description)) -and ($_.Supercedence)}

    $HotfixSupercedenceChainHT = @{}
    $FilteredHotfixSupercedence | Sort-Object -Property Description | ForEach-Object -Process {
        if ($HotfixSupercedenceChainHT[$_.Description])
        {
            Write-Verbose "Adding $($_.Description): $($_.Supercedence)"
            $HotfixSupercedenceChainHT[$_.Description] += $_.Supercedence
        }
        else
        {
            Write-Verbose "Setting $($_.Description): $($_.Supercedence)"
            $HotfixSupercedenceChainHT.Add($_.Description, @($_.Supercedence))
        }
        $Supercedence = $HotfixSupercedenceChainHT[$_.Supercedence]
        if ($Supercedence)
        {
            $HotfixSupercedenceChainHT[$_.Description] += $Supercedence
        }
    }

    $HotfixSupercedenceChain = $HotfixSupercedence | Select-Object -Property Month, Description, Supercedence, SubType, ProductName, @{Name="Supercedences"; Expression={ $null }} -Unique | Add-Member -MemberType ScriptProperty -Name SupercedenceCount -Value {$This.Supercedences.Length} -PassThru
    $HotfixSupercedenceChain | ForEach-Object -Process {
        $CurrentHotfix = $_
        if ($HotfixSupercedenceChainHT[$CurrentHotfix.Description])
        {
            $CurrentHotfix.Supercedences += $HotfixSupercedenceChainHT[$CurrentHotfix.Description]
        }
        if (-not($CurrentHotfix.Supercedences) -and ($CurrentHotfix.Supercedence))
        {
            $CurrentHotfix.Supercedences = @($CurrentHotfix.Supercedence)
        }
    }
    return $HotfixSupercedenceChain
}

#Getting all updates on Windows Server 2012 R2 later than January 2016
#$Hotfix = Get-MsrcSecurityUpdate -Verbose | Sort-Object -Property InitialReleaseDate | Where-Object -FilterScript { $_.ID -ne '2017-May-B'} | Get-MsrcHotfix -Verbose | Where-Object -FilterScript { "Windows Server 2012 R2" -in $_.ProductName } #| Out-GridView -PassThru
#$Hotfix | Export-Csv -Path $HotfixCSVFile -NoTypeInformation
$Hotfix = Import-Csv -Path $HotfixCSVFile

#Getting the hotfix supercedence for all updates on Windows Server 2012 R2 later than January 2016
$HotfixSupercedence = Get-MsrcHotfixSupercedence -Hotfix $Hotfix -Verbose
$HotfixSupercedenceChain = Get-MsrcHotfixSupercedenceChain -HotfixSupercedence $HotfixSupercedence -Verbose

$HotfixSupercedenceChain | Export-Csv -Path $HotfixSupercedenceChainCSVFile -NoTypeInformation
#For line below cf. https://stackoverflow.com/questions/20848507/why-does-powershell-give-different-result-in-one-liner-than-two-liner-when-conve/38212718#38212718
Remove-TypeData System.Array -ErrorAction Ignore
$HotfixSupercedenceChain | ConvertTo-Json | Set-Content -Path $HotfixSupercedenceChainJSONFile

#$HotfixSupercedenceChain = Get-content -Path $HotfixSupercedenceChainJSONFile | ConvertFrom-Json

