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
$HotfixCSVFile = Join-Path -Path $CurrentDir -ChildPath "MsrcHotfix.csv"
$HotfixJSONFile = Join-Path -Path $CurrentDir -ChildPath "MsrcHotfix.json"

$HotfixInheritanceCSVFile = Join-Path -Path $CurrentDir -ChildPath "MsrcHotfixInheritance.csv"
$HotfixInheritanceJSONFile = Join-Path -Path $CurrentDir -ChildPath "MsrcHotfixInheritance.json"

#For getting a API Key: https://microsoft.github.io/MSRC-Microsoft-Security-Updates-API/
$MSRCApiKey = "4378e032dc6843d8b92685ad3a42d14f"

Import-Module -Name MsrcSecurityUpdates
Set-MSRCApiKey -ApiKey $MSRCApiKey

function Get-MsrcHotfix {
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = 'ID', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        #Validating the specified IDs are later than April 2016
        #The format is "yyyy-MMM" like 2016-Jan except for particular case like 2017-May-B (2 releases)
        [ValidateScript( { (($_ -match "20\d{2}-Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec(-\w)?") -and ([datetime]($_.Substring(0, 8)) -ge [datetime]"2016-Jan")) })]
        #[ValidateScript({ $_ -in $((Get-MsrcSecurityUpdate).ID)})]
        [string[]]$ID
    )
    begin {
    }
    process {
        #Looping through the specified ID
        $ID | ForEach-Object {
            $CurrentID = $_

            $CVRFDoc = Get-MsrcCvrfDocument -ID $CurrentID
            #Getting the affected products
            $ProductID = $CVRFDoc.ProductTree.FullProductname | Group-Object -Property ProductID -AsHashTable -AsString
            #Getting affected softwares
            $AffectedSoftware = $CVRFDoc | Get-MsrcCvrfAffectedSoftware

            #Getting the maximum severity rating per CVE
            $MaximumSeverityRatingHT = $CVRFDoc | Get-MsrcCvrfCVESummary | Select-Object CVE, @{Name = "MaximumSeverityRating"; Expression = { $_."Maximum Severity Rating" } } | Group-Object -Property CVE -AsHashTable -AsString

            #Getting only data with supercedence
            $CVRFDoc.Vulnerability | ForEach-Object {
                $CurrentVulnerability = $_
                $CVE = $CurrentVulnerability.CVE
                $Title = $CurrentVulnerability.CVE
                $MostRecentRevisionDate = [datetime]($_.RevisionHistory | Sort-Object -Property Date -Descending | Select-Object -First 1).Date
                $Remediations = $CurrentVulnerability.Remediations | Where-Object -FilterScript { ($_.SubType) } | Select-Object -Property *
                $Month=$CurrentID
                $Remediations | ForEach-Object {
                    $CurrentRemediation = $_
                    Write-Verbose -Message "`$CurrentRemediation : $CurrentRemediation"
                    $KBID = $CurrentRemediation.Description.Value
                    $CurrentAffectedSoftware = $AffectedSoftware | Where-Object -FilterScript {$_.KBArticle.ID -eq $KBID }
                    $CurrentSupercedence = $CurrentAffectedSoftware.Supercedence | Where-Object -FilterScript { $_ } | Select-Object -Unique
                    Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] `$CurrentSupercedence : $CurrentSupercedence ..."
                    if ($KBID -match "\d+")
                    {
                        $CurrentHotfix = [PSCustomObject]@{
                            Month = $Month
                            Date = $MostRecentRevisionDate
                            KBID = $KBID
                                Supercedence = [array] $CurrentSupercedence -split ',|;|<br>' | Where-Object -FilterScript { (-not([string]::IsNullOrEmpty($_))) } | Select-Object -Unique | ForEach-Object -Process {
                                $CurrentSupercedence = $_.Trim()
                                #We skip Microsoft Security Bulletin MSYY-XXX because the related KBID is the item after the comma
                                if ($CurrentSupercedence -notmatch "^MS") {
                                    Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] `$CurrentSupercedence : $CurrentSupercedence ..."
                                    $CurrentSupercedence
                                }
                            }

                            SubType = $CurrentRemediation.SubType
                            ProductName = $ProductID[$CurrentRemediation.ProductID].Value
                            CVE = $CVE
                            MaximumSeverityRating = $MaximumSeverityRatingHT[$CVE].MaximumSeverityRating
                        }
                        $CurrentHotfix
                        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] `$CurrentHotfix: $CurrentHotfix"
                    }
                    else
                    {
                        Write-Warning -Message "[Warning] '$KBID' is not a KB ID. WE SKIP IT..."
                    }
                }
            }
        }
    }
    end {
    }
}

Function Get-MsrcHotfixInheritance {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotFix
    )

    $HotFixHT = $HotFix | Where-Object -FilterScript { $_.Supercedence } | Group-Object -Property KBID -AsHashTable -AsString
    $UniqueHotfixWithSupercedence = $HotFixHT.Keys | ForEach-Object -Process {
        $KBID = $_
        $Supercedence = $HotFixHT[$KBID].Supercedence | Select-Object -Unique
        [PSCustomObject] @{KBID=$KBID; Supercedence = [array]$Supercedence}
    } | Sort-Object -Property KBID

    $HotfixInheritedSupercedenceHT = @{}
    $UniqueHotfixWithSupercedence | ForEach-Object -Process {
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing KB$($_.KBID) ..."
        $Supercedence = $_.Supercedence
        #recursive supercedence
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing Supercedence $($Supercedence  -join ', ') for recursive inheritances ..."
        $AllInheritedSupercedences = $Supercedence | ForEach-Object -Process {
            $CurrentSupercedence = $_
            $InheritedSupercedence = $HotfixInheritedSupercedenceHT[$CurrentSupercedence]
            if ($InheritedSupercedence) {
                Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] $CurrentSupercedence supersedes $($InheritedSupercedence -join ', ') ..."
                $InheritedSupercedence
            }
        }
        #Adding recursive supersedence and removing duplicates
        $HotfixInheritedSupercedenceHT[$_.KBID] =  [array]($Supercedence + $AllInheritedSupercedences | Select-Object -Unique)
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Inherited Supercedence : $($HotfixInheritedSupercedenceHT[$_.KBID] -join ', ') ..."
    }

    $HotfixInheritedSuccessorHT = @{}
    $HotfixInheritedSupercedenceHT.Keys | ForEach-Object -Process {
        $KBID = $_
        $Supercedence = $HotfixInheritedSupercedenceHT[$KBID]
        $Supercedence | ForEach-Object -Process {
            $CurrentSupercedence = $_
            if ($HotfixInheritedSuccessorHT[$CurrentSupercedence])
            {
                if ($KBID -notin $HotfixInheritedSuccessorHT[$CurrentSupercedence])
                {
                    Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Inherited Succession : $KBID ..."
                    $HotfixInheritedSuccessorHT[$CurrentSupercedence] += $KBID
                }
                else
                {
                    Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] $KBID is already in the successor list ..."
                }
            }
            else
            {
                $HotfixInheritedSuccessorHT[$CurrentSupercedence] = [array]$KBID
            }
        }
    }



    #We returned a modified version of the input parameter by adding supercedence data
    $HotfixInheritance = $HotFix | Select-Object -Property KBID, Supercedence -Unique
    $HotfixInheritance | ForEach-Object -Process {
        #For Supercedence : Replaced Hotfix
        $CurrentHotfix = $_ | Add-Member -MemberType NoteProperty -Name Supercedences -Value $null -PassThru | Add-Member -MemberType ScriptProperty -Name SupercedenceCount -Value { $This.Supercedences.Count } -PassThru | Add-Member ScriptProperty SupercedenceList { $This.Supercedences -join ', ' } -PassThru
        #For Succession : Replacing Hotfix
        $CurrentHotfix = $_ | Add-Member -MemberType NoteProperty -Name Successors -Value $null -PassThru | Add-Member -MemberType ScriptProperty -Name SuccessorCount -Value { $This.Successors.Count } -PassThru | Add-Member ScriptProperty SuccessorList { $This.Successors -join ', ' } -PassThru
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $($CurrentHotFix.KBID) for update ..."
        $CurrentHotfix.Supercedences = $HotfixInheritedSupercedenceHT[$CurrentHotfix.KBID]
        $CurrentHotfix.Successors = $HotfixInheritedSuccessorHT[$CurrentHotfix.KBID]
    }

    return $HotfixInheritance
}

#Getting all updates regardless the products later than April 2016
$Hotfix = Get-MsrcSecurityUpdate -Verbose | Sort-Object -Property InitialReleaseDate | Where-Object -FilterScript { $_.ID -match "^\d{4}-\w{3}$" } | Get-MsrcHotfix -Verbose #| Out-GridView -PassThru
#Getting all updates for February 2019
#$Hotfix = Get-MsrcHotfix -ID 2019-Feb -Verbose #| Out-GridView -PassThru
#Getting all updates for Windows Server 2012 R2 (OS and products on this OS version) later than April 2016
#$Hotfix = Get-MsrcSecurityUpdate -Verbose | Sort-Object -Property InitialReleaseDate | Where-Object -FilterScript { $_.ID -match "^\d{4}-\w{3}$"} | Get-MsrcHotfix -Verbose | Where-Object -FilterScript {  $_.ProductName | Select-String -Pattern "Windows Server 2012 R2" -Quiet } #| Out-GridView -PassThru
#$Hotfix | Export-Csv -Path $HotfixCSVFile -NoTypeInformation
$Hotfix | ConvertTo-Json | Set-Content -Path $HotfixJSONFile
#$Hotfix = Get-Content -Path $HotfixJSONFile | ConvertFrom-Json

#For line below cf. https://stackoverflow.com/questions/20848507/why-does-powershell-give-different-result-in-one-liner-than-two-liner-when-conve/38212718#38212718
Remove-TypeData System.Array -ErrorAction Ignore

#Building the hotfix supececence and successor chain (supercedence and succession by inheritance) for all updates
$HotfixInheritance = Get-MsrcHotfixInheritance -HotFix $HotFix -Verbose
#$HotfixInheritance | Select-Object -Property * -ExcludeProperty Supercedences, Successors | Export-Csv -Path $HotfixInheritanceCSVFile -NoTypeInformation
$HotfixInheritance | ConvertTo-Json | Set-Content -Path $HotfixInheritanceJSONFile
#$HotfixInheritance = Get-Content -Path $HotfixInheritanceJSONFile | ConvertFrom-Json