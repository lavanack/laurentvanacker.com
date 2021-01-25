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
$HotfixInheritedSuccessorCSVFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfixInheritedSuccessor.csv"
$HotfixInheritedSuccessorJSONFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfixInheritedSuccessor.json"
$HotfixInheritedSupercedenceCSVFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfixInheritedSupercedence.csv"
$HotfixInheritedSupercedenceJSONFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfixInheritedSupercedence.json"
$HotfixSupercedenceCSVFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfixSupercedence.csv"
$HotfixCSVFile = Join-Path -Path $CurrentDir -ChildPath "Get-MsrcHotfix.csv"

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
                    $KBID = $CurrentRemediation.Description.Value
                    if ($KBID -match "\d+")
                    {
                        if ($CurrentRemediation.Supercedence)
                        {
                            if ($CurrentRemediation.Supercedence -notmatch "\d+")
                            {
                                $CurrentRemediation.Supercedence = $null
                            }
                        }
                        else
                        {
                                $CurrentRemediation = $CurrentRemediation | Add-Member -MemberType NoteProperty -Name Supercedence -Value $null -PassThru
                        }
                        $CurrentHotfix = [PSCustomObject]@{
                            Month = $Month
                            Date = $MostRecentRevisionDate
                            KBID = $KBID
                            Supercedence = $CurrentRemediation.Supercedence
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
            $CurrentHotfix.Supercedence -split ',|;|<br>' | Where-Object -FilterScript { (-not([string]::IsNullOrEmpty($_))) } | ForEach-Object -Process {
                $CurrentHotfixSupercedence = $_.Trim()
                #We skip Microsoft Security Bulletin MSYY-XXX because the related KBID is the item after the comma
                if ($CurrentHotfixSupercedence -notmatch "^MS") {
                    Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $CurrentHotfixSupercedence ..."
                    $CurrentHotfix | Select-Object -ExcludeProperty Supercedence -Property *, @{Name = "Supercedence"; Expression = { $CurrentHotfixSupercedence } }
                }
            }
        }
    }
    end {
    }
}

Function Get-MsrcHotfixInheritedSupercedence {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotfixSupercedence
    )

    $HotfixInheritedSupercedenceHT = @{}
    $UniqueHotfixWithSupercedence = $HotfixSupercedence | Sort-Object -Property KBID -Descending | Select-Object -Property KBID, Supercedence -Unique

    $HotfixInheritedSupercedenceHT = @{}
    $UniqueHotfixWithSupercedence | Sort-Object -Property KBID | ForEach-Object -Process {
        $CurrentSupercedence = @($_.Supercedence)
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $CurrentSupercedence for recursive inheritances ..."
        #recursive supercedence
        $InheritedSupercedence = $HotfixInheritedSupercedenceHT[$CurrentSupercedence]
        if ($InheritedSupercedence) {
            $CurrentSupercedence += @($InheritedSupercedence ) | Select-Object -Unique
        }
        $HotfixInheritedSupercedenceHT[$_.KBID] = $CurrentSupercedence
    }

    #We returned a modified version of the input parameter by adding supercedence data
    $HotfixInheritedSupercedence = $HotfixSupercedence | Select-Object -Property KBID, Supercedence -Unique
    $HotfixInheritedSupercedence | ForEach-Object -Process {
        $CurrentHotfix = $_ | Add-Member -MemberType NoteProperty -Name Supercedences -Value $null -PassThru | Add-Member -MemberType ScriptProperty -Name SupercedenceCount -Value { $This.Supercedences.Length } -PassThru | Add-Member ScriptProperty SupercedenceList { $This.Supercedences -join ', ' } -PassThru
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $($CurrentHotFix.KBID) for update ..."
        $CurrentHotfix.Supercedences = $HotfixInheritedSupercedenceHT[$CurrentHotfix.KBID]
    }

    return $HotfixInheritedSupercedence
}

Function Get-MsrcHotfixInheritedSuccessor {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotfixSupercedence
    )

    $HotfixInheritedSuccessorHT = @{}
    $UniqueHotfixWithSupercedence = $HotfixSupercedence | Sort-Object -Property KBID | Select-Object -Property KBID, Supercedence -Unique

    $HotfixInheritedSuccessorHT = @{}
    $UniqueHotfixWithSupercedence | Sort-Object -Property KBID -Descending | ForEach-Object -Process {
        $CurrentSuccessor = @($_.KBID)
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $CurrentSuccessor for recursive succession ..."
        #recursive succession
        $InheritedSuccessor = $HotfixInheritedSuccessorHT[$CurrentSuccessor]
        if ($InheritedSuccessor) {
            $CurrentSuccessor += @($InheritedSuccessor ) | Select-Object -Unique
        }
        $HotfixInheritedSuccessorHT[$_.Supercedence] = $CurrentSuccessor
    }

    #We returned a modified version of the input parameter by adding succession data
    $HotfixInheritedSuccessor = $HotfixSupercedence | Select-Object -Property @{Name="Successor"; Expression={$_.KBID}}, @{Name="KBID"; Expression={$_.Supercedence}} -Unique
    $HotfixInheritedSuccessor | ForEach-Object -Process {
        $CurrentHotfix = $_ | Add-Member -MemberType NoteProperty -Name Successors -Value $null -PassThru | Add-Member -MemberType ScriptProperty -Name SuccessorCount -Value { $This.Successors.Length } -PassThru | Add-Member ScriptProperty SuccessorList { $This.Successors -join ', ' } -PassThru
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $($CurrentHotFix.KBID) for update ..."
        $CurrentHotfix.Successors = $HotfixInheritedSuccessorHT[$CurrentHotfix.KBID]
    }

    return $HotfixInheritedSuccessor
}

Function Get-MsrcHotfixInheritance {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotfixSupercedence,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [object[]]$HotfixSuccessor
    )


    for ($index=0; $index -lt $HotfixSupercedence.Count; $index++)
    {
        $CurrentHotFix = $HotfixSupercedence[$index]
        Write-Verbose "[$(Get-Date -Format (Get-Culture).DateTimeFormat.UniversalSortableDateTimePattern)|$($MyInvocation.MyCommand)] Processing $CurrentHotfix ..."
        $CurrentHotfix.PSObject.Copy() | Add-Member -MemberType NoteProperty -Name Successors -Value $HotfixSuccessor[$index].Successors -PassThru | Add-Member -MemberType ScriptProperty -Name SuccessorCount -Value { $This.Successors.Length } -PassThru | Add-Member ScriptProperty SuccessorList { $This.Successors -join ', ' } -PassThru
    }

}

#Getting all updates regardless the products later than April 2016
$Hotfix = Get-MsrcSecurityUpdate -Verbose | Sort-Object -Property InitialReleaseDate | Where-Object -FilterScript { $_.ID -match "^\d{4}-\w{3}$" } | Get-MsrcHotfix -Verbose #| Out-GridView -PassThru
#Getting all updates for Windows Server 2012 R2 (OS and products on this OS version) later than April 2016
#$Hotfix = Get-MsrcSecurityUpdate -Verbose | Sort-Object -Property InitialReleaseDate | Where-Object -FilterScript { $_.ID -match "^\d{4}-\w{3}$"} | Get-MsrcHotfix -Verbose | Where-Object -FilterScript {  $_.ProductName | Select-String -Pattern "Windows Server 2012 R2" -Quiet } #| Out-GridView -PassThru
$Hotfix | Export-Csv -Path $HotfixCSVFile -NoTypeInformation
#$Hotfix = Import-Csv -Path $HotfixCSVFile

#Building the hotfix supercedence list for all updates with one entry per supercedence
$HotfixSupercedence = Get-MsrcHotfixSupercedence -Hotfix $Hotfix -Verbose
$HotfixSupercedence | Export-Csv -Path $HotfixSupercedenceCSVFile -NoTypeInformation
#$HotfixSupercedence = Import-Csv -Path $HotfixSupercedenceCSVFile

#For line below cf. https://stackoverflow.com/questions/20848507/why-does-powershell-give-different-result-in-one-liner-than-two-liner-when-conve/38212718#38212718
Remove-TypeData System.Array -ErrorAction Ignore

#Building the hotfix supercedence chain (supercedence by inheritance) for all updates
$HotfixInheritedSupercedence = Get-MsrcHotfixInheritedSupercedence -HotfixSupercedence $HotfixSupercedence -Verbose
$HotfixInheritedSupercedence | Select-Object -Property * -ExcludeProperty Supercedences | Export-Csv -Path $HotfixInheritedSupercedenceCSVFile -NoTypeInformation
#$HotfixInheritedSupercedence | ConvertTo-Json | Set-Content -Path $HotfixInheritedSupercedenceJSONFile

#Building the hotfix successor chain (succession by inheritance) for all updates
$HotfixInheritedSuccessor = Get-MsrcHotfixInheritedSuccessor -HotfixSupercedence $HotfixSupercedence -Verbose
$HotfixInheritedSuccessor | Select-Object -Property * -ExcludeProperty Successors | Export-Csv -Path $HotfixInheritedSuccessorCSVFile -NoTypeInformation
#$HotfixInheritedSuccessor | ConvertTo-Json | Set-Content -Path $HotfixInheritedSuccessorJSONFile

$HotfixInheritance = Get-MsrcHotfixInheritance -HotfixSupercedence $HotfixInheritedSupercedence -HotfixSuccessor $HotfixInheritedSuccessor -Verbose
