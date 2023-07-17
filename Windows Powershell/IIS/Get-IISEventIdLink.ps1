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
#Requires -version 5 -RunAsAdministrator

#region Function definitions
function Get-IISEventIdLink {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False)]
        [Object]$Root,
        [Parameter(Mandatory = $False)]
        [string]$FolderURI,
        #Just for progress bar
        [Parameter(Mandatory = $False)]
        [int]$Depth = 0,
        #Just to display navigation accross the level
        [Parameter(Mandatory = $False)]
        [string]$Path = ""
    )
    #For progress bar
    $Index = 0
    #Result
    #We use the embedded images to categorize the severity
    $Severity = @{"images/dd300121.green(ws.10).jpg" = "Information"; "images/dd299897.yellow(ws.10).jpg" = "Warning"; "images/ee406008.red(ws.10).jpg" = "Error"; }
    if (-not($Root)) {
        $URI = "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/toc.json"
        $FolderURI = $URI.Substring(0, $URI.LastIndexOf("/"))

        #Testing if Internet is reachable ...
        if (Test-NetConnection -ComputerName www.microsoft.com -CommonTCPPort HTTP  -InformationLevel Quiet) {
            #Get JSON Content
            $WindowsServer = Invoke-RestMethod -Uri $URI 
            #Get IIS 7.5 location in the the JSON Data
            $Root = $WindowsServer.items.children[6].children[0].children[2].children[15]
            #Main function doing the job by recursive call
        }
        else {
            Write-Error "[ERROR] Unable to connect to Internet ..." -ErrorAction Stop
        }
    }

    $CurrentSection = $Root.toc_title
    #For first call the Path is useless
    if ([string]::IsNullOrEmpty($Path)) {
        $Path = $Root.toc_title
    }
    Write-Host "Processing : $Path"
    #Recursive processing by browsing the children
    $IISEventIdLink = foreach ($CurrentChild in $Root.Children) {
        $Index++
        $CurrentURI = $FolderURI + "/" + $CurrentChild.href
        Write-Progress -Id $Depth -Activity "[$($Index)/$($Root.Children.Count)] Processing $($CurrentChild.toc_title) ..." -status "$([Math]::Round($Index/$Root.Children.Count * 100)) % - $CurrentURI"  -PercentComplete ($Index / $Root.Children.Count * 100)
        if ($CurrentChild.toc_title -match ("\s+(?<EventID>\d+)")) {
            $CurrentEventID = $Matches["EventID"]
            Write-Verbose "`$CurrentEventID : $CurrentEventID"
            $CurrentResponse = Invoke-WebRequest $CurrentURI -UseBasicParsing
            $MyMatches = [regex]::Matches($CurrentResponse, "<td>(?<data>[^<].*)</td>")
            $Data = ($MyMatches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'data' }).Value
            $CurrentProduct = $Data[0]
            $CurrentEventID = $Data[1]
            $CurrentSource = $Data[2]
            $CurrentVersion = $Data[3]
            $CurrentSymbolicName = $Data[4]
            #Event Id 2003 : Has a newline in the message content so -replace "`r`n" is just for this case
            $CurrentMessage = $Data[5] -replace "`r`n"
            #Getting relevant information
            $MyMatches = $([regex]::Matches($CurrentResponse, "<p>(?<data>.*)</p>"))
            $CurrentDescription = ($MyMatches[2].Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'data' }).Value

            $MyMatches = $([regex]::Matches($CurrentResponse, '<img.*src="(?<src>\S*)".*/>'))
            $Image = ($MyMatches.Groups.Captures | Where-Object -FilterScript { $_.Name -eq 'src' }).Value

            if ($Image) {
                $CurrentSeverity = $Severity[$Image]
                Write-Verbose "`$CurrentSeverity : $CurrentSeverity"
            }
            else {
                $CurrentSeverity = $null
            }
            $CurrentLink = [PSCustomObject] @{Section = $CurrentSection; Product = $CurrentProduct; ID = $CurrentEventID; Source = $currentSource; SymbolicName = $CurrentSymbolicName; Message = $currentMessage; Description = $CurrentDescription; Severity = $CurrentSeverity; Version = $CurrentVersion; URI = $CurrentURI }
            Write-Verbose "`$CurrentLink : $CurrentLink)"
            $CurrentLink
        }
        else {
            Write-Verbose "Recursive call from $($CurrentChild.toc_title)"
            Get-IISEventIdLink -Root $CurrentChild -Depth ($Depth + 1) -FolderURI $FolderURI -Path "$Path / $($CurrentChild.toc_title)"
        }
    }
    Write-Progress -Id $Depth -Activity 'Completed !' -Status 'Completed !' -Completed
    return $IISEventIdLink
}

function Get-FilteredIISWinEvent {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [hashtable]$Filter,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [datetime]$StartTime,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
        [datetime]$EndTime
    )
    
    $IISProviderName = Get-WinEvent -ListProvider *iis*, *was* -ErrorAction SilentlyContinue | Where-Object -FilterScript { ($_.LogLinks.DisplayName -in @("Application", "System", "Security")) } | Select-Object -Property Name, @{Name = "EventLog"; Expression = { $_.LogLinks.DisplayName } } | Group-Object -Property EventLog -AsHashTable -AsString

    $FilteredIISWinEvent = foreach ($CurrentEventLog in $IISProviderName.Keys) {
        Write-Verbose "`$CurrentEventLog : $CurrentEventLog"
        $CurrentProviderNames = $IISProviderName[$CurrentEventLog].Name
        foreach ($CurrentProviderName in $CurrentProviderNames) {
            Write-Verbose "`t`CurrentProviderName : $CurrentProviderName"
            $FilterHashtable = @{ LogName = $CurrentEventLog; ProviderName = $CurrentProviderName }
            if ($StartTime) {
                $FilterHashtable.Add('StartTime', $StartTime)
                Write-Verbose -Message "`$StartTime: $StartTime"
            }
            if ($EndTime) {
                $FilterHashtable.Add('EndTime', $EndTime)
                Write-Verbose -Message "`$EndTime: $EndTime"
            }

            if ($Filter) {
                $EventId = [int[]]$Filter.Keys
                $WinEvent = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.Id -in $EventId } | Select-Object -Property @{Name = "ComputerName"; Expression = { $env:COMPUTERNAME } }, @{Name = "EventLog"; Expression = { $CurrentEventLog } }, TimeCreated, Id, @{Name = "Reason"; Expression = { $Filter["$($_.Id)"].SymbolicName } }, LevelDisplayName, Message
                $WinEvent | Select-Object -Property @{Name='DateCreated'; Expression={$_.TimeCreated.Date}}, @{Name='TimeCreated'; Expression={$_.TimeCreated.ToString("HH:mm:ss")}}, @{Name='DateTimeCreated'; Expression={$_.TimeCreated}}, * -ExcludeProperty TimeCreated
            }
            else {
                $WinEvent = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue | Select-Object -Property @{Name = "ComputerName"; Expression = { $env:COMPUTERNAME } }, @{Name = "EventLog"; Expression = { $CurrentEventLog } }, TimeCreated, Id, LevelDisplayName, Message
                $WinEvent
            }
        }
    }
    return $FilteredIISWinEvent
}
#endregion

Clear-Host
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#CSV for exporting data
$IISEventIdLinkCSVFilePath = Join-Path -Path $CurrentDir -ChildPath "IISEventIdLink.csv"
$FilteredIISWinEventCSVFilePath = Join-Path -Path $CurrentDir -ChildPath "$($env:COMPUTERNAME)_FilteredIISWinEvent.csv"

if (-not(Test-Path -Path $IISEventIdLinkCSVFilePath)) {
    $IISEventIdLink = Get-IISEventIdLink -Verbose
    Write-Host "[INFO] Event ID Link Data have been exported to $IISEventIdLinkCSVFilePath"
    $IISEventIdLink | Export-Csv -Path $IISEventIdLinkCSVFilePath -NoTypeInformation -Encoding UTF8
}

if (Test-Path -Path $IISEventIdLinkCSVFilePath) {
    $YesterdayUTC = [System.DateTime]::UtcNow.AddDays(-1)
    $YesterdayUTCInLocalTime = ([System.DateTime]::new($YesterdayUTC.Year, $YesterdayUTC.Month, $YesterdayUTC.Day, 0, 0, 0, [System.DateTimeKind]::Utc)).ToLocalTime()
    $StartTime = $YesterdayUTCInLocalTime
    $EndTime = $StartTime.AddDays(1).AddSeconds(-1)
    $YesterDayTimeStamp = "{0:yyMMdd}" -f $StartTime
    $FilteredIISWinEventCSVFilePath = Join-Path -Path $CurrentDir -ChildPath "$($env:COMPUTERNAME)_FilteredIISWinEvent_$YesterDayTimeStamp.csv"

    $IISEventIdLink = Import-Csv -Path $IISEventIdLinkCSVFilePath -Encoding UTF8
    #Looking or local IIS-related event IDs ("Warning" or "Error" only)
    $WarningOrErrorIISEventIdLinkHT = $IISEventIdLink | Where-Object -FilterScript { $_.Severity -in "Warning", "Error" } | Group-Object -Property ID -AsHashTable -AsString
    $FilteredIISWinEvent = Get-FilteredIISWinEvent -Filter $WarningOrErrorIISEventIdLinkHT -StartTime $StartTime -EndTime $EndTime -Verbose
    Write-Host "[INFO] Filtered IIS Win Events have been exported to $FilteredIISWinEventCSVFilePath"
    $FilteredIISWinEvent | Export-Csv -Path $FilteredIISWinEventCSVFilePath -NoTypeInformation -Encoding UTF8
}
Else {
    Write-Error "[ERROR] No '$IISEventIdLinkCSVFilePath' file found ..."
}

