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
#Requires -version 5 #-RunAsAdministrator

function Get-IISEventIdLink
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [Object]$Root,
        [Parameter(Mandatory=$False)]
        [string]$FolderURI,
        #Just for progress bar
        [Parameter(Mandatory=$False)]
        [int]$Depth = 0,
        #Just to display navigation accross the level
        [Parameter(Mandatory=$False)]
        [string]$Path = ""
    )
    #For progress bar
    $Index = 0
    #Result
    $IISEventIdLink = @()
    #We use the embedded images to categorize the severity
    $Severity=@{"images/dd300121.green%28ws.10%29.jpg"="Information";"images/dd299897.yellow%28ws.10%29.jpg"="Warning";"images/ee406008.red%28ws.10%29.jpg"="Error";}
    if (-not($Root))
    {
        $URI = "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/toc.json"
        $FolderURI = $URI.Substring(0, $URI.LastIndexOf("/"))

        #Testing if Internet is reachable ...
        if (Test-NetConnection -ComputerName www.microsoft.com -CommonTCPPort HTTP  -InformationLevel Quiet)
        {
            #Get JSON Content
            $WindowsServer = Invoke-WebRequest $URI -ContentType  'charset=utf-8' | ConvertFrom-Json
            #Get IIS 7.5 location in the the JSON Data
            $Root=$WindowsServer.items.children[6].children[0].children[2].children[15]
            #Main function doing the job by recursive call
        }
        else
        {
            Write-Error "[ERROR] Unable to connect to Internet ..." -ErrorAction Stop
        }
    }

    $CurrentSection = $Root.toc_title
    #For first call the Path is useless
    if ([string]::IsNullOrEmpty($Path))
    {
        $Path = $Root.toc_title
    }
    Write-Host "Processing : $Path"
    #Recursive processing by browsing the children
    foreach ($CurrentChild in $Root.Children)
    {
        $Index++
        $CurrentURI = $FolderURI + "/" + $CurrentChild.href
        Write-Progress -Id $Depth -Activity "[$($Index)/$($Root.Children.Count)] Processing $($CurrentChild.toc_title) ..." -status "$([Math]::Round($Index/$Root.Children.Count * 100)) % - $CurrentURI"  -PercentComplete ($Index/$Root.Children.Count * 100)
        if ($CurrentChild.toc_title -match ("\s+(?<EventID>\d+)"))
        {
            $CurrentEventID = $Matches["EventID"]
            Write-Verbose "`$CurrentEventID : $CurrentEventID"
            $CurrentResponse = Invoke-WebRequest $CurrentURI -ContentType 'application/json; charset=utf-8'

            #Getting relevant information
            $CurrentProduct = ($CurrentResponse.AllElements.InnerText -match "^Product:(.+)$") -split ":" | Select-Object -Skip 1 -First 1
            $CurrentEventID = ($CurrentResponse.AllElements.InnerText -match "^ID:(.+)$") -split ":" | Select-Object -Skip 1 -First 1
            $CurrentSource = $CurrentResponse.AllElements.InnerText -match "^Source:(.+)$" -split ":" | Select-Object -Skip 1 -First 1
            #Event Id 2003 : Has a newline in the message content so -replace "`r`n" is just for this case
            $CurrentMessage = ($CurrentResponse.AllElements.InnerText -match "^Message:(.+)") -split ":" -replace "`r`n" | Select-Object -Skip 1 -First 1
            $CurrentVersion = ($CurrentResponse.AllElements.InnerText -match "^Version:(.+)$") -split ":"| Select-Object -Skip 1 -First 1
            $CurrentSymbolicName = ($CurrentResponse.AllElements.InnerText -match "^Symbolic Name:(.+)$") -split ":" | Select-Object -Skip 1 -First 1
            $CurrentDescription = ($CurrentResponse.ParsedHtml.body.getElementsByTagName("p") | Select-Object -Property innerText -First 1 -Skip 4).innerText
            $Image = ($CurrentResponse.Images | Where-Object -FilterScript { $_.Src }).Src.Trim() | Select-Object -First 1
            if ($Image)
            {
                $CurrentSeverity = $Severity[$Image]
                Write-Verbose "`$CurrentSeverity : $CurrentSeverity"
            }
            else
            {
                $CurrentSeverity = $null
            }
            $CurrentLink = New-Object -TypeName psobject -Property @{Section=$CurrentSection; Product=$CurrentProduct; ID=$CurrentEventID; Source = $currentSource; SymbolicName = $CurrentSymbolicName; Message = $currentMessage; Description = $CurrentDescription; Severity = $CurrentSeverity; Version = $CurrentVersion; URI=$CurrentURI}
            Write-Verbose "`$CurrentLink : $CurrentLink)"
            $IISEventIdLink += $CurrentLink
        }
        else
        {
            Write-Verbose "Recursive call from $($CurrentChild.toc_title)"
            $IISEventIdLink += Get-IISEventIdLink -Root $CurrentChild -Depth ($Depth+1) -FolderURI $FolderURI -Path "$Path / $($CurrentChild.toc_title)"
        }
    }
    Write-Progress -Id $Depth -Activity 'Completed !' -Status 'Completed !' -Completed
    return $IISEventIdLink
}

function Get-FilteredIISWinEvent
{
    [CmdletBinding()]
    param(
        [hashtable]$Filter
    )
    $FilteredIISWinEvent = @()
    $IISProviderName = Get-WinEvent -ListProvider *iis*, *was* -ErrorAction SilentlyContinue | Where-Object -FilterScript { ($_.LogLinks.DisplayName -in @("Application", "System", "Security")) } | Select-Object -Property Name,  @{Name="EventLog";Expression={$_.LogLinks.DisplayName}} | Group-Object -Property EventLog -AsHashTable -AsString
    foreach ($CurrentEventLog in $IISProviderName.Keys)
    {
        Write-Verbose "`$CurrentEventLog : $CurrentEventLog"
        $CurrentProviderNames=$IISProviderName[$CurrentEventLog].Name
        foreach ($CurrentProviderName in $CurrentProviderNames)
        {
            Write-Verbose "`t`CurrentProviderName : $CurrentProviderName"
            if ($Filter)
            {
                $EventId = [int[]]$Filter.Keys
                $FilteredIISWinEvent += Get-WinEvent -FilterHashtable @{ Logname=$CurrentEventLog; ProviderName=$CurrentProviderName} -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.Id -in $EventId} | Select-Object -Property @{Name="ComputerName"; Expression={$env:COMPUTERNAME}}, @{Name="EventLog"; Expression={$CurrentEventLog}}, TimeCreated, Id, @{Name="Reason"; Expression={$Filter["$($_.Id)"].SymbolicName}}, LevelDisplayName, Message
            }
            else
            {
                $FilteredIISWinEvent += Get-WinEvent -FilterHashtable @{ Logname=$CurrentEventLog; ProviderName=$CurrentProviderName} -ErrorAction SilentlyContinue | Select-Object -Property @{Name="ComputerName"; Expression={$env:COMPUTERNAME}}, @{Name="EventLog"; Expression={$CurrentEventLog}}, TimeCreated, Id, LevelDisplayName, Message
            }

        }
    }
    return $FilteredIISWinEvent
}

Clear-Host
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#TOC URI : JSON content

#CSV for exporting data
$IISEventIdLinkCSVFilePath = Join-Path -Path $CurrentDir -ChildPath "IISEventIdLink.csv"
$FilteredIISWinEventCSVFilePath = Join-Path -Path $CurrentDir -ChildPath "$($env:COMPUTERNAME)_FilteredIISWinEvent.csv"

if (-not(Test-Path -Path $IISEventIdLinkCSVFilePath))
{
    $IISEventIdLink = Get-IISEventIdLink -Verbose
    Write-Host "[INFO] Event ID Link Data have been exported to $IISEventIdLinkFilePath"
    $IISEventIdLink | Export-Csv -Path $IISEventIdLinkCSVFilePath -NoTypeInformation -Encoding UTF8
}

#Looking or local IIS-related event IDs ("Warning" or "Error" only)
$WarningOrErrorIISEventIdLinkHT = $IISEventIdLink | Where-Object -FilterScript { $_.Severity -in "Warning", "Error"} | Group-Object -Property ID -AsHashTable -AsString
$FilteredIISWinEvent = Get-FilteredIISWinEvent -Filter $WarningOrErrorIISEventIdLinkHT -Verbose
Write-Host "[INFO] Filtered IIS Win Events have been exported to $FilteredIISWinEventCSVFilePath"
$FilteredIISWinEvent | Export-Csv -Path $FilteredIISWinEventCSVFilePath -NoTypeInformation -Encoding UTF8