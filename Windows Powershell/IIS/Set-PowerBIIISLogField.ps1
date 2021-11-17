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
#This script will format the IIS log files to CSV files with the required IIS fields for the PowerBI used in https://joymonscode.blogspot.com/2019/09/power-bi-desktop-dashboard-for-iis-log.html

function Set-PowerBIIISLogField {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $True, HelpMessage = 'Please specify the path of a valid IIS log file', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.log$')
			})]
		[String[]]$Fullname,

		[Parameter(Mandatory = $False)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match 'LogParser\.exe$')
			})]
		[String]$LogParserExe = "C:\Program Files (x86)\Log Parser 2.2\LogParser.exe",

		[switch] $PassThru
	)
	
	begin {
        #All IIS Log fields
        #$AllIISLogFieldsWithDefaults = @{'date' = '-'; 'time' = '-'; 's-sitename' = '-'; 's-computername' = '-'; 's-ip' = '-'; 'cs-method' = '-'; 'cs-uri-stem' = '-'; 'cs-uri-query' = '-'; 's-port' = '-'; 'cs-username' = '-'; 'c-ip' = '-'; 'cs-version' = '-'; 'cs(User-Agent)' = '-'; 'cs(Cookie)' = '-'; 'cs(Referrer)' = '-'; 'cs-host' = '-'; 'sc-status' = '-'; 'sc-substatus' = '-'; 'sc-win32-status' = '-'; 'sc-bytes' = '0'; 'cs-bytes' = '0'; 'time-taken' = '0'}
        
        #PowerBI IIS Log fields
        $AllIISLogFieldsWithDefaults = @{'date' = '-'; 'time' = '-'; 's-ip' = '-'; 'cs-method' = '-'; 'cs-uri-stem' = '-'; 'cs-uri-query' = '-'; 's-port' = '-'; 'cs-username' = '-'; 'c-ip' = '-'; 'cs(User-Agent)' = '-'; 'sc-status' = '-'; 'sc-substatus' = '-'; 'sc-win32-status' = '-'; 'sc-bytes' = '0'; 'cs-bytes' = '0'; 'time-taken' = '0'}

        #IIS Log field translation from W3C to CSV format
        $TranslatedIISLogFields = @{'cs(User-Agent)' = 'cs-user-agent'; 'cs(Cookie)' = 'cs-cookie'; 'cs(Referrer)' = 'cs-referer'}
	}
	process {
		foreach ($CurrentFullname in $Fullname) {
			Write-Verbose "Processing $CurrentFullname"
			$OutputCSVFile = "$CurrentFullname" -replace ".log$", ".csv"
			Write-Verbose "`$OutputCSVFile : $OutputCSVFile"
			#IIS Fields in the IIS log
            $CurrentIISLogFields = ((Get-Content $CurrentFullname -TotalCount 4 | Select-Object -Last 1) -split " " | Select-Object -Skip 1)
			Write-Verbose "`$CurrentIISLogFields : $CurrentIISLogFields"

			#Missing IIS Fields in the IIS log and used by PowerBI
            $MissingIISLogFields = $AllIISLogFieldsWithDefaults.Keys | Where-Object -FilterScript { $_ -notin $CurrentIISLogFields}
			Write-Verbose "`$MissingIISLogFields : $MissingIISLogFields"

			#IIS Fields in the IIS log and used by PowerBI
            $CurrentIISLogFields = $CurrentIISLogFields | Where-Object -FilterScript { $_ -in $AllIISLogFieldsWithDefaults.Keys}
			Write-Verbose "PowerBI Filtered `$CurrentIISLogFields : $CurrentIISLogFields"

			#IIS Fields in the IIS log, used by PowerBI and needing name translation like cs(User-Agent) => cs-user-agent
            $CurrentIISLogFields = $CurrentIISLogFields | ForEach-Object -Process { if ($TranslatedIISLogFields[$_]) {"$_ as $($TranslatedIISLogFields[$_])"}  else {$_}  }
			Write-Verbose "Translated `$CurrentIISLogFields : $CurrentIISLogFields"

			#Missing IIS Fields in the IIS log, used by PowerBI and needing name translation like cs(User-Agent) => cs-user-agent
            $MissingIISLogFields = $($MissingIISLogFields | ForEach-Object -Process { if ($TranslatedIISLogFields[$_]) {"'$($AllIISLogFieldsWithDefaults[$_])' as $($TranslatedIISLogFields[$_])"} else {"'$($AllIISLogFieldsWithDefaults[$_])' as $_"} })
			Write-Verbose "Translated `$MissingIISLogFields : $MissingIISLogFields"

            #Building a IIS log field list (present or not in the IIS Logs) required by PowerBI
            $IISFields = $($CurrentIISLogFields + $MissingIISLogFields) -join ', '
			Write-Verbose "`$IISFields : $IISFields"

            #Building LogParser Query
            $LogParserQuery = "SELECT $IISFields INTO '"+$OutputCSVFile+"' FROM '"+$CurrentFullname+"'"
			Write-Verbose "`$LogParserQuery : $LogParserQuery"
            [void]$(& $LogParserExe -i:W3C -o:csv $LogParserQuery)
			if ($PassThru) {
				$OutputCSVFile
			}
		}
	}
	end {
	}
}

function Expand-String { 
	<#
			.SYNOPSIS
			Expands a string 

			.DESCRIPTION
			Expands a string 

			.PARAMETER Value
			The string to expand

			.PARAMETER EnvironmentVariable
			Switch to specify is the string to expand is related to an environment variable

			.EXAMPLE
			Expand-String -Value $env:Path -EnvironmentVariable
	#>
	[CmdletBinding()]
	param( 
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] 
		[string]$Value, 

		[switch]$EnvironmentVariable 
	)

	if ($EnvironmentVariable) {
		[System.Environment]::ExpandEnvironmentVariables($Value)
	} 
	else {
		$ExecutionContext.InvokeCommand.ExpandString($Value)
	} 
} 

function Get-IISLogFile {
	<#
			.SYNOPSIS
			Returns a collection of files (*.log or *.* if -All is specified) in the log directory for the specified web sites

			.DESCRIPTION
			Returns a collection of files (*.log or *.* if -All is specified) in the log directory for the specified web sites

			.PARAMETER WebSite
			The web sites for which we want generate fake log files

			.PARAMETER OlderThanThisDate
			The optional date in the past from which we return the log files (based on LastWriteTime property of each file)

			.PARAMETER OlderThanXDays
			The optional day number in the past (from now) from which we return the log files (based on LastWriteTime property of each file)

			.PARAMETER All 
			An optional switch specifying if we return all files (*.*) instead only IIS log files (*.log)

			.EXAMPLE
			$IISLogFiles = Get-Website | Get-IISLogFile -Verbose -OlderThanXDays 30
			Returns a collections of IIS log files older than 30 days for all hosted web sites and store it in the $IISLogFiles variables. The verbose mode is enabled

			.EXAMPLE
			$IISLogFiles = "www.contoso.com" | Get-IISLogFile -OlderThanThisDate "01/01/2016"
			Returns a collections of IIS log files older than the 1st January 2016 for the "www.contoso.com" web site and store it in the $IISLogFiles variables.

			.EXAMPLE
			$IISLogFiles =  Get-IISLogFile -FullName "www.contoso.com", "Default Web Site" -OlderThanThisDate "01/01/2016"
			Returns a collections of IIS log files older than the 1st January 2016 for the "www.contoso.com" and "Default Web Site" web sites and store it in the $IISLogFiles variables.
	#>
	[CmdletBinding(DefaultParameterSetName = 'OlderThanXDays')]
	Param
	(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[alias('Name')]
		[String[]]$WebSite,

		[Parameter(Mandatory = $False, ParameterSetName = 'OlderThanThisDate')][ValidateNotNullOrEmpty()][ValidateScript( {
				$_ -le (Get-Date)
			})]
		[Datetime]$OlderThanThisDate,

		[Parameter(Mandatory = $False, ParameterSetName = 'OlderThanXDays')][ValidateNotNullOrEmpty()]
		[int]$OlderThanXDays,

		[switch]$All
	)
	
	begin {
		#The collection of returned files.
		$IISLogFiles = @()
	}
	process {
		foreach ($currentWebSiteName in $WebSite) {
			$CurrentWebSite = Get-Website | Where-Object -FilterScript {
				$_.Name -eq $currentWebSiteName 
			}
			if ($CurrentWebSite) {
				# Date management
				if ($OlderThanXDays) {
					$PastDate = (Get-Date).AddDays(-$OlderThanXDays)
				}
				elseif ($OlderThanThisDate) {
					$PastDate = $OlderThanThisDate
				}
				else {
					$PastDate = Get-Date
				}
				Write-Verbose -Message "Past Date : $PastDate ..."

				Write-Verbose -Message "Processing $($CurrentWebSite.Name) ..."
				$CurrentLogFileDirectory = Expand-String -Value $(Join-Path -Path $CurrentWebSite.logFile.directory -ChildPath $('W3SVC' + $CurrentWebSite.id)) -EnvironmentVariable
				if ($All) {
					$Filter = '*.*'
				}
				else {
					$Filter = '*.log'
				}
				$IISLogFiles += $(Get-ChildItem -Path $CurrentLogFileDirectory -Filter $Filter -ErrorAction SilentlyContinue | Where-Object -FilterScript {
						$_.LastWriteTime -lt $PastDate
					})
			}
			else {
				Write-Warning -Message "$currentWebSiteName NOT found"
			}
		}
	}
	end {
		return $IISLogFiles
	}
}

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$LogParserExe = "C:\Program Files (x86)\Log Parser 2.2\LogParser.exe"

#Get-ChildItem -Path "$CurrentDir\*" -Filter *.log -File -Recurse | Set-PowerBIIISLogField -PassThru #-Verbose #-LogParserExe $LogParserExe
Get-Website | Get-IISLogFile | Where-Object { $_.Basename -like "*$("{0:yyMMdd}" -f ((Get-Date).AddDays(-1)))*"} | Set-PowerBIIISLogField -PassThru -Verbose #-LogParserExe $LogParserExe