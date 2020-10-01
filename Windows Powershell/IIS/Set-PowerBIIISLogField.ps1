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

			#IIS Fields in the IIS log and used by PowerBI
            $CurrentIISLogFields = $CurrentIISLogFields | Where-Object -FilterScript { $_ -in $AllIISLogFieldsWithDefaults.Keys}
			Write-Verbose "PowerBI Filtered`$CurrentIISLogFields : $CurrentIISLogFields"

			#IIS Fields in the IIS log, used by PowerBI and needing name translation like cs(User-Agent) => cs-user-agent
            $CurrentIISLogFields = $CurrentIISLogFields | ForEach-Object -Process { if ($TranslatedIISLogFields[$_]) {$TranslatedIISLogFields[$_]} else {$_}  }
			Write-Verbose "Translated `$CurrentIISLogFields : $CurrentIISLogFields"

			#Missing IIS Fields in the IIS log and used by PowerBI
            $MissingIISLogFields = $AllIISLogFieldsWithDefaults.Keys | Where-Object -FilterScript { $_ -notin $CurrentIISLogFields}
			Write-Verbose "`$MissingIISLogFields : $MissingIISLogFields"

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

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$LogParserExe = "C:\Program Files (x86)\Log Parser 2.2\LogParser.exe"

Get-ChildItem -Path "$CurrentDir\*" -Filter *.log -File -Recurse | Set-PowerBIIISLogField -PassThru #-Verbose #-LogParserExe $LogParserExe
