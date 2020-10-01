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
function Add-IISUserFriendlyTLSInfo {
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $True, HelpMessage = 'Please specify the path of a valid IIS log file', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.log$')
			})]
		[String[]]$Fullname,

		[Parameter(Mandatory = $True, HelpMessage = 'Please specify the path of a valid LogParser SQL file')]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.sql$')
			})]
		[String]$LogParserSQLFile,

		[Parameter(Mandatory = $False)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match 'LogParser\.exe$')
			})]
		[String]$LogParserExe = "C:\Program Files (x86)\Log Parser 2.2\LogParser.exe",

		[switch] $PassThru
	)
	
	begin {
	}
	process {
		foreach ($CurrentFullname in $Fullname) {
			Write-Verbose "Processing $CurrentFullname"
			$OutputLogFile = "$CurrentFullname" -replace ".log$", "_TLS.log"
			Write-Verbose "`$OutputLogFile : $OutputLogFile"
			$IISLogFields = ((Get-Content $CurrentFullname -TotalCount 4 | Select-Object -Last 1) -split " " | Select-Object -Skip 1) -join ", "
			# The dtLines option allows you to specify the number of lines to read to detect the types of fields at runtime. By setting to 0 this avoids an unfortunate side effect which converts for example all the values defined by 'e' in element of type REAL (for example '660e' becomes in 660.000000)
			$LogParserParamsInput = "file:`"$LogParserSQLFile`"?InputFiles=`"$CurrentFullname`"+IISLogFields=`"$IISLogFields`" -i:W3C -rtp:-1 -dtLines:0 -stats:OFF -o:W3C"
			Write-Verbose "`$LogParserParamsInput : $LogParserParamsInput"
			Write-Verbose "`"$LogParserExe`" $LogParserParamsInput "
			Start-Process -FilePath "$LogParserExe" -ArgumentList $LogParserParamsInput -WindowStyle Hidden -Wait -RedirectStandardOutput $OutputLogFile
			if ($PassThru) {
				$OutputLogFile
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
$LogParserSQLFile = Join-Path -Path $CurrentDir -ChildPath "IISTLSUsage.sql"

Get-ChildItem -Path "$CurrentDir\*" -Filter *.log -Exclude *_TLS.log -File -Recurse | Add-IISUserFriendlyTLSInfo -LogParserSQLFile $LogParserSQLFile -PassThru -Verbose
