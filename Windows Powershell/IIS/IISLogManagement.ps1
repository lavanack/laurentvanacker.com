#requires -version 2 -Module WebAdministration -RunAsAdministrator

#region Importing the Module WebAdministration for Windows 2008 R2
Import-Module -Name WebAdministration
#endregion

#region Function definition
Function Remove-Ref {
	param
	(
		[Object]
		$ref
	)

	<#
			.SYNOPSIS
			Releases a COM Object

			.DESCRIPTION
			Releases a COM Object

			.PARAMETER  ref
			The COM Object to release

			.EXAMPLE
			$Word=new-object -ComObject "Word.Application"
			...
			Remove-Ref($Word)
	#>
	$null = Remove-Variable -Name $ref -ErrorAction SilentlyContinue
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {

	}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
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

function New-IISLogFile {
	<#
			.SYNOPSIS
			Generates fake log files for the specified web sites. The collection of the generated log files is returned.
			The date and time of the log files is set to the related day at 11:59:59 PM (UTC) 
			Useful function to test a purge and archive mechanism.

			.DESCRIPTION
			Generates fake log files for the specified web sites. The collection of the generated log files is returned.
			The date and time of the log files is set to the related day at 11:59:59 PM (UTC) 
			Useful function to test a purge and archive mechanism.

			.PARAMETER WebSite
			The web sites for which we want generate fake log files

			.PARAMETER Days
			The optional day number in the past from which we generate the fake log files. A log file per day. (default value : 365. Range : 1-366)

			.PARAMETER Format
			The optional format of the fake log files. If no format is specified we look for the format in the IIS configuration for the web site(s).

			.PARAMETER Encoding
			The optional encoding of the fake log files. If no encoding is specified we look for the format in the IIS configuration. 

			.PARAMETER Size 
			The optional size of the fake log files. (default value : 1M. Range : 1-100MB)

			.PARAMETER Force 
			An optional switch specifying if we overwrite existing log files. (Be Careful !)

			.EXAMPLE
			$NewIISLogFiles = Get-Website | New-IISLogFile -Verbose
			Generates one year of fake log files for all hosted websites and store the collections of generated files into the $NewIISLogFile variable in verbose mode

			.EXAMPLE
			$NewIISLogFiles = New-IISLogFile -Days 100 -Encoding ANSI -WebSite "Default Web site", "www.contoso.com" -Force -Verbose 
			Generates 100 fake log files for the "Default Web site" and "www.contoso.com" websites in verbose mode
    
			.EXAMPLE
			$NewIISLogFiles = New-IISLogFile -Force -Days 30 -WebSite "Default Web site"
			Generates 30 fake log files for the "Default Web site" website and overwrite previously existing files.
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[alias('Name')]
		[String[]]$WebSite,
		
		[Parameter(Mandatory = $False)]
		[ValidateRange(1, 366)]
		[int]$Days = 365,
		
		[Parameter(Mandatory = $False)]
		[ValidateSet('W3C', 'IIS', 'NCSA')]
		[String]$Format,
		
		[Parameter(Mandatory = $False)]
		[ValidateSet('UTF8', 'ANSI')]
		#[String]$Encoding="UTF8",
		[String]$Encoding,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Size")]
		[ValidateRange(1, 100MB)]
		[int]$Size = 1MB,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Content")]
		[switch]$Content,

		[Parameter(Mandatory = $False, ParameterSetName = "Content")]
		[switch]$Custom,

		[switch]$Force
	)
	begin {
		#The collection of the generated fake IIS log files.
		$NewIISLogFiles = @()
		if (-not($Encoding)) {
			if ((Get-WebConfiguration -Filter system.applicationHost/log).logInUTF8) {
				$Encoding = 'UTF8'
			}
			else {
				$Encoding = 'ANSI'
			}
			Write-Verbose -Message "Encoding : $Encoding"
		}
        if ($Custom) {
            $Content = $true
        }
		$IISLogFileContent = @"
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2020-12-10 15:02:48
#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken
2020-12-10 15:02:48 W3SVC1 $env:COMPUTERNAME 127.0.0.1 GET / - 80 - 127.0.0.1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+Touch;+rv:11.0)+like+Gecko - - 127.0.0.1 304 0 0 166 359 140
2020-12-10 15:02:48 W3SVC1 $env:COMPUTERNAME 127.0.0.1 GET /iisstart.png - 80 - 127.0.0.1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+Touch;+rv:11.0)+like+Gecko - http://www.contoso.com/ 127.0.0.1 304 0 0 166 413 15
"@
		$IISLogFileCustomContent = @"
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2020-12-10 15:02:48
#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken crypt-protocol crypt-cipher crypt-hash crypt-keyexchange OriginalIP
2020-12-10 15:02:48 W3SVC1 $env:COMPUTERNAME 127.0.0.1 GET / - 80 - 127.0.0.1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+Touch;+rv:11.0)+like+Gecko - - 127.0.0.1 304 0 0 166 359 140 400 6610 800d ae06 -
2020-12-10 15:02:48 W3SVC1 $env:COMPUTERNAME 127.0.0.1 GET /iisstart.png - 80 - 127.0.0.1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+Touch;+rv:11.0)+like+Gecko - http://www.contoso.com/ 127.0.0.1 304 0 0 166 413 15 400 6610 800d ae06 -
"@
	}
	process {
		foreach ($currentWebSiteName in $WebSite) {
			$CurrentWebSite = Get-Website | Where-Object -FilterScript {
				$_.Name -eq $currentWebSiteName 
			}
			if ($CurrentWebSite) {
				Write-Verbose -Message "Processing $($CurrentWebSite.Name) ..."
				$CurrentLogFileDirectory = Expand-String -Value $(Join-Path -Path $CurrentWebSite.logFile.directory -ChildPath $('\W3SVC' + $CurrentWebSite.id)) -EnvironmentVariable
				Write-Verbose -Message "Log File Directory : $CurrentLogFileDirectory"
				if (-not(Test-Path -Path $CurrentLogFileDirectory -PathType Leaf)) {
					Write-Verbose -Message "Creating $CurrentLogFileDirectory directory ..."
					$null = New-Item -ItemType Directory -Path $CurrentLogFileDirectory -Force
				}
				if ($Format) {
					$CurrentLogFormat = $Format
				}
				else {
					$CurrentLogFormat = $CurrentWebSite.Logfile.logFormat
				}
				Write-Verbose -Message "Current Log Format : $CurrentLogFormat ..."
				(-$Days + 1)..0 | ForEach-Object -Process {
					# Transforming the specified date as UTC time (without shifting) at 23:59:59
					$LogFileLastWriteTimeUTC = [DateTime]::SpecifyKind((Get-Date).AddDays($_).Date.AddSeconds(-1), [DateTimeKind]::Utc)
					Write-Verbose -Message "Log File Last Write Time UTC : $LogFileLastWriteTimeUTC ..."
					switch ($CurrentLogFormat) {
						'W3C' {
							if ($Encoding -eq 'ANSI') {
								$CurrentLogFile = Join-Path -Path $CurrentLogFileDirectory -ChildPath $('ex{0:yy}{0:MM}{0:dd}.log' -f ($LogFileLastWriteTimeUTC))
							}
							else {
								$CurrentLogFile = Join-Path -Path $CurrentLogFileDirectory -ChildPath $('u_ex{0:yy}{0:MM}{0:dd}.log' -f ($LogFileLastWriteTimeUTC))
							}
						}
						'IIS' {
							$CurrentLogFile = Join-Path -Path $CurrentLogFileDirectory -ChildPath $('u_in{0:yy}{0:MM}{0:dd}.log' -f ($LogFileLastWriteTimeUTC))
						}
						'NCSA' {
							$CurrentLogFile = Join-Path -Path $CurrentLogFileDirectory -ChildPath $('u_nc{0:yy}{0:MM}{0:dd}.log' -f ($LogFileLastWriteTimeUTC))
						}
					}
                    if ($Custom)
                    {
                        $CurrentLogFile = $CurrentLogFile -replace ".log$","_x.log"
                    }
					if (-not (Test-Path -Path $CurrentLogFile -PathType Leaf)) {
						# fsutil file createnew $CurrentLogFile $Size | Out-Null
						# $NewIISLogFile = Get-Item -Path $CurrentLogFile
						# $NewIISLogFile.LastWriteTimeUTC = $LogFileLastWriteTimeUTC
						if ($Custom) {
							$IISLogFileCustomContent | Out-File -FilePath $CurrentLogFile -Encoding $Encoding
							(Get-Item -Path $CurrentLogFile).LastWriteTimeUtc = $LogFileLastWriteTimeUTC
						}
						elseif ($Content) {
							$IISLogFileContent | Out-File -FilePath $CurrentLogFile -Encoding $Encoding
							(Get-Item -Path $CurrentLogFile).LastWriteTimeUtc = $LogFileLastWriteTimeUTC
						}
						else {
							$NewIISLogFile = [System.IO.File]::Create($CurrentLogFile)
							$NewIISLogFile.SetLength($Size)
							$NewIISLogFile.Close()
							[System.IO.File]::SetLastWriteTimeUTC($CurrentLogFile, $LogFileLastWriteTimeUTC)

						}
						Write-Verbose -Message "Creating the $CurrentLogFile file (Size : $((Get-Item -Path $CurrentLogFile).Length)) ..."
						$NewIISLogFiles += $NewIISLogFile
					}
					else {
						if ($Force) {
							Remove-Item -Path $CurrentLogFile -Force
						    
							#fsutil file createnew $CurrentLogFile $Size | Out-Null
							#$NewIISLogFile = Get-Item -Path $CurrentLogFile
							#$NewIISLogFile.LastWriteTimeUTC = $LogFileLastWriteTimeUTC

						    if ($Custom) {
							    $IISLogFileCustomContent | Out-File -FilePath $CurrentLogFile -Encoding $Encoding
							    (Get-Item -Path $CurrentLogFile).LastWriteTimeUtc = $LogFileLastWriteTimeUTC
						    }
						    elseif ($Content) {
								$IISLogFileContent | Out-File -FilePath $CurrentLogFile -Encoding $Encoding
								(Get-Item -Path $CurrentLogFile).LastWriteTimeUtc = $LogFileLastWriteTimeUTC
							}
							else {
								$NewIISLogFile = [System.IO.File]::Create($CurrentLogFile)
								$NewIISLogFile.SetLength($Size)
								$NewIISLogFile.Close()
								[System.IO.File]::SetLastWriteTimeUTC($CurrentLogFile, $LogFileLastWriteTimeUTC)
							}
    						Write-Verbose -Message "Overwriting the $CurrentLogFile file (Size : $((Get-Item -Path $CurrentLogFile).Length)) ..."						
							$NewIISLogFiles += $NewIISLogFile
						}
						else {
							Write-Verbose -Message "Skipping the $CurrentLogFile file because it already exists ..."
						}
					}
					Write-Progress -Activity "$($CurrentWebSite.Name) - $($('{0:yyyy}/{0:MM}/{0:dd}' -f ($LogFileLastWriteTimeUTC)))" -Status "Processing $CurrentLogFile (Size : $((Get-Item -Path $CurrentLogFile).Length))" -PercentComplete (($Days + $_) / $Days * 100)
					Write-Verbose -Message $('Percent Complete : {0:p0}' -f $(($Days + $_) / $Days))
				}
				Write-Progress -Activity 'IIS Logs Generation Completed !' -Status 'IIS Logs Generation Completed !' -Completed
			}
			else {
				Write-Warning -Message "$currentWebSiteName NOT found"
			}
		}
	}
	end {
		return $NewIISLogFiles
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

function Compress-File {
	<#
			.SYNOPSIS
			Compress a file in the zip format by using a Windows native feature.
			This function supports the risk mitigation mode (-whatif and -confirm switches)

			.DESCRIPTION
			Compress a file in the zip format by using a Windows native feature.
			This function supports the risk mitigation mode (-whatif and -confirm switches)

			.PARAMETER FullName
			The File to compress specified by its full name

			.PARAMETER TimeoutSec
			An optional timeout in seconds for the compression operation. (default value : 600. Range : 1-3600) 
		
			.PARAMETER SleepingTimeSec
			An optional sleeping time in seconds between two checks to see if the file has been copied in the archive file. (default value : 1. Range : 1-5) 
		
			.PARAMETER PreserveLastWriteTime
			An optional switch to set the last write time of the zip file to the same value that the source file
		
			.PARAMETER Force
			An optional switch to specify if we overwrite the previously existing zip file (if any)
		
			.EXAMPLE
			"C:\inetpub\logs\LogFiles\W3SVC1\u_ex160101.log" | Compress-File -WhatIf -Verbose
			Compress the iis log file (1st January 2016) of the "Default Web Site" (W3SVC1). The verbose mode and the risk mitigation mode (-whatif) are enabled

			.EXAMPLE
			Compress-File -FullName "C:\inetpub\logs\LogFiles\W3SVC1\u_ex160101.log", "C:\inetpub\logs\LogFiles\W3SVC1\u_ex160102.log"
			Compress two IIS log files (1st and 2nd January 2016) of the "Default Web Site" (W3SVC1)

			.EXAMPLE
			Get-ChildItem -Path "C:\inetpub\logs\LogFiles\W3SVC1" -Filter "*.log" | Compress-File -Verbose -Force
			Compress all IIS log files of the "Default Web Site" (W3SVC1) and overwrite any previously existing destination zip file
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param
	(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript( {
				Test-Path -Path $_ -PathType Leaf
			})]
		[String[]]$FullName,

		[Parameter(Mandatory = $False)]
		[ValidateRange(1, 3600)]
		[int]$TimeoutSec = 600,

		[Parameter(Mandatory = $False)]
		[ValidateRange(1, 5)]
		[int]$SleepingTimeSec = 1,
		
		[switch]$PreserveLastWriteTime,

		[switch]$Force
	)
	begin {
		#The collection of returned files.
		$CompressedFiles = @()
	}
    
	process {
		foreach ($CurrentFullName in $FullName ) {
			$File = Get-Item -Path $CurrentFullName
			# Write-Verbose -Message "Processing $File ..."
			if ($File.Extension -ne '.zip') {
				$ZipFileName = $File.FullName.replace($File.Extension, '.zip')
				if (Test-Path -Path $ZipFileName -PathType Leaf) {
					if ($Force) {
						Write-Verbose -Message "The $ZipFileName already exists and will be overwritten ..."
						If ($pscmdlet.ShouldProcess($ZipFileName, 'Removing')) {
							Remove-Item -Path $ZipFileName -Force
						}
					}
					else {
						Write-Warning -Message "The $ZipFileName already exists and won't be overwritten (-Force not specified) ..."
						continue
					}
				}
				If ($pscmdlet.ShouldProcess($CurrentFullName, 'Compressing')) {
					Set-Content -Path $ZipFileName -Value ('PK' + [char]5 + [char]6 + ("$([char]0)" * 18))
					$ShellApplication = New-Object -ComObject Shell.Application
					$ZipObject = $ShellApplication.NameSpace($ZipFileName)
					$ZipObject.CopyHere($CurrentFullName)
					# Write-Verbose -Message "Item Number in the $ZipFileName file : $($ZipObject.Items().count)"
					$WaitTimeSec = 0
					While ($null -eq ($ZipObject.Items().Item($File.name)) -and ($WaitTimeSec -lt $TimeoutSec)) {
						Write-Verbose -Message "Sleeping $SleepingTimeSec second(s) (Copy in progress : $CurrentFullName ==> $ZipFileName) ..."
						Start-Sleep -Seconds $SleepingTimeSec
						$WaitTimeSec += $SleepingTimeSec
					}
					if ($ZipObject.Items().Item($File.name)) {
						# Write-Verbose -Message "Item Number in the $ZipFileName file : $($ZipObject.Items().count)"
						Write-Host -Object "$File is now compressed into the $ZipFileName file"
						$ZipFile = (Get-Item -Path $ZipFileName)
						if ($PreserveLastWriteTime) {
							$ZipFile.LastWriteTime = $File.LastWriteTime
							Write-Verbose -Message "Last Write Time of $ZipFileName set to : $($ZipFile.LastWriteTime) ..."
						}
						$CompressedFiles += $ZipFile
					}
					else {
						Write-Warning -Message "Timeout reached ($TimeoutSec seconds). A potential error occured during the compression of the $CurrentFullName file (Asynchronous operation)"
					}
					Remove-Ref -ref ($ShellApplication)
				}
			}
			else {
				Write-Verbose -Message "The $File has a .zip extension and won't be compressed ..."
			}
		}
	}
	end {
		return $CompressedFiles
	}
}

function Compress-FileV5 {
	<#
			.SYNOPSIS
			Compress a file in the zip format by using a Windows native feature.
			This function supports the risk mitigation mode (-whatif and -confirm switches)

			.DESCRIPTION
			Compress a file in the zip format by using a Windows native feature.
			This function supports the risk mitigation mode (-whatif and -confirm switches)

			.PARAMETER FullName
			The File to compress specified by its full name

			.PARAMETER PreserveLastWriteTime
			An optional switch to set the last write time of the zip file to the same value that the source file
		
			.PARAMETER Force
			A switch to specify if we overwrite the previously existing zip file (if any)
		
			.EXAMPLE
			"C:\inetpub\logs\LogFiles\W3SVC1\u_ex160101.log" | Compress-FileV5 -WhatIf -Verbose
			Compress the iis log file (1st January 2016) of the "Default Web Site" (W3SVC1). The verbose mode and the risk mitigation mode (-whatif) are enabled

			.EXAMPLE
			Compress-FileV5 -FullName "C:\inetpub\logs\LogFiles\W3SVC1\u_ex160101.log", "C:\inetpub\logs\LogFiles\W3SVC1\u_ex160102.log"
			Compress two IIS log files (1st and 2nd January 2016) of the "Default Web Site" (W3SVC1)

			.EXAMPLE
			Get-ChildItem -Path "C:\inetpub\logs\LogFiles\W3SVC1" -Filter "*.log" | Compress-FileV5 -Verbose -Force
			Compress all IIS log files of the "Default Web Site" (W3SVC1) and overwrite any previously existing destination zip file
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param
	(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript( {
				Test-Path -Path $_ -PathType Leaf
			})]
		[String[]]$FullName,

		[switch]$PreserveLastWriteTime,
		
		[switch]$Force
	)
	begin {
		#The collection of returned files.
		$CompressedFiles = @()
	}
    
	process {
		foreach ($CurrentFullName in $FullName ) {
			$File = Get-Item -Path $CurrentFullName
			Write-Verbose -Message "Processing $File ..."
			if ($File.Extension -ne '.zip') {
				$ZipFileName = $File.FullName.replace($File.Extension, '.zip')
				if (Test-Path -Path $ZipFileName -PathType Leaf) {
					if ($Force) {
						Write-Verbose -Message "The $ZipFileName already exists and will be overwritten ..."
						If ($pscmdlet.ShouldProcess($ZipFileName, 'Removing')) {
							Remove-Item -Path $ZipFileName -Force
						}
					}
					else {
						Write-Warning -Message "The $ZipFileName already exists and won't be overwritten (-Force not specified) ..."
						continue
					}
				}
				If ($pscmdlet.ShouldProcess($CurrentFullName, 'Compressing')) {
					Compress-Archive -LiteralPath $CurrentFullName -CompressionLevel Optimal -DestinationPath $ZipFileName
					#Testing if the compression was successful
					if ($?) {
						Write-Host -Object "$File is now compressed into the $ZipFileName file"
						$ZipFile = (Get-Item -Path $ZipFileName)
						if ($PreserveLastWriteTime) {
							$ZipFile.LastWriteTime = $File.LastWriteTime
							Write-Verbose -Message "Last Write Time of $ZipFileName set to : $($ZipFile.LastWriteTime) ..."
						}
						$CompressedFiles += $ZipFile
					}
					else {
						Write-Error -Message "An error occured during the compression of the $CurrentFullName file"
					}
				}
			}
			else {
				Write-Verbose -Message "The $File has a .zip extension and won't be compressed ..."
			}
		}
	}
	end {
		return $CompressedFiles
	}
}
#endregion

Clear-Host
# Generates 100 fake log files (one log file per day) with custom content (adding custom fields) for every hosted web sites.
$NewIISLogFiles = Get-Website | New-IISLogFile -Verbose -Days 100 -Custom

# The 11 following lines are a good example to show you how to keep an history of the 30 newest IIS log files (an IIS log file per day/site): the 10 newest are in the orginal clear text format and the others are compressed.
# Returns a collection of files contained in the IIS log folder (*.*) older than 30 days for every hosted web sites.
$IISLogFiles = Get-Website | Get-IISLogFile -All -Verbose -OlderThanXDays 30
# Remove these files
$IISLogFiles | Remove-Item -Force -Verbose 

# Returns a collection of IIS log files (*.log only) older than 10 days for every hosted web sites.
$IISLogFiles = Get-Website | Get-IISLogFile -Verbose -OlderThanXDays 10
# Compresses these files, set the last write time of the compressed file to the last write time of the source file and returns a collection of the compressed files
$CompressedFiles = $IISLogFiles | Compress-File -Force -Verbose -PreserveLastWriteTime
# Removes the non-compressed files (to keep only those compressed at the previous line)
$IISLogFiles | Remove-Item -Force -Verbose 


# Generates 100 fake log files (one log file per day) for the "Default Web site", "www.contoso.com" web sites with the ANSI encoding in verbose mode. Previously existing log files will be overwritten
# $NewIISLogFiles = New-IISLogFile -Days 100 -Encoding ANSI -WebSite "Default Web site", "www.contoso.com" -Force -Verbose 

# Generates 30 fake log files (one log file per day) for the "Default Web site" web site. The size of every log file will be set to 10MB
# $NewIISLogFiles = New-IISLogFile -Force -Verbose -Days 30 -WebSite "Default Web site" -Size 10MB

# Returns a collection of files contained in the IIS log folder (*.*) older than 2 months ago for every hosted web sites.
# $IISLogFiles = Get-Website | Get-IISLogFile -All -Verbose -OlderThanThisDate $((Get-Date).AddMonths(-2))

# Compresses these files with a timeout of 5 minutes (300 seconds) and a sleeping time of 10 seconds between each check, sets the last write time of the compressed file to the last write time of the source file and returns a collection of the compressed files
# $CompressedFiles = $IISLogFiles | Compress-File -Force -Verbose -TimeoutSec 300 -SleepingTimeSec 10 -PreserveLastWriteTime

# Compresses these files by using the built-in feature available since PowerShell 5.0
# $CompressedFiles = $IISLogFiles | Compress-FileV5 -Force -Verbose

# Returns a collection of IIS log files (*.log only) older than the date "05/18/2016 01:40:00" for "Default Web Site" web site.
# $IISLogFiles = Get-Website -Name "Default Web Site" | Get-IISLogFile -Verbose -OlderThanThisDate "05/18/2016 01:40:00"
# Compresses these files and overwrite previously existing .zip files, set the last write time of the compressed file to the last write time of the source file and returns a collection of the compressed files
# $CompressedFiles = $IISLogFiles | Compress-File -Force -Verbose -PreserveLastWriteTime

# Returns a collection of IIS log files (*.log only) older than the date "05/18/2016 01:40:00" for "Default Web Site" and "www.contoso.com" web sites.
# $IISLogFiles = "Default Web Site", "www.contoso.com" | Get-IISLogFile -Verbose -OlderThanThisDate "05/18/2016 01:40:00"
# Compresses these files and overwrite previously existing .zip files in whatif mode (the returned collection will be empty)
# $CompressedFiles = $IISLogFiles | Compress-File -Force -Verbose -WhatIf