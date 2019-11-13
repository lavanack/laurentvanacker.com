#requires -version 2

#region function definitions
Function Get-NetExceptionsRate
{
	<#
			.SYNOPSIS
			Return performance counters data by extracting only the .NET CLR Exceptions/(*w3wp*)\# of Exceps Thrown / sec and ASP.NET Applications\(*_LM_W3SVC_*)\Requests/Sec when the 5 percent threshold is exceeded.

			.DESCRIPTION
			Return performance counters data by extracting only the .NET CLR Exceptions/(*w3wp*)\# of Exceps Thrown / sec and ASP.NET Applications\(*_LM_W3SVC_*)\Requests/Sec when the 5 percent threshold is exceeded.

			.PARAMETER FullName
			The BLG File to analyze specified by its full name

			.PARAMETER Full
			A switch to specify if we return all the data (threshold exceeded or not)

			.EXAMPLE
			Get-ChildItem "*.blg" | Get-NetExceptionsRate -Verbose
	#>
	[CmdletBinding(DefaultParameterSetName = 'Global', SupportsShouldProcess = $true)]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
		#The BLG File to convert : Checking if the file exists and has the .BLG extension
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.blg$')
		})]
		[alias('Source', 'BLG')]
		[String[]]$FullName,

		#To list all timestamp even if the 5 percent is not exceeded"
		[parameter(Mandatory = $false)]
		[switch]$Full,
		
		# For ASP.Net 2.0
		[Parameter(ParameterSetName = 'ASPNetV2')]
		[switch]$v2,        

		# For ASP.Net 4.0
		[Parameter(ParameterSetName = 'ASPNetV4')]
		[switch]$v4        
	)
	begin
	{
		#Array for storing the results
		$Data = @()
	}	
	process
	{
		#For all files passed as argument outside a pipeline context
		ForEach ($CurrentFullName in $FullName)
		{
			$CurrentFullName = Get-Item -Path $CurrentFullName
			$SourceBLGFullName = $CurrentFullName.FullName
			Write-Host -Object "Processing $SourceBLGFullName ..."

			# Keeping only '.NET CLR Exceptions', 'ASP.NET Applications', 'ASP.NET Apps v2.0.50727' and 'ASP.NET Apps v4.0.30319' performance counter names
			Write-Verbose -Message 'Extracting .Net Performance Data ...'
			$CounterNames = Import-Counter -Path $SourceBLGFullName  -Listset '.NET CLR Exceptions', 'ASP.NET Applications', 'ASP.NET Apps v2.0.50727', 'ASP.NET Apps v4.0.30319' -ErrorAction SilentlyContinue |
			Select-Object -ExpandProperty PathsWithInstances |
			Where-Object -FilterScript {
				($_ -like '*w3wp*)\# of Exceps Thrown / sec') -or ($_ -like '*_LM_W3SVC_*)\Requests/Sec')
			}

			#Importing only the required performance counters"
			$Counters = $(Import-Counter -Path $SourceBLGFullName -Counter $CounterNames -ErrorAction SilentlyContinue)
			
			#Getting the computer list (if data have been collected remotely for multiple servers)
			$ServerNames = $Counters.countersamples |
			ForEach-Object -Process {
				$_.path.split('\')[2] 
			} |
			Select-Object -Unique

			# Adding the computername as a member of the performance counters
			$Counters.countersamples | ForEach-Object -Process {
				$_ | Add-Member -MemberType NoteProperty -Name 'ServerName' -Value $($_.path.split('\')[2])
			}

			#Processing loop for each server
			ForEach ($CurrentServerName in $ServerNames) 
			{
				Write-Verbose -Message "Processing performance counter for $($CurrentServerName) ..."

				#Getting the performance couter list for the processed server
				$CurrentCounters  = $($CounterNames | Where-Object -FilterScript {
						$_ -like "*$CurrentServerName*"
				}) -join ', '
				Write-Verbose -Message "Processing the following counters : $CurrentCounters"
				
				$Counters | ForEach-Object -Process {
					$Timestamp = $_.Timestamp
					#If we work only for ASP.Net v2
					if ($v2)
					{
						#Getting the ASP.Net Request/Sec performance counters for every web applications
						$ASPNetAppsV2RequestPerSecCounters = ($_.CounterSamples | Where-Object -FilterScript {
								($_.Path -like '*ASP.NET Apps v2.0.50727*') -and ($_.InstanceName -like '*_LM_W3SVC_*') -and ($_.ServerName -eq $CurrentServerName ) 
						})
						$ASPNetAppsV2RequestPerSec = ($ASPNetAppsV2RequestPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum

						# If at least one ASP.NET Apps v2.0.50727 request
						if ($ASPNetAppsV2RequestPerSec -gt 0)
						{
							#Getting the .NET CLR Exceptions Exceptions Thrown/Sec performance counters for every worker process
							$NetClrExceptionsThrownPerSecCounters = $_.CounterSamples | Where-Object -FilterScript {
								($_.InstanceName -like '*w3wp*') -and ($_.ServerName -eq $CurrentServerName ) 
							}
							$NetClrExceptionsThrownPerSec = ($NetClrExceptionsThrownPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum
							#We calculate the rate
							$Percent = $NetClrExceptionsThrownPerSec/$ASPNetAppsV2RequestPerSec*100
							#If this rate exceeds the 5% percent threshold
							if ($Percent -ge 5)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] More than 5 percent of ASP.NET Apps v2.0.50727\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetAppsV2RequestPerSec)
								#Building an object to store the data
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetAppsV2RequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $true
								}
								#Adding this data to the data array
								$Data += $CurrentData
							}
							#If the -full switch has been specified we even store the data
							elseif ($Full)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] Less than 5 percent of ASP.NET Apps v2.0.50727\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetAppsV2RequestPerSec)
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetAppsV2RequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $false
								}
								$Data += $CurrentData
							}
						}
						#IF no ASP.Net v2 request but -full switch has been specified we write a verbose message
						elseif ($Full)
						{
							Write-Verbose -Message "[$($_.TimeStamp)] No ASP.NET Apps v2.0.50727 Request "
						}
					}
					#If we work only for ASP.Net v4
					elseif ($v4)
					{
						#Getting the ASP.Net Request/Sec performance counters for every web applications
						$ASPNetAppsV4RequestPerSecCounters = ($_.CounterSamples | Where-Object -FilterScript {
								($_.Path -like '*ASP.NET Apps v4.0.30319*') -and ($_.InstanceName -like '*_LM_W3SVC_*') -and ($_.ServerName -eq $CurrentServerName ) 
						})
						$ASPNetAppsV4RequestPerSec = ($ASPNetAppsV4RequestPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum
						# If at least one ASP.NET Apps v4.0.30319 request
						if ($ASPNetAppsV4RequestPerSec -gt 0)
						{
							#Getting the .NET CLR Exceptions Exceptions Thrown/Sec performance counters for every worker process
							$NetClrExceptionsThrownPerSecCounters = $_.CounterSamples | Where-Object -FilterScript {
								($_.InstanceName -like '*w3wp*') -and ($_.ServerName -eq $CurrentServerName ) 
							}
							$NetClrExceptionsThrownPerSec = ($NetClrExceptionsThrownPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum
							#We calculate the rate
							$Percent = $NetClrExceptionsThrownPerSec/$ASPNetAppsV4RequestPerSec*100
							#If this rate exceeds the 5% percent threshold
							if ($Percent -ge 5)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] More than 5 percent of ASP.NET Apps v4.0.30319\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetAppsV4RequestPerSec)
								#Building an object to store the data
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetAppsV4RequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $true
								}
								#Adding this data to the data array
								$Data += $CurrentData
							}
							#If the -full switch has been specified we even store the data
							elseif ($Full)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] Less than 5 percent of ASP.NET Apps v4.0.30319\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetAppsV4RequestPerSec)
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetAppsV4RequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $false
								}
								$Data += $CurrentData
							}
						}
						#IF no ASP.Net v4 request but -full switch has been specified we write a verbose message
						elseif ($Full)
						{
							Write-Verbose -Message "[$($_.TimeStamp)] No ASP.NET Apps v4.0.30319 Request "
						}
					}
					#Regarless the ASP.Net version
					else
					{
						#Getting the ASP.Net Request/Sec performance counters for every web applications
						$ASPNetApplicationsRequestPerSecCounters = ($_.CounterSamples | Where-Object -FilterScript {
								($_.Path -like '*ASP.NET Applications*') -and ($_.InstanceName -like '*_LM_W3SVC_*') -and ($_.ServerName -eq $CurrentServerName ) 
						})
						$ASPNetApplicationsRequestPerSec = ($ASPNetApplicationsRequestPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum
						# If at least one ASP.Net Applications request
						if ($ASPNetApplicationsRequestPerSec -gt 0)
						{
							#Getting the .NET CLR Exceptions Exceptions Thrown/Sec performance counters for every worker process
							$NetClrExceptionsThrownPerSecCounters = $_.CounterSamples | Where-Object -FilterScript {
								($_.InstanceName -like '*w3wp*') -and ($_.ServerName -eq $CurrentServerName ) 
							}
							$NetClrExceptionsThrownPerSec = ($NetClrExceptionsThrownPerSecCounters | Measure-Object -Property CookedValue -Sum).Sum
							#We calculate the rate
							$Percent = $NetClrExceptionsThrownPerSec/$ASPNetApplicationsRequestPerSec*100
							#If this rate exceeds the 5% percent threshold
							if ($Percent -ge 5)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] More than 5 percent of ASP.NET Applications\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetApplicationsRequestPerSec)
								#Building an object to store the data
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetApplicationsRequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $true
								}
								#Adding this data to the data array
								$Data += $CurrentData
							}
							#If the -full switch has been specified we even store the data
							elseif ($Full)
							{
								Write-Verbose -Message $("[$($_.TimeStamp)] Less than 5 percent of ASP.NET Applications\Requests/sec are .NET exceptions. The Rate is {0:N2}% ({1:N2}/{2:N2})" -f $Percent, $NetClrExceptionsThrownPerSec, $ASPNetApplicationsRequestPerSec)
								$CurrentData = New-Object -TypeName PSObject -Property @{
									SourceBLGFullName               = $SourceBLGFullName
									ServerName                      = $CurrentServerName
									Timestamp                       = $Timestamp
									NetClrExceptionsThrownPerSec    = $NetClrExceptionsThrownPerSec
									ASPNetApplicationsRequestPerSec = $ASPNetApplicationsRequestPerSec
									Percent                         = $Percent
									IsThreSholdExceeded             = $false
								}
								$Data += $CurrentData
							}
						}
						#IF no ASP.Net v4 request but -full switch has been specified we write a verbose message
						elseif ($Full)
						{
							Write-Verbose -Message "[$($_.TimeStamp)] No ASP.Net Applications Request "
						}
					}			
				}
			}
		}
	}
	end
	{
		#returning the data array
		return $Data
	}
}
#endregion


Clear-Host
# Getting the this script path
$CurrentScript = $MyInvocation.MyCommand.Path
# Getting the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent

# Building a timestamped CSV file with the same base name that with script
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '_'+$(Get-Date  -Format 'yyyyMMddTHHmmss')+'.csv')

# Analyzing .Net v2 performance for every BLG file in the current directory
#$Data = Get-ChildItem -Path $CurrentDir -Filter '*.blg' | Get-NetExceptionsRate -V2 -Verbose -Full

# Analyzing .Net v4 performance for every BLG file in the current directory
#$Data = Get-ChildItem -Path $CurrentDir -Filter '*.blg' | Get-NetExceptionsRate -V4 -Verbose -Full

# Analyzing .Net performance (regardless the version) for every BLG file in the current directory
$Data = Get-ChildItem -Path $CurrentDir -Filter '*.blg' | Get-NetExceptionsRate -Verbose -Full

#Exporting the data in the CSV file 
$Data | Export-Csv -Path $CSVFile -Force -NoTypeInformation
Write-Host -Object "Results are available in '$CSVFile'"