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

		Laurent VAN ACKER - laurent.vanacker@microsoft.com
#>
#requires -version 2

#region My function definitions
function Test-PowerShellv2
{
	<#
			.SYNOPSIS
			Tests if the current PowerShell version is 2.0 

			.DESCRIPTION
			Tests if the current PowerShell version is 2.0 

			.EXAMPLE
			Test-PowerShellv2
	#>
	return ($HOST.Version.Major -eq 2)
}

function Get-MBSAFiles
{
	<#
			.SYNOPSIS
			Downloads the cabinet files passed as parameter

			.DESCRIPTION
			Downloads the cabinet files passed as parameter

			.PARAMETER URI
			The URI(s) of the Cabinet file(s) to download

			.PARAMETER Destination
			The destination folder 

			.PARAMETER Force
			An optional switch specifying if we download the cabinet files even if they are up-to-date. By default only outdated cabinet files will be downloaded (based on the LastWriteTime property). 

			.EXAMPLE
			$CabURIs = @('http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab', 'http://update.microsoft.com/redist/wuredist.cab', 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab')
			$CabURIs | Get-MBSAFiles -Destination C:\Temp\CabDir -Verbose

			.EXAMPLE
			$CabURIs = @('http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab', 'http://update.microsoft.com/redist/wuredist.cab', 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab')
			Get-MBSAFiles -URI $CabURIs -Destination C:\Temp\CabDir -Verbose
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,
		
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination,

		[parameter(Mandatory=$false)]
		[switch]$Force
	)
	begin
	{
	}
	process
	{
		Foreach ($CurrentURI in $URI)
		{
			Write-Verbose -Message "Processing $CurrentURI"
			if (Test-PowerShellv2)
			{
				$LastModified=Get-LastModifiedv2($CurrentURI)
			}
			else
			{
				$LastModified=Get-LastModified($CurrentURI)
			}
			Write-Verbose -Message "Last Modification Time : $LastModified"
			#$File = Split-Path $CurrentURI -Leaf
			$File = ($CurrentURI -split('/'))[-1]
			New-Item -Path $Destination -ItemType Directory -Force | Out-Null
			$DestinationFile=Join-Path -Path $Destination -ChildPath $File
			
			If (($Force) -or (!(Test-Path -Path $DestinationFile)) -or ($(Get-Item -Path $DestinationFile).LastWriteTime -lt $LastModified))
			{
				If ($Force)
				{
					Write-Verbose -Message "[Force] Downloading $CurrentURI ..."
				}	
				ElseIf (!(Test-Path -Path $DestinationFile))
				{
					Write-Verbose -Message "[Normal] Downloading $CurrentURI ..."
				}	
				ElseIf ($(Get-Item -Path $DestinationFile).LastWriteTime -lt $LastModified)
				{
					Write-Verbose -Message "Last Write Time : $($(Get-Item -Path $DestinationFile).LastWriteTime)"
					Write-Verbose -Message "[Update] Downloading $CurrentURI ..."
				}	
				Write-Verbose -Message "The destination will be $DestinationFile"
				if (Test-PowerShellv2)
				{
					$Webclient = New-Object -TypeName System.Net.WebClient
					$WebClient.DownloadFile($CurrentURI, $DestinationFile)
					$WebClient.Dispose()
				}
				else
				{
					Start-BitsTransfer -Source $CurrentURI -Destination $DestinationFile
				}
			}
			else 
			{
				Write-Verbose -Message "Last Write Time : $($(Get-Item -Path $DestinationFile).LastWriteTime)"
				Write-Host -Object "[Skip] $DestinationFile is up-to-date ..."
			}		
		}		
	}	
	end
	{
	}
}

function Get-LastModified
{
	<#
			.SYNOPSIS
			Returns the 'Last-Modified' reponse header of the URI passed as parameter. This function relies on the Invoke-WebRequest available since PowerShell 3.0

			.DESCRIPTION
			Returns the 'Last-Modified' reponse header of the URI passed as parameter. This function relies on the Invoke-WebRequest available since PowerShell 3.0

			.PARAMETER URI
			The URI(s) to reach

			.EXAMPLE
			Get-LastModified -Uri 'http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab'
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$URI
	)

	$Response=Invoke-WebRequest -Method Head -Uri $URI
	$LastModified=$Response.Headers.'Last-Modified'
	if ($LastModified)
	{
		return [datetime]$LastModified
	}
	else
	{
		return $null
	}
}

function Get-LastModifiedv2
{
	<#
			.SYNOPSIS
			Returns the 'Last-Modified' reponse header of the URI passed as parameter. This function relies on a .Net Class so it is compatible with PowerShell 2.0

			.DESCRIPTION
			Returns the 'Last-Modified' reponse header of the URI passed as parameter. This function relies on a .Net Class so it is compatible with PowerShell 2.0

			.PARAMETER URI
			The URI(s) to reach

			.EXAMPLE
			Get-LastModifiedv2 -Uri 'http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab'
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$URI
	)

	$WebRequest = [System.Net.HttpWebRequest]::Create($URI);
	$WebRequest.Method = 'HEAD';
	$WebResponse = $WebRequest.GetResponse()
	$LastModified = $WebResponse.LastModified
	if ($LastModified)
	{
		return [datetime]$LastModified
	}
	else
	{
		return $null
	}	
}

function New-MBSAScan
{
	<#
			.SYNOPSIS
			Runs a local MBSA Scan and sends the results to 2 CSV files. The first one with a summary (missing hotfixes per category), the second one with the details of all missing hotfixes

			.DESCRIPTION
			Runs a local MBSA Scan and sends the results to 2 CSV files. The first one with a summary (missing hotfixes per category), the second one with the details of all missing hotfixes

			.PARAMETER Destination
			The destination folder  of the CSV files

			.PARAMETER CabDir
			The folder containing the required cabinet files
			
			.PARAMETER Detailed
			An optional switch specifying if we generate the CSV file with the details about the missing hotfixes. 

			.EXAMPLE
			New-MBSAScan -Destination C:\Temp\CSV -CabDir C:\Temp\CabDir -Detailed -Verbose
	#>
		[CmdletBinding()]
		Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path -Path $_ -PathType Container})]
		[String]$Destination,

		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path -Path $_ -PathType Container})]
		[String]$CabDir,

		[parameter(Mandatory=$false)]
		[switch]$Detailed
	)
	begin
	{
		$MBSACli = "$CurrentDir\MBSA\MBSACli.exe"
		$Severities=@{'0'='No Rating'; '1'='Low'; '2'='Moderate'; '3'='Important'; '4'='Critical'}
		$WSUSSCN2FullName=Join-Path -Path $CabDir -ChildPath 'wsusscn2.cab'
		$OSMajorVersion=[int][environment]::OSVersion.Version.Major
		if ($OSMajorVersion -ge 10)
		{
			Write-Error -Message "Not supported OS Version : $([environment]::OSVersion.Version)" -ErrorAction Stop
		}
		if (-not(Test-Path -Path $WSUSSCN2FullName))
		{
			Write-Error -Message "$WSUSSCN2FullName not found"-ErrorAction Stop
		}
	}
	process
	{
		Write-Host -Object "Getting Update Informations for $env:ComputerName ..."
		$XMLOutputFilePath = Join-Path -Path $Destination -ChildPath "$($env:ComputerName)_MBSA.xml"

		Write-Verbose -Message "Running the MBSA Client : $MBSACli /nd /wi /xmlout /nvc /catalog `"$WSUSSCN2FullName`" /unicode"
		Start-process -FilePath $MBSACli -ArgumentList "/nd /wi /xmlout /nvc /catalog `"$WSUSSCN2FullName`" /unicode" -RedirectStandardOutput $XMLOutputFilePath -Wait

		
		Write-Verbose -Message 'Processing XML Output'
		[xml]$Result = Get-Content -Path $XMLOutputFilePath
		$CatalogUpdates = @()
		$CatalogInfoFound = $False
		$Index=0
		$Result.XMLOut.ChildNodes | ForEach-Object {
			$Index++
			$CurrentNodeName = $_.Name
			Write-Progress -Activity "[$($Index)/$($Result.XMLOut.ChildNodes.Count)] Anaysing XML output ..." -status "Processing $CurrentNodeName Node ..." -PercentComplete ($Index /$Result.XMLOut.ChildNodes.Count * 100)
			if ($CurrentNodeName -eq 'CatalogInfo')
			{
				$CatalogInfoFound = $True
			}
			if (($CatalogInfoFound) -and ($CurrentNodeName -ne 'CatalogInfo'))
			{
				# Write-Host "Adding $CurrentNodeName ..."
				$CatalogUpdates += $_
			}
		}
		$Summary = $CatalogUpdates | Where-Object {$_.ID -eq 500} | Select-Object @{Name='ComputerName';Expression={$env:ComputerName}}, Name, Advice
		if ($Summary)
		{
			$SummaryCSVFile = Join-Path -Path $Destination -ChildPath "$($env:ComputerName)_MBSA_Summary.csv"
			$Summary | Export-Csv -Path $SummaryCSVFile -Force -NoTypeInformation
			Write-Verbose -Message "The MBSA Scan summary is available into the $SummaryCSVFile file."
		}

		if ($Detailed)
		{
			$DetailsCSVFile = Join-Path -Path $Destination -ChildPath "$($env:ComputerName)_MBSA_Details.csv"
			$Details = $CatalogUpdates | ForEach-Object { $CategoryName=$_.Name ; $_.Detail.UpdateData } | Where-Object {$_.IsInstalled -eq $False} | Select-Object @{Name='ComputerName';Expression={$env:ComputerName}}, @{Name='Category';Expression={$CategoryName}},ID, @{Name='Severity';Expression={$Severities[$_.Severity]}}, Title
			if ($Details)
			{
				$Details | Sort-Object -Property ID | Export-Csv -Path $DetailsCSVFile -Force -NoTypeInformation
				Write-Verbose -Message "The MBSA Scan details are available into the $DetailsCSVFile file."
			}
		}
	}
	end 
	{
	}
}
#endregion


Clear-Host
Import-Module -Name BitsTransfer -ErrorAction SilentlyContinue

$CurrentDir=Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$CabDir=Join-Path -Path $CurrentDir -ChildPath 'CabFiles'
New-Item -ItemType Directory -Path $CabDir -Force | Out-Null

$CabURIs = @('http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab', 'http://update.microsoft.com/redist/wuredist.cab', 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab')

$CabURIs | Get-MBSAFiles -Destination $CabDir -Verbose
#Get-MBSAFiles -URI $CabURIs -Destination $CabDir -Verbose

New-MBSAScan -Destination $CurrentDir -CabDir $CabDir -Detailed -Verbose
