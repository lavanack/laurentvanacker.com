#requires -version 2 
#Remove the following line if you run this script from PS v2 or v3
#Requires -RunAsAdministrator

#region My function definitions
#Function for releasing a COM object
Function Release-Ref {
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
			$Excel=new-object -ComObject "Excel.Application"
			...
			Release-Ref($Excel)
	#>
	Remove-Variable -Name $ref -ErrorAction SilentlyContinue | Out-Null
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) { 
 }
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}

#Function to test if the current PowerShell version is 2.0 
function Test-PowerShellv2 {
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

function Get-LastModified {
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
		[Parameter(Mandatory = $True)]
		[String]$URI
	)
	try {
		$Response = Invoke-WebRequest -Method Head -Uri $URI
		$LastModified = $Response.Headers.'Last-Modified'
		if ($LastModified) {
			return [datetime]$LastModified
		}
		else {
			Write-Warning -Message "Unable to get the last modification time for $URI"
			return $null
		}
	}
	catch {
		Write-Warning -Message "An exception occured : $($_.Exception.Message)"
		return $null
	}
}

function Get-LastModifiedv2 {
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
		[Parameter(Mandatory = $True)]
		[String]$URI
	)
	try {
		$WebRequest = [System.Net.HttpWebRequest]::Create($URI);
		$WebRequest.Method = 'HEAD';
		$WebResponse = $WebRequest.GetResponse()
		$LastModified = $WebResponse.LastModified
		if ($LastModified) {
			return [datetime]$LastModified
		}
		else {
			Write-Warning -Message "Unable to get the last modification time for $URI"
			return $null
		}	
	}
	catch {
		Write-Warning -Message "An exception occured : $($_.Exception.Message)"
		return $null
	}
}

#Function to download the required Cabinet files
function Get-CabinetFile {
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
			$CabURIs | Get-CabinetFile -Destination C:\Temp\CabDir -Verbose

			.EXAMPLE
			$CabURIs = @('http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab', 'http://update.microsoft.com/redist/wuredist.cab', 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab')
			Get-CabinetFile -URI $CabURIs -Destination C:\Temp\CabDir -Verbose
	#>
	[CmdletBinding()]
	Param(
		#The URIs of the cabinet files to download
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,
		
		#The destination folder
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination,

		#To force the download even if the local cabinet files are up-to-date
		[parameter(Mandatory = $false)]
		[switch]$Force
	)
	begin {
	}
	process {
		#For all URIs passed as argument outside a pipeline context
		Foreach ($CurrentURI in $URI) {
			Write-Verbose -Message "Processing $CurrentURI"
			#If the host is running Powershell 2.0
			if (Test-PowerShellv2) {
				$LastModified = Get-LastModifiedv2($CurrentURI)
			}
			else {
				$LastModified = Get-LastModified($CurrentURI)
			}
			Write-Verbose -Message "Last Modification Time : $LastModified"
			#$File = Split-Path $CurrentURI -Leaf
			$File = ($CurrentURI -split ('/'))[-1]
			New-Item -Path $Destination -ItemType Directory -Force | Out-Null
			$DestinationFile = Join-Path -Path $Destination -ChildPath $File
			if (Test-Path -Path $DestinationFile) {
				$LastWriteTime = $(Get-Item -Path $DestinationFile).LastWriteTime
			}
			If (($Force) -or (!(Test-Path -Path $DestinationFile)) -or ($LastWriteTime -lt $LastModified)) {
				If ($Force) {
					Write-Verbose -Message "[Force] Downloading $CurrentURI ..."
				}	
				ElseIf (!(Test-Path -Path $DestinationFile)) {
					Write-Verbose -Message "[Normal] Downloading $CurrentURI ..."
				}	
				ElseIf ($LastWriteTime -lt $LastModified) {
					Write-Verbose -Message "Last Write Time : $LastWriteTime)"
					Write-Verbose -Message "[Update] Downloading $CurrentURI ..."
				}	
				Write-Verbose -Message "The destination will be $DestinationFile"
				try {
					if (Test-PowerShellv2) {
						$Webclient = New-Object -TypeName System.Net.WebClient
						$WebClient.DownloadFile($CurrentURI, $DestinationFile)
						$WebClient.Dispose()
						Release-Ref($Webclient) 
					}
					else {
						Start-BitsTransfer -Source $CurrentURI -Destination $DestinationFile -ErrorAction Stop
					}
				}
				catch {
					Write-Warning -Message "An exception occured : $($_.Exception.Message)"
					return $null
				}
			}
			else {
				Write-Verbose -Message "Last Write Time : $LastWriteTime"
				if ($LastWriteTime) {
					Write-Host -Object "[Skip] $DestinationFile is up-to-date ..."
				}
			}		
		}		
	}	
	end {
	}
}

function Get-MissingHotFix {
	<#
			.SYNOPSIS
			Runs a local WUA Scan and sends the results to 2 CSV files. The first one with a summary (missing hotfixes per category), the second one with the details of all missing hotfixes

			.DESCRIPTION
			Runs a local WUA Scan and sends the results to 2 CSV files. The first one with a summary (missing hotfixes per category), the second one with the details of all missing hotfixes

			.PARAMETER Destination
			The destination folder  of the CSV files

			.PARAMETER CabDir
			The folder containing the required cabinet files
			
			.EXAMPLE
			Get-MissingHotFix -Destination C:\WUAScan\CSV -CabDir C:\WUAScan\CabDir -Verbose
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript( { Test-Path -Path $_ -PathType Container })]
		[String]$Destination,

		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript( { Test-Path -Path $_ -PathType Container })]
		[String]$CabDir
	)
	begin {
		$WSUSSCN2FullName = Join-Path -Path $CabDir -ChildPath 'wsusscn2.cab'
		if (-not(Test-Path -Path $WSUSSCN2FullName)) {
			Write-Error -Message "$WSUSSCN2FullName not found"-ErrorAction Stop
		}
	}
	process {
		$UpdateSession = New-Object -ComObject Microsoft.Update.Session 
		$UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager 
		$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $WSUSSCN2FullName, 1) 
		$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()  
 
		Write-Host -Object "Getting Update Informations for $env:ComputerName ..."
 
		$UpdateSearcher.ServerSelection = 3 #ssOthers 
		$UpdateSearcher.SearchScope = 1 # MachineOnly
		$UpdateSearcher.ServiceID = [string]$UpdateService.ServiceID 
 
		Write-Verbose -Message "Running the Update Searcher"
		$Criteria = "IsInstalled=0 and DeploymentAction='Installation' or IsPresent=1 and DeploymentAction='Uninstallation' or IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"          
		$SearchResult = $UpdateSearcher.Search($Criteria)
 
		$Updates = $SearchResult.Updates 
 
		if ($Updates.Count -eq 0) { 
			Write-Host "There are no applicable updates." 
			return $null 
		}
		else {
			$CSVFile = Join-Path -Path $Destination -ChildPath "$($env:ComputerName)_WUA_Details.csv"
			$Details = @()
			foreach ($CurrentUpdate in $Updates) {
				$CurrentDetail = $CurrentUpdate | Select-Object -Property @{Name = 'ComputerName'; Expression = { $env:ComputerName } }, Title, @{Name = 'Categories'; Expression = { $_.Categories[0].Name } }, Description, LastDeploymentChangeTime, @{Name = 'MoreInfoUrls'; Expression = { $_.MoreInfoUrls } }, MsrcSeverity, @{Name = 'SecurityBulletinIDs'; Expression = { $_.SecurityBulletinIDs } }, SupportUrl, @{Name = 'KBArticleIDs'; Expression = { $_.KBArticleIDs } }
				$Details += $CurrentDetail
			}

			$Details | Sort-Object -Property Title | Export-Csv -Path $CSVFile -Force -NoTypeInformation
			Write-Verbose -Message "The WUA Scan details are available into the $CSVFile file."
		}
 
	}
	end {
	}
}

#endregion


Clear-Host
Import-Module -Name BitsTransfer -ErrorAction SilentlyContinue

$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$CabDir = Join-Path -Path $CurrentDir -ChildPath 'CabFiles'
$null = New-Item -ItemType Directory -Path $CabDir -Force

$CabURIs = @('http://update.microsoft.com/v9/microsoftupdate/redir/MUAuth.cab', 'http://update.microsoft.com/redist/wuredist.cab', 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab')

# To download the cabinet files over the Internet (Internet connection required)
#$CabURIs | Get-CabinetFile -Destination $CabDir -Verbose
Get-CabinetFile -URI $CabURIs -Destination $CabDir -Verbose #-Force

# To run a missing hotfix scan by using WUA
Get-MissingHotFix -Destination $CurrentDir -CabDir $CabDir -Verbose