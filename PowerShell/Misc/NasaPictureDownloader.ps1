
#requires -Version 4

#region function definitions
Function Release-Ref {
	param
	(
		[Object]
		$ref
	)

	Remove-Variable -Name $ref -ErrorAction SilentlyContinue | Out-Null
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {
 }
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}

Function Get-LastModifiedHeader {
	param
	(
		[String]$url
	)

	$xHTTP = New-Object -Com msxml2.xmlhttp
	$xHTTP.open('HEAD', $url, $false)
	try {
		$xHTTP.send()
		#$xHTTP.getAllResponseHeaders()
		$LastModified = $xHTTP.getResponseHeader('Last-Modified')
		Release-Ref($xHTTP) | Out-Null
		if ($LastModified) {
			return [datetime]$LastModified
		}
		else {
			return $null
		}
	}
	catch {
		Write-Host -Object "[ERROR] Unable to query $url from Internet ...." -Foreground Red
	}
	finally {
	}
}

Function Get-LastModifiedAndContentLengthHeaders {
	param
	(
		[String]$url
	)

	$xHTTP = New-Object -Com msxml2.xmlhttp
	$xHTTP.open('HEAD', $url, $false)
	try {
		$xHTTP.send()
		#$xHTTP.getAllResponseHeaders()
		$LastModified = $xHTTP.getResponseHeader('Last-Modified')
		$ContentLength = $xHTTP.getResponseHeader('Content-Length')
		Release-Ref($xHTTP) | Out-Null
		if ($LastModified) {
			$LastModified = [datetime]$LastModified
		}
		else {
			$LastModified = $null
		}
		if ($ContentLength) {
			$ContentLength = [long]$ContentLength
		}
		else {
			$ContentLength = 0
		}
	}
	catch {
		Write-Host -Object "[ERROR] Unable to query $url from Internet ...." -Foreground Red
		$LastModified = $null
		$ContentLength = 0
	}
	finally {
	}
	return New-Object -TypeName psobject -Property @{LastModified = $LastModified; ContentLength = $ContentLength }
}

Function Get-MissionNasaPictures {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Domain,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)

	$MissionNasaPictures = @()
	ForEach ($CurrentURI in $URI) {
		$PageNumber = 0
		$HasMoreRows = $true
		While ($HasMoreRows) {
			$RequestURI = $CurrentURI.Replace('[PAGENUMBER]', $PageNumber)
			Write-Verbose -Message "Processing the page : $($PageNumber) ..."

			Write-Host -Object "Processing the request : $($RequestURI) ..."
			$JSONResponse = Invoke-RestMethod -uri $RequestURI
			$HasMoreRows = ($JSONResponse.meta.total_rows -gt 0)

			if ($HasMoreRows) {
				$Nids = $JSONResponse.ubernodes.nid
				ForEach ($CurrentNid in $Nids) {
					Write-Verbose -Message "Processing the nid : $($CurrentNid) ..."
					$NidURI = "$Domain/api/1/record/node/$CurrentNid.json"
					Write-Host -Object "`tProcessing the request : $($NidURI ) ..."
					$JSONResponse = Invoke-RestMethod -uri $NidURI 
					try {
						$AlternativeText = $JSONResponse.images.alt
						$TextBody = $JSONResponse.ubernode.body
						$Title = $JSONResponse.ubernode.title
						$FullWidthImage = $Domain + $JSONResponse.images.fullWidthFeature
						$Caption = $JSONResponse.ubernode.imageFeatureCaption
						#$Caption = $Caption -replace "<[^>]*>",""

						Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
						Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
						Write-Verbose -Message "Text Body : $($TextBody) ..."
						Write-Verbose -Message "Caption : $($Caption) ..."
						Write-Verbose -Message "Title : $($Title) ..."

						$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
						$MissionNasaPictures += $CurrentNasaPicture
						Write-Verbose -Message "[$('{0:D5}' -f $($MissionNasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."
					}
					catch {
						Write-Host -Object "[ERROR] The JSON file $NidURI is not well formatted" -ForegroundColor Red
					}

				}
				$PageNumber++
			}
		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($MissionNasaPictures.Count) ..."
	return $MissionNasaPictures
}


Function Get-JPLNasaPictures {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)


	$JPLNasaPictures = @()
	ForEach ($CurrentURI in $URI) {
		$PageNumber = 1
		$More = $true
		While ($More) {
			$RequestURI = $CurrentURI.Replace('[PAGENUMBER]', $PageNumber)
			Write-Verbose -Message "Processing the page : $($PageNumber) ..."

			Write-Host -Object "Processing the request : $($RequestURI) ..."
			$JSONResponse = Invoke-RestMethod -uri $RequestURI
			$More = ($JSONResponse.more)

			if ($More) {
				$Items = $JSONResponse.items
				ForEach ($CurrentItem in $Items) {
					Write-Verbose -Message "Processing the item : $($CurrentItem.id) ..."
					$AlternativeText = $CurrentItem.images.full.alt
					$TextBody = $CurrentItem.body
					$Title = $CurrentItem.title
					$FullWidthImage = $CurrentItem.images.full.src
					$Caption = $CurrentItem.tease
					#$Caption = $Caption -replace "<[^>]*>",""

					Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
					Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
					Write-Verbose -Message "Text Body : $($TextBody) ..."
					Write-Verbose -Message "Caption : $($Caption) ..."
					Write-Verbose -Message "Title : $($Title) ..."

					$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
					$JPLNasaPictures += $CurrentNasaPicture
					Write-Verbose -Message "[$('{0:D5}' -f $($JPLNasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."

				}
				$PageNumber++
			}
		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($JPLNasaPictures.Count) ..."
	return $JPLNasaPictures
}


Function Get-AssetNasaPictures {
	[CmdletBinding()]
	Param(

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)

	$AssetNasaPictures = @()
	foreach ($CurrentURI in $URI) {
		Write-Host -Object "Processing the request : $($CurrentURI) ..."
		$Items = (Invoke-RestMethod -uri $CurrentURI).collection.items
		ForEach ($CurrentItem in $Items) {
			Write-Host -Object "`tProcessing the request : $($CurrentItem) ..."
			$JSONResponse = Invoke-RestMethod -uri $CurrentItem
			$FullWidthImage = $JSONResponse[0]
			$MetaData = $JSONResponse[-1]
			
			$JSONResponse = Invoke-RestMethod -uri $MetaData         
			if ($JSONResponse.GetType().fullName -eq 'System.String') {
				#Bug XMP:Createdate is duplicated : https://windowsserver.uservoice.com/forums/301869-powershell/suggestions/11088237-duplicate-keys-error-with-convertfrom-json
				$JSONResponse = $JSONResponse -creplace "`"XMP:Createdate`"\s*:\s*`"(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})`"\s*,", '' | ConvertFrom-Json
			}

			$AlternativeText = $null
			$TextBody = $JSONResponse.'AVAIL:Description'
			$Title = $JSONResponse.'AVAIL:Title'
			$Caption = $null

			Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
			Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
			Write-Verbose -Message "Text Body : $($TextBody) ..."
			Write-Verbose -Message "Caption : $($Caption) ..."
			Write-Verbose -Message "Title : $($Title) ..."

			$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
			$AssetNasaPictures += $CurrentNasaPicture
			Write-Verbose -Message "[$('{0:D5}' -f $($AssetNasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."

		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($AssetNasaPictures.Count) ..."
	return $AssetNasaPictures
}

Function Get-ApiNasaPictures {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)

	$ApiNasaPictures = @()
	ForEach ($CurrentURI in $URI) {
		$PageNumber = 1
		$HasMoreRows = $true
		
		While ($HasMoreRows) {

			$RequestURI = $CurrentURI.Replace('[PAGENUMBER]', $PageNumber)
			Write-Verbose -Message "Processing the page : $($PageNumber) ..."
			Write-Host -Object "Processing the request : $($RequestURI) ..."

			$JSONResponse = Invoke-RestMethod -uri $RequestURI
			$Items = $JSONResponse.collection.items
			$HasMoreRows = ($Items -ne $null)

			if ($HasMoreRows) {
				ForEach ($CurrentItem in $Items.href) {
					Write-Host -Object "`tProcessing the request : $($CurrentItem) ..."
					$JSONResponse = Invoke-RestMethod -uri $CurrentItem
					$FullWidthImage = $JSONResponse[0]
					$MetaData = $JSONResponse[-1]

					$JSONResponse = Invoke-RestMethod -uri $MetaData         
					$AlternativeText = $null
					$TextBody = $JSONResponse.'AVAIL:Description'
					$Title = $JSONResponse.'AVAIL:Title'
					$Caption = $null

					Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
					Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
					Write-Verbose -Message "Text Body : $($TextBody) ..."
					Write-Verbose -Message "Caption : $($Caption) ..."
					Write-Verbose -Message "Title : $($Title) ..."

					$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
					$ApiNasaPictures += $CurrentNasaPicture
					Write-Verbose -Message "[$('{0:D5}' -f $($ApiNasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."
				}
				$PageNumber++
			}
		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($ApiNasaPictures.Count) ..."
	return $ApiNasaPictures
}

Function Get-PlanetaryNasaPictures {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)

	$PlanetaryNasaPictures = @()
	ForEach ($CurrentURI in $URI) {
		$PageNumber = 1
		$HasMorePictures = $true
		
		While ($HasMorePictures) {
			$RequestURI = $CurrentURI.Replace('[PAGENUMBER]', $PageNumber)
			Write-Verbose -Message "Processing the page : $($PageNumber) ..."
			Write-Host -Object "Processing the request : $($RequestURI) ..."

			$Response = Invoke-WebRequest -uri $RequestURI -UseBasicParsing
			$Links = ($Response.Links | Where-Object { $_.href -like 'https://www.planetary.org/multimedia/space-images/*.html' })
			$HasMorePictures = ($Links -ne $null)

			if ($HasMorePictures) {
				ForEach ($CurrentLink in $Links.href) {
					Write-Host -Object "`tProcessing the request : $($CurrentLink) ..."
					$Response = Invoke-WebRequest -uri $CurrentLink -UseBasicParsing

					$Response.Content -match '<title>(?<title>.*)</title>' | Out-Null
					$Title = $Matches['title']

					$Response.Content -match '<meta name="twitter:description" content="(?<description>.*)"\s/>' | Out-Null
					$TextBody = $Matches['description']    

					$Response.Content -match '<meta name="twitter:image" content="(?<image>.*)"\s/>' | Out-Null
					$FullWidthImage = $Matches['image']    

					Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
					Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
					Write-Verbose -Message "Text Body : $($TextBody) ..."
					Write-Verbose -Message "Caption : $($Caption) ..."
					Write-Verbose -Message "Title : $($Title) ..."

					$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
					$PlanetaryNasaPictures += $CurrentNasaPicture
					Write-Verbose -Message "[$('{0:D5}' -f $($PlanetaryNasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."
				}
				$PageNumber++
			}
		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($PlanetaryNasaPictures.Count) ..."
	return $PlanetaryNasaPictures
}

Function Get-SDONasaPictures {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Domain,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String[]]$URI,

		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
		[ValidateNotNullOrEmpty()]
		[String]$Destination
	)


	$SDONasaPictures = @()
	foreach ($CurrentURI in $URI) {
		Write-Verbose -Message "Processing the page : $($PageNumber) ..."
		Write-Host -Object "Processing the request : $($CurrentURI) ..."

		$Response = Invoke-WebRequest -uri $CurrentURI -UseBasicParsing
		$Links = ($Response.Links | Where-Object { $_.href -like '/gallery/main/item/*' })

		ForEach ($CurrentLink in $Links.href) {

			$Response = Invoke-WebRequest -uri "$domain$CurrentLink" -UseBasicParsing
			$Response.Content -match '<title>(?<title>.*)</title>' | Out-Null
			$Title = $Matches['title']
			$Images = $Response.Images | Where-Object { ($_.src -like '*/assets/gallery/preview/*') }
			ForEach ($CurrentImage in $Images) {
			
				$FullWidthImage = $domain + $($CurrentImage.src)
				$AlternativeText = $CurrentImage.alt  
				$TextBody = $null
				$Caption = $null

				Write-Verbose -Message "Image to download : $($FullWidthImage) ..."
				Write-Verbose -Message "Alternative Text : $($AlternativeText) ..."
				Write-Verbose -Message "Text Body : $($TextBody) ..."
				Write-Verbose -Message "Caption : $($Caption) ..."
				Write-Verbose -Message "Title : $($Title) ..."

				$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ ImageURI = $FullWidthImage; AlternativeText = $AlternativeText; TextBody = $TextBody; Title = $title; Caption = $Caption; Destination = $Destination }
				$SDONasaPictures += $CurrentNasaPicture
				Write-Verbose -Message "[$('{0:D5}' -f $($SDONasaPictures.Count))] Adding the image $FullWidthImage to the image collection ..."
			}
		}
	}
	Write-Verbose -Message "End of processing. Image Number : $($SDONasaPictures.Count) ..."
	return $SDONasaPictures
}


Function Download-NasaPictures {
	[CmdletBinding()]
	Param(
		#The BLG File to convert
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $False)]
		[Object[]]$Images,

		[parameter(Mandatory = $false)]
		[switch]$Force,

		[parameter(Mandatory = $false)]
		[switch]$Asynchronous
	)
	begin {
		$MaxJobsPerUser = 200
		$Index = 0
		if ($Asynchronous) {
			$BitsDownloads = @()
		}
	}
	process {
		ForEach ($CurrentImage in $Images) {
			$CurrentImageURI = $CurrentImage.ImageURI
			$CurrentImageDestination = $CurrentImage.Destination
			If (!(Test-Path -Path $CurrentImageDestination)) {
				Write-Verbose -Message "Creating the $($CurrentImageDestination) folder to store downloaded data ..."
				New-Item -ItemType Directory -Path $CurrentImageDestination -Force | Out-Null
			}

			#$LastModified=Get-LastModifiedHeader -url $CurrentImageURI
			$LastModifiedAndContentLengthHeaders = Get-LastModifiedAndContentLengthHeaders -url $CurrentImageURI
			$LastModified = $LastModifiedAndContentLengthHeaders.LastModified
			$ContentLength = $LastModifiedAndContentLengthHeaders.ContentLength

			if (($ContentLength -le 0) -or ($ContentLength -eq $null)) {
				Write-Verbose -Message "[SKIP] $CurrentImageURI has a 0 Content-Length"
				continue
			}
			if ($LastModified -eq $null) {
				Write-Verbose -Message "[SKIP] Unable to get the last modified date for : $CurrentImageURI"
				continue
			}
			
			$Tokens = $CurrentImage.ImageURI.Split('/')
			#$LastModified=Get-LastModifiedHeader -url $CurrentImageURI
			$CurrentImageFileName = $Tokens[$Tokens.Count - 1] -replace '\?.*', ''
			$CurrentImageFullPath = Join-Path -Path $CurrentImageDestination -childPath $CurrentImageFileName

			Write-Verbose -Message "`$LastModified : $LastModified ..."
			Write-Verbose -Message "`$ContentLength : $ContentLength ..."

			$Index++
			Write-Verbose -Message "Processing $CurrentImageURI ..."
	        
			If (($Force) -or (!(Test-Path -Path $CurrentImageFullPath)) -or ($(Get-Item -Path $CurrentImageFullPath).LastWriteTime -lt $LastModified)) {
				if ($Asynchronous) {
					If ($Force) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Asynchronous][Force] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					ElseIf (!(Test-Path -Path $CurrentImageFullPath)) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Asynchronous][Normal] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					ElseIf ($(Get-Item -Path $CurrentImageFullPath).LastWriteTime -lt $LastModified) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Asynchronous][Update] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					$CurrentNasaPicture = New-Object -TypeName PSObject -Property @{ Source = $CurrentImageURI; Destination = $CurrentImageFullPath; ContentLength = $ContentLength }
					$BitsDownloads += $CurrentNasaPicture
					Write-Verbose -Message "[$('{0:D5}' -f $($BitsDownloads.Count))] Adding the $CurrentImageURI to the download list ..."
				}
				else {
					If ($Force) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Force] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					ElseIf (!(Test-Path -Path $CurrentImageFullPath)) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Normal] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					ElseIf ($(Get-Item -Path $CurrentImageFullPath).LastWriteTime -lt $LastModified) {
						Write-Verbose -Message "[$('{0:D5}' -f $Index)][Update] Downloading $CurrentImageURI into $CurrentImageFullPath ..."
					}	
					Start-BitsTransfer -Source $CurrentImageURI -Destination $CurrentImageFullPath -ErrorAction SilentlyContinue
				}

				$CurrentImageInfoFullPath = $CurrentImageFullPath -replace "\.(.*)$", '_info.txt'
				Write-Verbose -Message "Creating the picture information file : $CurrentImageInfoFullPath ..."
				$Text = ''
				$Text += 'Alternative Text : ' + $CurrentImage.AlternativeText + "`r`n"
				$Text += 'Text Body : ' + $CurrentImage.TextBody + "`r`n"
				$Text += 'Title : ' + $CurrentImage.Title + "`r`n"
				$Text += 'Caption : ' + $CurrentImage.Caption + "`r`n"
				$Text += 'URI : ' + $CurrentImage.ImageURI + "`r`n"
				$Text | Out-File -FilePath ($CurrentImageInfoFullPath)
			}
			else {
				Write-Verbose -Message "[$('{0:D5}' -f $Index)][Skip] Downloading $CurrentImageURI because $CurrentImageFullPath is up-to-date ..."
			}
		}
	}
	end {
		if ($Asynchronous) {
			$BitsDownloadsCSVFile = Join-Path -Path $CurrentDir -ChildPath $('BitsDownloads.csv')
			$BitsDownloads | Export-Csv -Path $BitsDownloadsCSVFile -NoTypeInformation
			Write-Verbose -Message 'Runing asynchronous downloads ...'
			#https://msdn.microsoft.com/en-us/library/windows/desktop/ee663885(v=vs.85).aspx#to_create_a_synchronous_bits_transfer_job_with_multiple_files
			#https://www.jonathanmedd.net/2013/04/start-bitstransfer-submitting-greater-than-60-asynchronous-jobs-generates-error.html
			#https://www.computerstepbystep.com/limit-the-maximum-number-of-bits-jobs-for-each-user.html
			#https://www.computerstepbystep.com/limit-the-maximum-number-of-files-allowed-in-a-bits-CurrentBitsTransfer.html#PowerShellScript
			$BitsTransferred = 0
			$BitsError = 0
			$Index = 0
			$TotalContentLength = ($BitsDownloads.ContentLength | Measure-Object -Sum).sum
			$CurrentContentLength = 0
			ForEach ($CurrentBitsDownload in $BitsDownloads) {
				$Index++

				Write-Verbose -Message "`$CurrentContentLength : $CurrentContentLength"
				Write-Verbose -Message "`$TotalContentLength : $TotalContentLength"
				[int] $Percent = $CurrentContentLength / $TotalContentLength * 100
				Write-Progress -Id 1 -Activity "MBytes : $('{0:N2}' -f ($CurrentContentLength/1MB))/$('{0:N2}' -f ($TotalContentLength/1MB)) - Downloads Started : $($Index)/$($BitsDownloads.Count) - Downloads Completed : $BitsTransferred - Downloads Failed : $BitsError" -status 'In progress ...' -PercentComplete $Percent

				Start-BitsTransfer -Source $CurrentBitsDownload.Source -Destination $CurrentBitsDownload.Destination -Asynchronous | Out-Null
				$BitsTransfers = Get-BitsTransfer
				if ($BitsTransfers.Count -ge $MaxJobsPerUser) {
					Write-Verbose -Message "Limit for the maximum number of BITS jobs for each user reached : $MaxJobsPerUser. Waiting the end of some running jobs ..."
				}
				while ($BitsTransfers.Count -ge $MaxJobsPerUser) {
					
					$BitsTransfers = Get-BitsTransfer
					Foreach ($CurrentBitsTransfer in $BitsTransfers) {
						Switch ($CurrentBitsTransfer.JobState) {
							'Transferring' {
								break 
       }
							'Connecting' {
								break 
       }
							'Transferred' {
								$BitsTransferred++; $CurrentContentLength += $CurrentBitsTransfer.BytesTotal; Complete-BitsTransfer -BitsJob $CurrentBitsTransfer; break 
       }
							'Error' {
								Write-Host -Object "Error while downloading $($CurrentBitsTransfer.FileList.RemoteName) ..." -ForegroundColor Red; $CurrentBitsTransfer | Remove-BitsTransfer ; $BitsError++; break 
       }
							default {
								Write-Host -Object "Other action while downloading $($CurrentBitsTransfer.FileList.RemoteName) : $($CurrentBitsTransfer.ErrorDescription) ..." -ForegroundColor Red; $CurrentBitsTransfer | Remove-BitsTransfer ; $BitsError++; break
       }
						}
					}
					Start-Sleep -Second 1 
				}
			}
			Write-Verbose -Message 'Waiting the last asynchronous Bits transfers complete ...'
			$BitsTransfers = Get-BitsTransfer
			while ($BitsTransfers.Count -gt 0) {
				Write-Verbose -Message "`$CurrentContentLength : $CurrentContentLength"
				Write-Verbose -Message "`$TotalContentLength : $TotalContentLength"
				[int] $Percent = $CurrentContentLength / $TotalContentLength * 100
				Write-Progress -Id 1 -Activity "MBytes : $('{0:N2}' -f ($CurrentContentLength/1MB))/$('{0:N2}' -f ($TotalContentLength/1MB)) - Downloads Started : $($Index)/$($BitsDownloads.Count) - Downloads Completed : $BitsTransferred - Downloads Failed : $BitsError" -status 'In progress ...' -PercentComplete $Percent
				$BitsTransfers = Get-BitsTransfer
				Foreach ($CurrentBitsTransfer in $BitsTransfers) {
					Switch ($CurrentBitsTransfer.JobState) {
						'Transferring' {
							break
      }
						'Connecting' {
							break
      }
						'Transferred' {
							$BitsTransferred++; $CurrentContentLength += $CurrentBitsTransfer.BytesTotal; Complete-BitsTransfer -BitsJob $CurrentBitsTransfer; break 
      }
						'Error' {
							Write-Host -Object "Error while downloading $($CurrentBitsTransfer.FileList.RemoteName) ..." -ForegroundColor Red; $CurrentBitsTransfer | Remove-BitsTransfer ; $BitsError++; break 
      }
						default {
							Write-Host -Object "Other action while downloading $($CurrentBitsTransfer.FileList.RemoteName) : $($CurrentBitsTransfer.ErrorDescription) ..." -ForegroundColor Red; $CurrentBitsTransfer | Remove-BitsTransfer ; $BitsError++; break
      }
					}
				}
			}
			Write-Verbose -Message 'All asynchronous Bits transfers have completed ...'
			Write-Progress -Id 1 -Activity 'Completed !' -Completed
		}
	}
}
#endregion

$Missions = @{
	'Exploration Mission-1'       = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=12388&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'InSight Mars Lander'         = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3455&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'TESS Exoplanet Mission'      = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=5613&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Curiosity Mars Rover'        = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3643&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'New Horizons at Pluto'       = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3648&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'International Space Station' = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3456&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Mars Missions'               = 'https://www.nasa.gov/api/1/query/ubernodes.json?topics[]=3152&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Orion Spacecraft'            = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3212&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Space Launch System'         = @('https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3221&unType[]=image&page=[PAGENUMBER]&pageSize=24', 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=6954&unType[]=image&page=[PAGENUMBER]&pageSize=24');
	'Earth Missions'              = 'https://www.nasa.gov/api/1/query/ubernodes.json?topics[]=3125&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Hubble Space Telescope'      = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3451&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Spitzer Space Telescope'     = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3677&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Cassini at Saturn'           = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3187&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'James Webb Space Telescope'  = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3627&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'Apollo'                      = 'https://www.nasa.gov/api/1/query/ubernodes.json?missions[]=3235&unType[]=image&page=[PAGENUMBER]&pageSize=24';
	'NASA Image of the Day'       = 'https://www.nasa.gov/api/1/query/ubernodes.json?unType[]=image&routes[]=1446&page=[PAGENUMBER]&pageSize=24';
}

$APIs = @{
	'NASA Images' = 'https://images-api.nasa.gov/search?q=saturn&page=[PAGENUMBER]&media_type=image&year_start=1920&year_end=2016';
}

$Planetaries = @{
	'The Planetary Society' = 'https://www.planetary.org/multimedia/space-images/index.jsp?page=[PAGENUMBER]';
}

$SDOs = @{
	'Solar Dynamics Observatory' = 'https://sdo.gsfc.nasa.gov/gallery/main';
}

$Assets = @{
	'Recents' = 'https://images-assets.nasa.gov/recent.json';
	'Popular' = 'https://images-assets.nasa.gov/popular.json';
}

$JPLs = @{
	'Jet Propulsion Laboratory' = 'https://www.jpl.nasa.gov/assets/json/getMore.php?images=true&page=[PAGENUMBER]'
}

Clear-Host
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
# To get the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#$DownloadFolder = Join-Path -Path $CurrentDir -ChildPath 'Data'
$DownloadFolder = Join-Path -Path $home -ChildPath 'Pictures\Nasa'
$OutputCSVFile = $CurrentScript -replace "\.(.*)$", '.csv'

$NasaPictures = @() 


ForEach ($CurrentPlanetary in $Planetaries.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentPlanetary
	$NasaPictures += Get-PlanetaryNasaPictures -Verbose -URI $Planetaries[$CurrentPlanetary] -Destination $DestinationFolder
} 

ForEach ($CurrentSDO in $SDOs.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentSDO
	$NasaPictures += Get-SDONasaPictures -Verbose -Domain 'https://sdo.gsfc.nasa.gov' -URI $SDOs[$CurrentSDO] -Destination $DestinationFolder
} 

ForEach ($CurrentMission in $Missions.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentMission
	$NasaPictures += Get-MissionNasaPictures -Verbose -Domain 'https://www.nasa.gov' -URI $Missions[$CurrentMission] -Destination $DestinationFolder
} 

ForEach ($CurrentAPI in $APIs.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentAPI
	$NasaPictures += Get-ApiNasaPictures -Verbose -URI $APIs[$CurrentAPI] -Destination $DestinationFolder
} 

ForEach ($CurrentAsset in $Assets.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentAsset
	$NasaPictures += Get-AssetNasaPictures -Verbose -URI $Assets[$CurrentAsset] -Destination $DestinationFolder
} 

ForEach ($CurrentJPL in $JPLs.Keys) {
	$DestinationFolder = Join-Path -Path $DownloadFolder -ChildPath $CurrentJPL
	$NasaPictures += Get-JPLNasaPictures -Verbose -URI $JPLs[$CurrentJPL] -Destination $DestinationFolder
} 

$NasaPictures = $NasaPictures | Where-Object { $_.imageuri -match '^http' }
$NasaPictures | Export-Csv -Path $OutputCSVFile -NoTypeInformation


#$NasaPictures = Import-Csv -Path $OutputCSVFile -Verbose

$NasaPictures | Download-NasaPictures -Asynchronous -Verbose #-Force #Use -Force to force the download of previously downloaded content

$ElapsedTime = New-TimeSpan $StartTime $(Get-Date) 
$ElapsedTime