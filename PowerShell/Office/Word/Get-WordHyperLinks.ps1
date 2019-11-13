#requires -version 4

#region function definitions

Function Remove-Ref {
	[CmdletBinding()]
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
			Remove-Ref ($Word)
	#>
	$null = Remove-Variable -Name $ref -ErrorAction SilentlyContinue
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {

	}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}


Function Get-WordHyperLinks {
	<#
			.SYNOPSIS
			Returns a collection of object related to the Hyptertext links (Properties : "Link", "Document", "Page", "Title" (optional), "StatusCode" (optional)) inside a Word Document

			.DESCRIPTION
			Returns a collection of object related to the Hyptertext links inside a Word Document

			.PARAMETER FullName
			The Word document to analyze specified by its full name

			.PARAMETER Visible
			A switch to specify if the Word application will be visible during the processing

			.PARAMETER Status
			A switch to specify if we should query the URL and get the HTTP Status (the processing will take more time)

			.EXAMPLE
			$WordHyperLinks = (Get-ChildItem "*.docx" | Get-WordHyperLinks -Verbose -Visible -Status)
			Will return a collection of hypertext links contained inside all Word documents. 
			The output will be verbose
			The Word application will be visible
			The HTTP status will be returned (the processing will take more time)

			.EXAMPLE
			$WordHyperLinks = Get-WordHyperLinks -FullName "Sales.docx","HR.docx"
			Will return a collection of hypertext links contained inside the two given Word documents. The Word application will be invisible
	#>
	[CmdletBinding()]
	Param(
		#The Word document to process
		[Parameter(Mandatory = $True, HelpMessage = 'Please specify the path of a valid Word document', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.docx?$')
			})]
		[string[]]$FullName,

		#To display the Word application
		[parameter(Mandatory = $false)]
		[switch]$Visible,
		#To get the HTTP status of the link (and the title of the page)
		[parameter(Mandatory = $false)]
		[switch]$Status
	)
	begin {
		#For Microsoft Word
		$null = Add-Type -AssemblyName Microsoft.Office.Interop.Word
		$wdActiveEndPageNumber = [Microsoft.Office.Interop.Word.WdInformation]::wdActiveEndPageNumber
		$wdDoNotSaveChanges = [Microsoft.Office.Interop.Word.WdSaveOptions]::wdDoNotSaveChanges
		$ConfirmConversion = $false
		$ReadOnly = $True

		#Opening the word application
		Write-Verbose -Message 'Running the Word application ...'
		$Word = New-Object -ComObject 'Word.Application'
		#To make the Word application visible (or not)
		$Word.Visible = $Visible
		$Word.Application.DisplayAlerts = $false
		#To store the hypertext links
		$WordHyperLinks = @()
	}	
	process {
		#For all files passed as argument outside a pipeline context
		Foreach ($CurrentFullName in $FullName) {
			$CurrentFullName = Get-Item -Path $CurrentFullName
			#Getting the fullname of the processed Word document
			$CurrentWordDocumentFullName = $CurrentFullName.FullName
			#Getting the name of the processed Word document
			$CurrentTrainerWordDocumentName = $CurrentFullName.Name
			Write-Host -Object ('Processing {0} ...' -f $CurrentWordDocumentFullName)

			Write-Verbose -Message 'Opening the Word document ...'
			$OpenDoc = $Word.Documents.OpenNoRepairDialog($CurrentWordDocumentFullName, $ConfirmConversion, $ReadOnly)
			#Getting the hypertext links
			$HyperLinks = $OpenDoc.Hyperlinks | Where-Object -FilterScript {
				$_.Address
			}
			$Index = 0
			#Going through the hyperlink collection
			ForEach ($CurrentHyperLink in $HyperLinks) {
				$Index++
				Write-Progress -Activity "[$($Index)/$($HyperLinks.Count)] Processing $($CurrentHyperLink.Address)" -Status "Percent : $('{0:N0}' -f $($Index/($HyperLinks.Count) * 100)) %" -PercentComplete ($Index / $HyperLinks.Count * 100)
				#To Select/highlight the link
				$CurrentHyperLink.Range.Select()
				$Selection = $Word.Selection
				
				#To get the page number
				$PageNumber = $Selection.Information($wdActiveEndPageNumber)
				Write-Verbose -Message "$($CurrentHyperLink.Address) - $($CurrentHyperLink.TextToDisplay) - $PageNumber"
				
				#We process only http or https links
				if ($CurrentHyperLink.Address -match '^https?://') {
					if ($Status) {
						Try {
							# The HEAD method can return some 404 HTTP status instead of HTTP 200
							$Response = Invoke-WebRequest -Method Get -Uri $CurrentHyperLink.Address -UseBasicParsing -ErrorAction SilentlyContinue
							$StatusCode = [int]$Response.StatusCode
							# Bug : https://connect.microsoft.com/PowerShell/feedbackdetail/view/1557783/invoke-webrequest-hangs-in-some-cases-unless-usebasicparsing-is-used)
							# Workaround http://www.networksteve.com/forum/topic.php/Invoke-WebRequest_hangs_in_some_cases,_unless_-UseBasicParsing_i/?TopicId=77984&Posts=2
							# $Title = $Response.ParsedHTML.title
							$null = $Response.RawContent -replace "`n", '' -match '<title>(?<title>.*)</title>'
							#The title of the HTML document 
							$Title = $matches['title']
						}
						#If an exception occurs (Page Not found for instance : HTTP/404)
						catch {
							#Getting the status code
							if ($_.Exception.Response.StatusCode.Value__) {
								$StatusCode = $_.Exception.Response.StatusCode.Value__
							}
						}
						# Storing hyperlinks infos inside an array
						$WordHyperLinks += (New-Object -TypeName PSObject -Property @{
								#The document full path
								Document      = $CurrentWordDocumentFullName
								#The page number
								Page          = $PageNumber
								#The link URI
								Link          = $CurrentHyperLink.Address
								#The text link in the document
								TextToDisplay = $CurrentHyperLink.TextToDisplay
								#The HTTP Status Code
								StatusCode    = $StatusCode
								#The title of the HTML document 
								Title         = $Title
							})
						Write-Verbose -Message $("[$CurrentTrainerWordDocumentName][Page {0:D3}][Added] $($CurrentHyperLink.Address) ($StatusCode - $Title)" -f $PageNumber)
					}
					else {
						# Storing hyperlink information inside an array
						$WordHyperLinks += (New-Object -TypeName PSObject -Property @{
								#The document full path
								Document      = $CurrentWordDocumentFullName
								#The page number
								Page          = $PageNumber
								#The link URI
								Link          = $CurrentHyperLink.Address
								#The text link in the document
								TextToDisplay = $CurrentHyperLink.TextToDisplay
							})
						Write-Verbose -Message $("[$CurrentTrainerWordDocumentName][Page {0:D3}][Added] $($CurrentHyperLink.Address)" -f $PageNumber)
					}
				}
			}
			Write-Verbose -Message 'Closing the Word document ...'
			$OpenDoc.Close($wdDoNotSaveChanges)

			Remove-Ref -ref ($OpenDoc)
		}
	}
	end {
		Write-Progress -Activity 'Completed !' -Status 'Completed !' -Completed
		Write-Verbose -Message 'Exiting the Word application ...'
		$null = $Word.Quit()

		Remove-Ref -ref ($Word)
		return $WordHyperLinks
	}
}
#endregion

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
# Getting the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent
# Creating CSV file name based on the script full file path and by appending the timestamp at the end of the file name
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '_' + $(Get-Date  -Format 'yyyyMMddTHHmmss') + '.csv')

$WordHyperLinks = Get-ChildItem -Path $CurrentDir -Filter '*.docx' | Get-WordHyperLinks -Verbose -Visible -Status
#$WordHyperLinks = Get-WordHyperLinks -FullName "C:\datasheet_fr-FR.docx", "C:\datasheet_en-US.docx"
$WordHyperLinks | Export-Csv -Path $CSVFile -Force -NoTypeInformation
Write-Host -Object "Results are available in '$CSVFile'"