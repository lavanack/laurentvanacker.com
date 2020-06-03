#requires -Version 4
#region function definitions

Function Remove-Ref 
{
	param
	(
		[parameter(Mandatory = $true, HelpMessage = 'Please specify a reference')]
		[Object]$ref
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
	while ([Runtime.InteropServices.Marshal]::ReleaseComObject([__ComObject]$ref) -gt 0) 
	{

	}
	[GC]::Collect()
	[GC]::WaitForPendingFinalizers() 
}

Function ConvertTo-PDF
{
	<#
			.SYNOPSIS
			Convert a Word document into a PDF document

			.DESCRIPTION
			Convert a Word document into a PDF document

			.PARAMETER FullName
			The Word document to convert specified by its full name or by a System.IO.FileInfo object

			.PARAMETER Force
			A switch to specify if we overwrite the PDF document even if it is newer than that the Word document

			.PARAMETER Visible
			A switch to specify if the Word application will be visible during the processing

			.EXAMPLE
			Get-ChildItem "*.docx" | ConvertTo-PDF -Verbose
			Will convert all word documents into PDF documents but only if the Word document is newer than the related PDF document (if any). The verbose mode is enabled

			.EXAMPLE
			Get-ChildItem "*.docx" | ConvertTo-PDF -Force
			Will convert all word documents into PDF documents even if the PDF document is newer than the original Word document

			.EXAMPLE
			ConvertTo-PDF -FullName "c:\datasheet_FR-fr.docx", "c:\datasheet_en_US.docx" -Force
			Will convert two word documents into PDF documents even if the PDF document is newer than the original Word document

	#>
	Param(
		#The Word Document to convert
		[Parameter(Mandatory = $true,HelpMessage = 'Please enter the full path of a Word Document', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.docx?$')
		})]
		[alias('Source', 'WordDocument', 'Document')]
		[string[]]$FullName,

		#To overwrite the previously generated PDF files."
		[switch]$Force,

		#To display the Word application
		[switch]$Visible
	)
	begin
	{
		#Loading Word Properties
		$null = Add-Type -AssemblyName Microsoft.Office.Interop.Word
		#Static value for the PDF format (for saving)
		$wdFormatPDF = [Microsoft.Office.Interop.Word.WdSaveFormat]::wdFormatPDF
		#Static value for not saving changes
		$wdDoNotSaveChanges = [Microsoft.Office.Interop.Word.WdSaveOptions]::wdDoNotSaveChanges
		#Constant Definitions
		$ConfirmConversion = $false
		$ReadOnly = $true

		Write-Verbose -Message 'Running the Word application ...'
		#Opening the Word Application
		$Word = New-Object -ComObject 'Word.Application'
		$Word.Visible = $Visible
		$Word.Application.DisplayAlerts = $false
	}	
	process
	{
		#For all files passed as argument outside a pipeline context
		Foreach ($CurrentFullName in $FullName)
		{
			$CurrentFullName = Get-Item -Path $CurrentFullName
			#Getting the fullname of the processed presentation
			$SourceWordDocumentFullName = $CurrentFullName.FullName
			#Getting the name of the processed presentation
			$SourceWordDocumentName = $CurrentFullName.Name
			#Getting the final PDF full name (same directory and name that the Word document)
			$TargetPDFDocumentFullName = $($SourceWordDocumentFullName) -replace '\.docx?$', '.pdf'
			#Getting the write time of the word document
			$SourceWordDocumentTimeWritten = $(Get-Item -Path $SourceWordDocumentFullName).LastWriteTime

			#Getting if -Force was specified or if the PDF doesn't exist or if the Word document is newer that a previously generated PDF Document.
			If (($Force) -or (!(Test-Path -Path $TargetPDFDocumentFullName)) -or ($(Get-Item -Path $TargetPDFDocumentFullName).LastWriteTime -lt $SourceWordDocumentTimeWritten))
			{
				#If -Force was specified
				If ($Force)
				{
					Write-Verbose -Message ('Forcing {0} ...' -f $SourceWordDocumentFullName)
				}	
				#If the PDF doesn't exist
				ElseIf (!(Test-Path -Path $TargetPDFDocumentFullName))
				{
					Write-Verbose -Message ('Processing {0} ...' -f $SourceWordDocumentFullName)
				}	
				#If the Word document is newer that a previously generated PDF Document.
				ElseIf ($(Get-Item -Path $TargetPDFDocumentFullName).LastWriteTime -lt $SourceWordDocumentTimeWritten)
				{
					Write-Verbose -Message ('Updating {0} ...' -f $SourceWordDocumentFullName)
				}	
		
				Write-Verbose -Message 'Opening the Word document ...'
				$OpenDoc = $Word.Documents.OpenNoRepairDialog($SourceWordDocumentFullName, $ConfirmConversion, $ReadOnly)

				Write-Verbose -Message 'Saving the PDF document ...'
				$OpenDoc.SaveAs($TargetPDFDocumentFullName, $wdFormatPDF)

				Write-Verbose -Message 'Closing the Word document ...'
				$OpenDoc.Close($wdDoNotSaveChanges)

				Write-Host -Object ("The PDF file is available at : '{0}'" -f $TargetPDFDocumentFullName)
				Remove-Ref -ref ($OpenDoc)
			}
			else
			{
				Write-Host -Object ("Skipping '{0}' because it is up-to-date`r`nUse -force to overwrite previously generated PDF file" -f $SourceWordDocumentName) -ForegroundColor Yellow
			}
		}
	}
	end
	{
		Write-Verbose -Message 'Exiting the Word application ...'
		$null = $Word.Quit()

		Remove-Ref -ref ($Word)
	}
}
#endregion

Clear-Host
# To get the directory of this script
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Get-ChildItem -Path $CurrentDir -Filter '*.docx' | ConvertTo-PDF -Verbose -Force -Visible
#ConvertTo-PDF -Source "$CurrentDir\datasheet_FR-fr.docx", "$CurrentDir\datasheet_en_US.docx" -Force -Verbose