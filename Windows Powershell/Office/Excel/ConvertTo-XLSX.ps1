#region function definitions

Function Remove-Ref 
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true, HelpMessage = 'Please specify a reference')]
		[Object] $ref
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
			Remove-Ref ($Excel)
	#>
	$null = Remove-Variable -Name $ref -ErrorAction SilentlyContinue
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) 
	{

	}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}

Function ConvertTo-XLSX
{
	<#
			.SYNOPSIS
			Convert a CSV File into a XLSX document

			.DESCRIPTION
			Convert a CSV File into a XLSX document

			.PARAMETER FullName
			The CSV File to convert specified by its full name or by a System.IO.FileInfo object

			.PARAMETER Force
			A switch to specify if we overwrite the XLSX document even if it is newer than that the CSV File

			.PARAMETER Visible
			A switch to specify if the Excel application will be visible during the processing

			.EXAMPLE
			Get-ChildItem "*.csv" | ConvertTo-XLSX -Verbose
			Will convert all CSV Files into XLSX documents but only if the CSV File is newer than the related XLSX document (if any)

			.EXAMPLE
			Get-ChildItem "*.csv" | ConvertTo-XLSX -Verbose -Force
			Will convert all CSV Files into XLSX documents even if the XLSX document is newer than the original CSV File

			.EXAMPLE
			Get-ChildItem "*.csv" | ConvertTo-XLSX -WhatIf
			Will convert all CSV Files into XLSX documents in risk mitigation mode

			.EXAMPLE
			ConvertTo-XLSX -FullName "processes.csv","services.csv"
			Will convert the two CSV Files into XLSX documents

	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param(
		#The CSV File to convert
		[Parameter(Mandatory = $true,HelpMessage = 'Please enter the full path of a CSV file', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.csv$')
		})]
		[String[]]$FullName,

		#To overwrite the previously generated XLSX files."
		[parameter(Mandatory = $false)]
		[switch]$Force,

		#To display the Excel application
		[parameter(Mandatory = $false)]
		[switch]$Visible
	)
	begin
	{
		#Loading Excel Properties
		$null = Add-Type -AssemblyName Microsoft.Office.Interop.Excel
		#Static value for the Excel Workbook default 
		$xlWorkbookDefault = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlWorkbookDefault
		#For Gray color for first row heading
		$Gray = 15
 
		Write-Verbose -Message 'Running the Excel application ...'
		#Opening the Excel Application
		$Excel = New-Object -ComObject 'Excel.Application'
		$Excel.Visible = $Visible
		$Excel.Application.DisplayAlerts = $false
	}	
	process
	{
		#For all files passed as argument outside a pipeline context
		Foreach ($CurrentFullName in $FullName)
		{
			$CurrentFullName = Get-Item -Path $CurrentFullName
			#Getting the fullname of the processed CSV File
			$SourceCSVFullName = $CurrentFullName.FullName
			#Getting the name of the processed CSV File
			$SourceCSVName = $CurrentFullName.Name
			#Getting the final XLSX full name (same directory and name that the CSV File)
			$TargetXLSXDocumentFullName = $SourceCSVFullName -replace '\.csv$', '.xlsx'
			#Getting the write time of the CSV File
			$SourceCSVTimeWritten = $(Get-Item -Path $SourceCSVFullName).LastWriteTime

			#Getting if -Force was specified or if the XLSX doesn't exist or if the CSV File is newer that a previously generated XLSX Document.
			If (($Force) -or (!(Test-Path -Path $TargetXLSXDocumentFullName)) -or ($(Get-Item -Path $TargetXLSXDocumentFullName).LastWriteTime -lt $SourceCSVTimeWritten))
			{
				#If -Force was specified
				If ($Force)
				{
					Write-Verbose -Message ('Forcing {0} ...' -f $SourceCSVFullName)
				}	
				#If the XLSX file doesn't exist
				ElseIf (!(Test-Path -Path $TargetXLSXDocumentFullName))
				{
					Write-Verbose -Message ('Processing {0} ...' -f $SourceCSVFullName)
				}	
				#If the CSV file is newer that a previously generated XLSX Document.
				ElseIf ($(Get-Item -Path $TargetXLSXDocumentFullName).LastWriteTime -lt $SourceCSVTimeWritten)
				{
					Write-Verbose -Message ('Updating {0} ...' -f $SourceCSVFullName)
				}	
		
				#Risk Mitigation : support of -whatif and -confirm
				If ($pscmdlet.ShouldProcess($SourceCSVFullName, 'Converting'))
				{
					Write-Verbose -Message 'Opening the CSV File ...'
					$WorkBook = $Excel.Workbooks.Open($SourceCSVFullName) 
					#Adding a worksheet
					$WorkSheet = $WorkBook.worksheets.Item(1) 
					$Range = $WorkSheet.UsedRange 
					$null = $Range.EntireColumn.AutoFit() 
					#Getting teh first row
					$firstRow = $WorkSheet.cells.item(1,1).entireRow
					#Make Headings Bold
					$firstRow.Font.Bold = $true
					#Freezing header row
					$Excel.ActiveWindow.SplitColumn = 0
					$Excel.ActiveWindow.SplitRow = 1
					$Excel.ActiveWindow.FreezePanes = $true

					#Add Data Filters to Heading Row
					$null = $firstRow.AutoFilter() 

					#Setting header row gray
					$firstRow.Interior.ColorIndex = $Gray
					Write-Verbose -Message 'Saving the XLSX document ...'
					$WorkBook.SaveAs($TargetXLSXDocumentFullName, $xlWorkbookDefault) 


					Write-Verbose -Message 'Closing the CSV File ...'
					$WorkBook.Close()

					Write-Verbose -Message 'Releasing firstRow ...'
					Remove-Ref  -ref ($firstRow)
					Write-Verbose -Message 'Releasing Range ...'
					Remove-Ref  -ref ($Range)
					Write-Verbose -Message 'Releasing WorkSheet ...'
					Remove-Ref  -ref ($WorkSheet)
					Write-Verbose -Message 'Releasing WorkBook ...'
					Remove-Ref  -ref ($WorkBook)
				} 

				# Write-Host -Object "File saved to:" $TargetXLSXDocumentFullName 

				Write-Host -Object ("The XLSX file is available at : '{0}'" -f $TargetXLSXDocumentFullName)
			}
			else
			{
				Write-Verbose -Message ("Skipping '{0}' because it is up-to-date`r`nUse -Force to overwrite previously generated XLSX file" -f $SourceCSVName)
			}
		}
	}
	end
	{
		Write-Verbose -Message 'Exiting the Excel application ...'
		$null = $Excel.Quit()

		Remove-Ref  -ref ($Excel)
	}
}
#endregion

Clear-Host
# To get the directory of this script
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Get-ChildItem -Path $CurrentDir -Filter '*.csv' -Recurse | ConvertTo-XLSX -Force -Verbose
# ConvertTo-XLSX -FullName "$CurrentDir\processes.csv","CurrentDir\services.csv" -Force
# Get-ChildItem -Path $CurrentDir -Filter "*.csv" -recurse | ConvertTo-XLSX -Verbose
# Get-ChildItem -Path $CurrentDir -Filter "*.csv" -recurse | ConvertTo-XLSX -WhatIf -Verbose
# Get-ChildItem -Path $CurrentDir -Filter "*.csv" -recurse | ConvertTo-XLSX -Visible