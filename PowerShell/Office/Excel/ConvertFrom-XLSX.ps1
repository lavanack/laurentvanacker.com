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

Function ConvertFrom-XLSX
{
	<#
			.SYNOPSIS
			Convert a Excel workbook into a CSV file(s) (one per worksheet)

			.DESCRIPTION
			Convert a Excel workbook into a CSV file(s) (one per worksheet)

			.PARAMETER FullName
			The Excel workbook to convert specified by its full name or by a System.IO.FileInfo object

			.PARAMETER Force
			A switch to specify if we overwrite the CSV file(s) even if they are newer than that the Excel workbook

			.PARAMETER Visible
			A switch to specify if the Excel application will be visible during the processing

			.EXAMPLE
			Get-ChildItem "*.xlsx" | ConvertFrom-XLSX -Verbose
			Will convert all Excel workbooks into CSV file(s)s but only if the Excel workbook are newer than the related CSV file(s) (if any). The verbose mode is enabled

			.EXAMPLE
			Get-ChildItem "*.xlsx" | ConvertFrom-XLSX -Force
			Will convert all Excel workbooks into CSV file(s)s even if the CSV file(s) are newer than the original Excel workbook

			.EXAMPLE
			ConvertFrom-XLSX -FullName "c:\2018.xls", "c:\2019.xls" -Force
			Will convert two Excel workbooks into CSV file(s)s even if the CSV file(s) are newer than the original Excel workbook

	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	Param(
		#The xlsx File to convert
		[Parameter(Mandatory = $true,HelpMessage = 'Please enter the full path of a xlsx file', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.xlsx$')
		})]
		[String[]]$FullName,

		#To overwrite the previously generated CSV file(s)."
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
            $Workbook = $Excel.Workbooks.Open($CurrentFullName)
			$CurrentFullName = Get-Item -Path $CurrentFullName
			#Getting the fullname of the processed xlsx File
			$SourceXLSXFullName = $CurrentFullName.FullName
			#Getting the name of the processed xlsx File
			$SourceXLSXName = $CurrentFullName.Name
			#Getting the final CSV full name (same directory and name that the xlsx File)

            foreach ($CurrentWorksheet in $Workbook.Worksheets)
            {
			    Write-Verbose -Message ('Processing {0}\{1} ...' -f $SourceXLSXFullName,$($CurrentWorksheet.Name))
    			$TargetCSVDocumentFullName = $SourceXLSXFullName -replace $CurrentFullName.Extension, "_$($CurrentWorksheet.Name).csv"

			    #Getting the write time of the xlsx File
			    $SourceXLSXTimeWritten = $(Get-Item -Path $SourceXLSXFullName).LastWriteTime

			    #Getting if -Force was specified or if the XLSX doesn't exist or if the xlsx File are newer that a previously generated XLSX Document.
			    If (($Force) -or (!(Test-Path -Path $TargetCSVDocumentFullName)) -or ($(Get-Item -Path $TargetCSVDocumentFullName).LastWriteTime -lt $SourceXLSXTimeWritten))
			    {
				    #If -Force was specified
				    If ($Force)
				    {
					    Write-Verbose -Message ('Forcing {0} ...' -f $SourceXLSXFullName)
				    }	
				    #If the CSV file doesn't exist
				    ElseIf (!(Test-Path -Path $TargetCSVDocumentFullName))
				    {
					    Write-Verbose -Message ('Processing {0} ...' -f $SourceXLSXFullName)
				    }	
				    #If the xlsx file are newer that a previously generated CSV file(s).
				    ElseIf ($(Get-Item -Path $TargetCSVDocumentFullName).LastWriteTime -lt $SourceXLSXTimeWritten)
				    {
					    Write-Verbose -Message ('Updating {0} ...' -f $SourceXLSXFullName)
				    }	
		
				    #Risk Mitigation : support of -whatif and -confirm
				    If ($pscmdlet.ShouldProcess($SourceXLSXFullName, 'Converting'))
				    {

                        $CurrentWorksheet.SaveAs($TargetCSVDocumentFullName, [Microsoft.Office.Interop.Excel.XlFileFormat]::xlCSV)

					    Write-Verbose -Message 'Releasing WorkSheet ...'
					    Remove-Ref -ref ($CurrentWorksheet)
				    } 

				    # Write-Host -Object "File saved to:" $TargetCSVDocumentFullName 

				    Write-Host -Object ("The CSV file is available at : '{0}'" -f $TargetCSVDocumentFullName)
			    }
			    else
			    {
				    Write-Verbose -Message ("Skipping '{0}' because it is up-to-date`r`nUse -Force to overwrite previously generated XLSX file" -f $SourceXLSXName)
			    }
            }
			Write-Verbose -Message 'Closing the XLSX File ...'
			$Workbook.Close()

			Write-Verbose -Message 'Releasing WorkBook ...'
			Remove-Ref -ref ($WorkBook)
		}
	}
	end
	{
		Write-Verbose -Message 'Exiting the Excel application ...'
		$null = $Excel.Quit()
		Remove-Ref -ref ($Excel)
	}
}
#endregion

Clear-Host
# To get the directory of this script
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Get-ChildItem -Path $CurrentDir -Filter '*.xlsx' -Recurse | ConvertFrom-XLSX -Force -Verbose -WhatIf
# ConvertFrom-XLSX -FullName "$CurrentDir\processes.xlsx","CurrentDir\services.xlsx" -Force
# Get-ChildItem -Path $CurrentDir -Filter "*.xlsx" -recurse | ConvertFrom-XLSX -Verbose
# Get-ChildItem -Path $CurrentDir -Filter "*.xlsx" -recurse | ConvertFrom-XLSX -WhatIf -Verbose
# Get-ChildItem -Path $CurrentDir -Filter "*.xlsx" -recurse | ConvertFrom-XLSX -Visible
