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
#region Function definition
Function Release-Ref {
	param
	(
		[Object]
		$ref
	)

	Remove-Variable $ref -ErrorAction SilentlyContinue | Out-Null
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {
 }
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}

Function ConvertTo-PDF {
	[CmdletBinding()]
	Param(
		#The collection of the powerpoint files to merge
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.pptx$")
			})]
		[alias('FilePath', 'Path', 'Source')]
		[string[]]$FullName,

		#To overwrite the previously generated PDF files."
		[switch]$Force,

		#To keep open the generated Powerpoint presentation
		[parameter(Mandatory = $False)]
		[switch]$Visible
	)
	begin {
		#Loading PowerPoint Properties
		$null = [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Office.Interop.PowerPoint')
		$ppSaveAsPDF = [Microsoft.Office.Interop.PowerPoint.PpSaveAsFileType]::ppSaveAsPDF

		#Opening the PowerPoint application once
		$Powerpoint = New-Object -ComObject Powerpoint.Application
	}	
	process {
		Foreach ($CurrentFullName in $FullName) {
			$CurrentFullName = Get-Item $CurrentFullName
			$CurrentTrainerPowerPointFullName = $CurrentFullName.FullName
			$CurrentTrainerPowerPointName = $CurrentFullName.Name
			Write-Host "Processing $CurrentTrainerPowerPointFullName ..."
			$CurrentStudentPDFDocumentFullName = $CurrentTrainerPowerPointFullName.replace('.pptx', '.pdf')
			$CurrentTrainerPowerPointTimeWritten = $(Get-Item $CurrentTrainerPowerPointFullName).LastWriteTime

			If (($Force) -or (!(Test-Path $CurrentStudentPDFDocumentFullName)) -or ($(Get-Item $CurrentStudentPDFDocumentFullName).LastWriteTime -lt $CurrentTrainerPowerPointTimeWritten)) {
				If ($Force) {
					Write-Verbose "Forcing $CurrentTrainerPowerPointFullName ..."
				}	
				ElseIf (!(Test-Path $CurrentStudentPDFDocumentFullName)) {
					Write-Verbose "Processing $CurrentTrainerPowerPointFullName ..."
				}	
				ElseIf ($(Get-Item $CurrentStudentPDFDocumentFullName).LastWriteTime -lt $CurrentTrainerPowerPointTimeWritten) {
					Write-Verbose "Updating $CurrentTrainerPowerPointFullName ..."
				}	

				
				Write-Verbose 'Opening the PowerPoint document ...'
				$CurrentPresentation = $PowerPoint.Presentations.open($CurrentTrainerPowerPointFullName)

				Write-Verbose 'Saving the PDF document ...'
				$CurrentPresentation.SaveAs($CurrentStudentPDFDocumentFullName, $ppSaveAsPDF)

				Write-Verbose 'Closing the PowerPoint document ...'
				$CurrentPresentation.Close()

				Write-Host "The student PDF file is available at : '$CurrentStudentPDFDocumentFullName'"
			}
			else {
				Write-Host "Skipping '$CurrentTrainerPowerPointName' because it is up-to-date`r`nUse -force to overwrite previously generated trainer PDF file" -ForeGroundColor Yellow
			}
	
		}
	}
	end {
		Write-Verbose -Message 'Exiting the PowerPoint application ...'
		$null = $PowerPoint.Quit()

		Release-Ref($PowerPoint)
	}
}
#endregion	

Clear-Host
# To get the directory of this script
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Get-ChildItem -Path "C:\AzurePaaS\InstructorSource" -File -Filter '*.pptx' -Recurse | ConvertTo-PDF -Verbose -Visible -Force
