#region Function definition
Function Release-Ref 
{
	 param
	 (
		 [Object]
		 $ref
	 )

	Remove-Variable $ref -ErrorAction SilentlyContinue | Out-Null
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}

Function Replace-String {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
		$Selection,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$True)]
		[string]$Name,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$True)]
		[string]$Value
	)
	begin
	{
		$wdReplaceAll = [Enum]::Parse([Microsoft.Office.Interop.Word.WdReplace], 'wdReplaceAll');
		#region Word variables for search
		$FindContinue = 1
		$Wrap = $FindContinue
		$MatchCase = $False
		$MatchWholeWord = $False
		$MatchWildcards = $False
		$MatchSoundsLike = $False
		$MatchAllWordForms = $False
		$Forward = $True
		#endregion 
	}	
	process
	{
		$Selection.Start = 0
		$SelectionIndex = 0
		$SelectionIndex++
		Write-Verbose $("[{0:D3}] Replacing '$Name' by '$Value'..." -f $SelectionIndex)
		$Selection.Find.Execute("$Name", $MatchCase, $MatchWholeWord, $MatchWildcards, $MatchSoundsLike, $MatchAllWordForms, $Forward, $Wrap, $False, $Value, $wdReplaceAll) | Out-Null
	}
	end
	{
	}
}


Function Remove-Style
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
		$OpenDoc,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
		$Selection,
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$False)]
		[string]$CurrentStyleToRemove
	)
	begin
	{
		$wdActiveEndPageNumber = [Enum]::Parse([Microsoft.Office.Interop.Word.WdInformation], 'wdActiveEndPageNumber');
	}	
	process
	{
		Write-Host "Removing the '$CurrentStyleToRemove' Style ..."
		# $Style=$Word.ActiveDocument.Styles | Where { $_.namelocal -eq $CurrentStyleToRemove }
		$Style=$OpenDoc.Styles | Where-Object { $_.namelocal -eq $CurrentStyleToRemove }
		If ($Style -ne $null)
		{
			$Selection.Start = 0
			$Selection.Find.Style = $Style
			$SelectionIndex = 0
			While ($Selection.Find.Execute())
			{
				$SelectionIndex++
				$PageNumber = $Selection.Information($wdActiveEndPageNumber)
				Write-Verbose $("[{0:D3}] Deleting an '$CurrentStyleToRemove' Style - Page $($PageNumber)..." -f $SelectionIndex)
				$Selection.Delete() | Out-Null
			}
		}
		else
		{
			Write-Verbose "The '$CurrentStyleToRemove' Style doesn't exist in the '$($OpenDoc.Name)' Word document..."
		}
	}
	end
	{
	}
}

Function Remove-HeadingAndContent
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
		$OpenDoc,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$False)]
		$Selection,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$True)]
		[string]$Name,
		[Parameter(Mandatory=$True, ValueFromPipeline=$False, ValueFromPipelineByPropertyName=$True)]
		$Value
	)
	begin
	{
		$wdActiveEndPageNumber = [Microsoft.Office.Interop.Word.WdInformation]::wdActiveEndPageNumber
		$wdParagraph = [Microsoft.Office.Interop.Word.WdUnits]::wdParagraph	
    }	
	process
	{
		$CurrentStyleToRemove = $Name
		Write-Host "Removing the '$CurrentStyleToRemove' Style ..."
		$Style=$OpenDoc.Styles | Where-Object { $_.namelocal -eq $CurrentStyleToRemove }
		If ($Style -ne $null)
		{
			$Selection.Start = 0
			$Selection.Find.Style = $Style
			$SelectionIndex = 0
			While ($Selection.Find.Execute())
			{
				$PageNumber = $Selection.Information($wdActiveEndPageNumber)
				$SelectionText = ($Selection.Text -replace "`r", '' -replace "`n", '')
				if ($SelectionText -in $Value)
				{
					$Selection.Expand($wdParagraph) | Out-Null 
					Do 
					{
						$NextParagraphStyle=$OpenDoc.Styles[$Selection.Paragraphs[$Selection.Paragraphs.Count].Next().Style]
						
						<#
								Write-Verbose "Selection Text : $($Selection.Text)"
								Write-Verbose "Selection Level : $($Style.ParagraphFormat.OutlineLevel)"
								Write-Verbose "Next Paragraph Level  : $($NextParagraphStyle.ParagraphFormat.OutlineLevel)"
								Write-Verbose "Next Paragraph Style : $($NextParagraphStyle.namelocal)"
						#>

						If ($Selection.Paragraphs[$Selection.Paragraphs.Count].Next() -eq $null) 
						{
							break
						}
						if ($NextParagraphStyle.ParagraphFormat.OutlineLevel -gt $Style.ParagraphFormat.OutlineLevel)
						{                            
							$Selection.MoveEnd($wdParagraph) | Out-Null 
						}
					} While ($NextParagraphStyle.ParagraphFormat.OutlineLevel -gt $Style.ParagraphFormat.OutlineLevel)
					$PageNumber = $Selection.Information($wdActiveEndPageNumber)
					$SelectionIndex++
					Write-Verbose $("[{0:D3}] Deleting an '$CurrentStyleToRemove' Style matching '$SelectionText' - Page $($PageNumber)..." -f $SelectionIndex)
					$Selection.Delete() | Out-Null
					#return $Selection
				}
			}
		}
		else
		{
			Write-Verbose "The '$CurrentStyleToRemove' Style doesn't exist in the '$($OpenDoc.Name)' Word document..."
		}
		# $return $null
	}
	end
	{
	}
}

Function Update-TOCs
{
	 param
	 (
		 [Object]
		 $OpenDoc
	 )

	$SelectionIndex = 0
	$OpenDoc.TablesOfContents | ForEach-Object { 
		$SelectionIndex++
		Write-Verbose $('[{0:D3}] Updating a Table Of Content ...' -f $SelectionIndex)
		$_.Update()
	}
}

Function Get-StudentPDFVersion
{
	[CmdletBinding()]
	Param(
		#The Word Document to convert
		[Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, Position=0)]
		[ValidateScript({(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.doc(x{0,1})$")})]
		[string[]]$FullName,

		#To overwrite the previously generated PDF files."
		[parameter(Mandatory=$false)]
		[switch]$Force,

		#To display the Word application
		[parameter(Mandatory=$false)]
		[switch]$Visible
	)
	begin
	{
		#Loading Word Properties
		[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Office.Interop.Word') | Out-Null
		$wdFormatPDF = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveFormat], 'wdFormatPDF');
		$wdDoNotSaveChanges = [Enum]::Parse([Microsoft.Office.Interop.Word.WdSaveOptions], 'wdDoNotSaveChanges');
		#Constant Definitions
		$ConfirmConversion = $False
		$ReadOnly = $False

		Write-Verbose -Message 'Running the Word application ...'
		#Opening the Word Application
		$Word=new-object -ComObject 'Word.Application'
		$Word.Visible=$Visible
		$Word.Application.DisplayAlerts = $False
	}	
	process
	{
		Foreach ($CurrentFullName in $FullName)
		{
			$CurrentFullName = Get-Item $CurrentFullName
			$CurrentTrainerWordDocumentFullName = $CurrentFullName.FullName
			$CurrentTrainerWordDocumentName = $CurrentFullName.Name
			$CurrentStudentWordDocumentFullName=$($CurrentTrainerWordDocumentFullName).replace('Trainer\', 'Students\').replace('(Instructor)', '(Student)')
			Write-Host "Processing $CurrentTrainerWordDocumentFullName ..."
			$CurrentStudentPDFDocumentFullName=$CurrentStudentWordDocumentFullName.replace('.docx', '.pdf')
			$CurrentTrainerWordDocumentTimeWritten=$(Get-Item $CurrentTrainerWordDocumentFullName).LastWriteTime

			If (($Force) -or (!(Test-Path $CurrentStudentPDFDocumentFullName)) -or ($(Get-Item $CurrentStudentPDFDocumentFullName).LastWriteTime -lt $CurrentTrainerWordDocumentTimeWritten))
			{
				If ($Force)
				{
					Write-Verbose "Forcing $CurrentTrainerWordDocumentFullName ..."
				}	
				ElseIf (!(Test-Path $CurrentStudentPDFDocumentFullName))
				{
					Write-Verbose "Processing $CurrentTrainerWordDocumentFullName ..."
				}	
				ElseIf ($(Get-Item $CurrentStudentPDFDocumentFullName).LastWriteTime -lt $CurrentTrainerWordDocumentTimeWritten)
				{
					Write-Verbose "Updating $CurrentTrainerWordDocumentFullName ..."
				}	

				
				Write-Verbose 'Duplicating the Trainer Word Document to create the Student version ...'
				Copy-Item $CurrentTrainerWordDocumentFullName $CurrentStudentWordDocumentFullName -Force
				
				Write-Verbose 'Opening the Word document ...'
				$OpenDoc=$Word.Documents.OpenNoRepairDialog($CurrentStudentWordDocumentFullName, $ConfirmConversion, $ReadOnly)
				Write-Verbose 'Unmarking the Word document as final ...'
				$OpenDoc.Final = $False

				$Selection=$Word.Selection
				# Remove-Styles $OpenDoc $Selection $StylesToRemove
				$StylesToRemove | Remove-Style $OpenDoc $Selection 

				# Remove-HeadingsAndContents $OpenDoc $Selection $HeadingToRemove
				$HeadingToRemove.GetEnumerator() | Remove-HeadingAndContent $OpenDoc $Selection 

				# Replace-Strings $Selection $Replacements
				$Replacements.GetEnumerator() | Replace-String $Selection 
				Update-TOCs $OpenDoc

				Write-Verbose 'Marking the Word document as final ...'
				$OpenDoc.Final = $True

				Write-Verbose 'Saving the PDF document ...'
				$OpenDoc.SaveAs($CurrentStudentPDFDocumentFullName, $wdFormatPDF)

				Write-Verbose 'Closing the Word document ...'
				$OpenDoc.Close($wdDoNotSaveChanges)

				Remove-Item $CurrentStudentWordDocumentFullName -Force | Out-Null

				Write-Host "The student PDF file is available at : '$CurrentStudentPDFDocumentFullName'"
				Release-Ref($OpenDoc)
			}
			else
			{
				Write-Host "Skipping '$CurrentTrainerWordDocumentName' because it is up-to-date`r`nUse -force to overwrite previously generated trainer PDF file" -ForeGroundColor Yellow
			}
	
		}
	}
	end
	{
		Write-Verbose -Message 'Exiting the Word application ...'
		$Word.Quit() | Out-Null

		Release-Ref($Word)
	}
}
#endregion	

Clear-Host
$CurrentDir=Split-Path $MyInvocation.MyCommand.Path

#region Variables for Word item to remove/replace
$StylesToRemove = @('Note(s) for Trainer', 'Lab Answer')
$Replacements = @{'Instructor Workbook'='Student Workbook'}
$HeadingToRemove=@{'Heading 1'=@('History', 'Instructor: Prerequisites');'Heading 2'=@('Module Review (Answers)')}
#endregion

# To get the directory of this script
$CurrentDir=Split-Path -Path $MyInvocation.MyCommand.Path -Parent
Get-ChildItem -Path $CurrentDir -Filter '*.docx' | Get-StudentPDFVersion -Verbose -Visible -Force
