#region function definitions
#Function for releasing a COM object
Function Remove-Ref {
	param
	(
		[Object]
		$ref
	)

	$null = Remove-Variable -Name $ref -ErrorAction SilentlyContinue
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) {

	}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}


#Main function for merging PowerPoint presentations
Function Split-PowerPointPresentation {
	<#
			.SYNOPSIS
			Split PowerPoint presentations with section with on dedicated file per section or slide

			.DESCRIPTION
			Split PowerPoint presentations with section with on dedicated file per section or slide

			.PARAMETER Source
			The PowerPoint presentation files to split specified by its full name

			.EXAMPLE
			$Get-ChildItem -Path $CurrentDir -filter *.pptx | Sort-Object -Property Name | Split-PowerPointPresentation -Verbose -Open
			Will Split all the PowerPoint files into the current directory into multiple single Powerpoint files (one file per section - Default mode) 
			The output will be verbose
			The PowerPoint application won't be left after the processing

			.EXAMPLE
			$Presentations = "$CurrentDir\0.pptx", "$CurrentDir\PresentationToSplit1.pptx", "$CurrentDir\PresentationToSplit2.pptx"
            Split-PowerPointPresentation -Source $Presentations -Verbose -Mode Slide
			Will Split all the PowerPoint files into the current directory into multiple single Powerpoint files (one file per slide) 
			Will Split all the specified PowerPoint files into into the C:\Temp\SplitdPresentation.pptx Powerpoint file
	#>
	[CmdletBinding()]
	Param(
		#The collection of the powerpoint files to Split
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.ppt(x{0,1})$")
			})]
		[alias('FilePath', 'Path', 'FullName')]
		[string[]]$Source,
		[ValidateSet('Section', 'Slide')]
		[string]$Mode = 'Section'
	)
	begin {
		#Opening the PowerPoint application once
		Add-Type -AssemblyName Microsoft.Office.Interop.PowerPoint
		$Powerpoint = New-Object -ComObject Powerpoint.Application
	}
	process {
		#For all files passed as argument outside a pipeline context
		foreach ($CurrentSourcePath in $Source) {
			#Getting the base name of the processed presentation
			Write-Verbose -Message "Opening (Read-only mode) $CurrentSourcePath ..."
			$CurrentSrcPresentation = $Powerpoint.Presentations.Open($CurrentSourcePath, [Microsoft.Office.Core.MsoTriState]::msoTrue)
			if ($Mode -eq 'Section') {
				for ($SrcSectionIndex = 1; $SrcSectionIndex -le $CurrentSrcPresentation.SectionProperties.count; $SrcSectionIndex++) {
					if ($CurrentSourcePath -match "(?<filename>.*)\.(?<extension>\w+)") {
						$CurrentDestPath = $Matches["filename"] + $("_{0:D3}_{1}." -f $SrcSectionIndex, $CurrentSrcPresentation.SectionProperties.Name($SrcSectionIndex)) + $Matches["extension"]
						Write-Verbose "Processing $($CurrentDestPath) ..."
						Copy-Item -Path $CurrentSourcePath -Destination $CurrentDestPath -Force
						Write-Verbose -Message "Opening (Write mode) $CurrentDestPath  ..."
						$CurrentDestPresentation = $Powerpoint.Presentations.Open($CurrentDestPath, [Microsoft.Office.Core.MsoTriState]::msoFalse)
						#Moving the section to keep in the first position
						$CurrentDestPresentation.SectionProperties.Move($SrcSectionIndex, 1)
						#Removing all other sections
						2 .. $CurrentDestPresentation.SectionProperties.count | ForEach-Object {
							Write-Verbose -Message "Deleting section : $($CurrentDestPresentation.SectionProperties.Name(2))  ..."
							$CurrentDestPresentation.SectionProperties.Delete(2, $True)
						}
						$CurrentDestPresentation.Save()
						$CurrentDestPresentation.Close()
						Remove-Ref -ref ($CurrentDestPresentation)
					}
				}
			}
			elseif ($Mode -eq 'Slide') {
				for ($SrcSlideIndex = 1; $SrcSlideIndex -le $CurrentSrcPresentation.Slides.Count; $SrcSlideIndex++) {
					if ($CurrentSourcePath -match "(?<filename>.*)\.(?<extension>\w+)") {
						$CurrentDestPath = $Matches["filename"] + $("_{0:D3}." -f $SrcSlideIndex) + $Matches["extension"]
						Write-Verbose "Creating $($CurrentDestPath) ..."
						$CurrentDestPresentation = $Powerpoint.Presentations.Add($True)

						#Inserting one slide of the current presentation to the new one
						$null = $CurrentDestPresentation.Slides.InsertFromfile($CurrentSourcePath, 0, $SrcSlideIndex, $SrcSlideIndex)
			
						#Applying the original template
						$CurrentDestPresentation.Slides.Range(1).ApplyTemplate($CurrentSourcePath)

						$CurrentDestPresentation.SaveAs($CurrentDestPath)
						$CurrentDestPresentation.Close()
						Remove-Ref -ref ($CurrentDestPresentation)
					}
				}
			}
			$CurrentSrcPresentation.Close()
			Remove-Ref -ref ($CurrentSrcPresentation)
		}
	}
	end {
		Write-Verbose -Message 'Releasing PowerPoint ...'
		$Powerpoint.Quit() | Out-Null
		Remove-Ref -ref ($Powerpoint)
	}
}
#endregion

Clear-Host
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path

#Example 1 : Processing all the PowerPoint presentation in current directory in the alphabetical order
Get-ChildItem -Path $CurrentDir -Filter *.pptx -File | Split-PowerPointPresentation -Verbose -Mode Section

#Example 2 : Processing a list of some PowerPoint presentations specified by their absolute path
#$Presentations = "$CurrentDir\0.pptx", "$CurrentDir\PresentationToSplit1.pptx", "$CurrentDir\PresentationToSplit2.pptx"
#Split-PowerPointPresentation -Source $Presentations -Verbose
