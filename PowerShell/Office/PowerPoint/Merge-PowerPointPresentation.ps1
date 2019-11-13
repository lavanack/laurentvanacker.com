#region function definitions
#Function for releasing a COM object
Function Remove-Ref 
{
	param
	(
		[Object]
		$ref
	)

	$null = Remove-Variable -Name $ref -ErrorAction SilentlyContinue
	while ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0) 
	{

	}
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers() 
}


#Main function for merging PowerPoint presentations
Function Merge-PowerPointPresentation 
{
	<#
			.SYNOPSIS
			Merge multiple PowerPoint presentation files to one file

			.DESCRIPTION
			Merge multiple PowerPoint presentation files to one file

			.PARAMETER Source
			The PowerPoint presentation files to merge specified by its full name

			.PARAMETER Destination
			The target PowerPoint presentation file specified by its full name

			.PARAMETER Open
			A switch to specify if we keep the PowerPoint application opened after the processing

			.EXAMPLE
			$Get-ChildItem -Path $CurrentDir -filter *.pptx | Sort-Object -Property Name | Merge-PowerPointPresentation -Verbose -Open
			Will merge all the PowerPoint files into the current directory into one single Powerpoint file by using a timestamped filename (ie. yyyyMMddTHHmmss.pptx like 20170126T091011.pptx) 
			The output will be verbose
			The PowerPoint application won't be left after the processing

			.EXAMPLE
			$Presentations = "$CurrentDir\0.pptx","$CurrentDir\1.pptx","$CurrentDir\2.pptx","$CurrentDir\3.pptx","$CurrentDir\4.pptx","$CurrentDir\5.pptx","$CurrentDir\6.pptx","$CurrentDir\7.pptx","$CurrentDir\8.pptx","$CurrentDir\9.pptx"
			Merge-PowerPointPresentation -Source $Presentations -Destination C:\Temp\MergedPresentation.pptx
			Will merge all the specified PowerPoint files into into the C:\Temp\MergedPresentation.pptx Powerpoint file
	#>
	[CmdletBinding()]
	Param(
		#The collection of the powerpoint files to merge
		[Parameter(Mandatory = $True,ValueFromPipeline = $True,ValueFromPipelineByPropertyName = $True)]
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match "\.ppt(x{0,1})$")
		})]
		[alias('FilePath', 'Path', 'FullName')]
		[string[]]$Source,

		#The path of the generated powerpoint file
		[Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[alias('OutputFile')]
		[string]$Destination = $(Join-Path -Path $([Environment]::GetFolderPath('MyDocuments')) -ChildPath $('{0:yyyyMMddTHHmmss}' -f (Get-Date))),

		#To keep open the generated Powerpoint presentation
		[parameter(Mandatory = $False)]
		[switch]$Open
	)
	begin
	{
		#Opening the PowerPoint application once
		Add-Type -AssemblyName Microsoft.Office.Interop.PowerPoint
		$Powerpoint = New-Object -ComObject Powerpoint.Application
		#Creating a new PowerPoint presentation
		$NewPresentation = $Powerpoint.Presentations.Add($True)
		# Adding an empty slide : mandatory
		$null = $NewPresentation.Slides.Add(1, [Microsoft.Office.Interop.PowerPoint.PpSlideLayout]::ppLayoutBlank)
		$SlidesNb = 0
	}
	process
	{
		#For all files passed as argument outside a pipeline context
		foreach ($CurrentSource in $Source)
		{
			#Getting the base name of the processed presentation
			$CurrentPresentationName = (Get-Item -Path $CurrentSource).BaseName
			
			#Inserting the slide of the current presentationt o the new one
			$InsertedSlidesNb = $NewPresentation.Slides.InsertFromfile($CurrentSource, $SlidesNb)
			
			#Applying the original template
			$NewPresentation.Slides.Range(($SlidesNb+1)..($SlidesNb+$InsertedSlidesNb)).ApplyTemplate($CurrentSource)

			#Adding a new section for the inserted context with the name of the processed presentation
			Write-Verbose -Message "Adding the section $CurrentPresentationName before Slide $($SlidesNb+1)..."
			$null = $NewPresentation.SectionProperties.AddBeforeSlide($SlidesNb+1, $CurrentPresentationName)

			Write-Verbose -Message "Processed file $CurrentSource by inserting $InsertedSlidesNb slides ($($SlidesNb+1) ==> $($SlidesNb+$InsertedSlidesNb)) ..."
			$SlidesNb += $InsertedSlidesNb
		}
	}
	end
	{
		#Deleting the useless empty slide (added at the beginning)
		$NewPresentation.Slides.Range($SlidesNb+1).Delete()
		#Saving the final file
		$NewPresentation.SaveAs($Destination)
		Write-Host -Object "The new presentation was saved in $($NewPresentation.FullName) ($SlidesNb slides)"
		#If the -Open switch is specified we keep the PowerPoint application opened
		if (!$Open)
		{
			$NewPresentation.Close()
			#$Powerpoint.Quit() | Out-Null
			Write-Verbose -Message 'Releasing PowerPoint ...'
			Remove-Ref -ref ($NewPresentation)
			Remove-Ref -ref ($Powerpoint)
		}
	}
}
#endregion

Clear-Host
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path
#Loading the PowerPoint assembly

#Example 1 : Processing all the PowerPoint presentation in current directory in the alphabetical order
#Get-ChildItem -Path "C:\Users\lavanack\OneDrive - Microsoft\Microsoft\Technical Ressources\WorkShop Plus\WorkshopPLUS-IIS_Troubleshooting and Best Practices\PowerPoint\Trainer" -Filter *.pptx | Sort-Object -Property Name | Merge-PowerPointPresentation -Verbose -Open
Get-ChildItem -Path "C:\Users\lavanack\OneDrive - Microsoft\Microsoft\Technical Ressources\WorkShop Plus\WorkshopPLUS-Windows_PowerShell_IT_Management\PPT\Trainer" -Filter "*_HiddenSections.pptx" | Sort-Object -Property Name | Merge-PowerPointPresentation -Verbose -Open
#Get-ChildItem -Path "C:\Users\lavanack\OneDrive - Microsoft\Microsoft\Technical Ressources\WorkShop Plus\WorkshopPLUS-Windows_PowerShell_Foundation_Skills\PPT\V1.1\Student" -Filter "*.pptx" | Sort-Object -Property Name | Merge-PowerPointPresentation -Verbose -Open


#Example 2 : Processing a list of some PowerPoint presentations specified by their absolute path
#$Presentations = "$CurrentDir\0.pptx", "$CurrentDir\1.pptx", "$CurrentDir\2.pptx", "$CurrentDir\3.pptx", "$CurrentDir\4.pptx", "$CurrentDir\5.pptx", "$CurrentDir\6.pptx", "$CurrentDir\7.pptx", "$CurrentDir\8.pptx", "$CurrentDir\9.pptx"
#Merge-PowerPointPresentation -Source $Presentations -Destination $CurrentDir\all.pptx -Verbose
