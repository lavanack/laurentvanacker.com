#requires -version 2

#requires -Module PowerDbg
Import-Module -Name PowerDbg

#region My function definitions
function New-PDBGCrashAnalysis
{
	<#
			.SYNOPSIS
			Runs a debugging session for the dump(s) passed as parameter(s)

			.DESCRIPTION
			Runs a debugging session for the dump(s) passed as parameter(s)

			.PARAMETER FullName
			The full file path of the dump(s) to analyze

			.EXAMPLE
			New-PDBGCrashAnalysis -FullName "C:\Tools\Dumps\w3wp.exe_160518_000457.dmp", "C:\Tools\Dumps\w3wp.exe_160518_002041.dmp" -Verbose
			Runs a debugging session for the two specified worker process dumps ("C:\Tools\Dumps\w3wp.exe_160518_000457.dmp", "C:\Tools\Dumps\w3wp.exe_160518_002041.dmp" )

			.EXAMPLE
			Get-ChildItem -Path 'C:\Temp' -Filter 'w3wp*.dmp' -Recurse | New-PDBGCrashAnalysis -Verbose
			Returns all worker processes dumps in the C:\Temp folder (and its subfolders) and runs a debugging session for all of them.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		#The BLG File to convert : Checking if the file exists and has the .dmp extension
		[ValidateScript({
					(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.dmp$')
		})]
		[alias('Source', 'Dump')]
		[String[]]$FullName
	)
	begin
	{
		#Array for storing the results
		$Analyses = @()
	}
	process
	{
		#For all files passed as argument outside a pipeline context
		Foreach ($CurrentFullName in $FullName)
		{
			Write-Verbose -Message "Processing $CurrentFullName ..."
			
			# Close proactively any existing debugger session if already connected for some reason
			Exit-DbgSession #Disconnect-Windbg
			Write-Verbose -Message 'Closing proactively any existing debugger session if already connected for some reason ...'

			Write-Verbose -Message 'Creating new DBG Session.'
			New-DbgSession -Dump $CurrentFullName

			Write-Verbose -Message 'Loading sos and clr extensions'
			Load-DbgExtension sos
			Load-DbgExtension clr

			#Invoke-DbgCommand !pe2
			Write-Verbose -Message 'Invoking DBG command : !pe'
			$Exception = Invoke-DbgCommand !pe
			Write-Verbose -Message 'Invoking DBG command : !ClrStack'
			$ClrStack = Invoke-DbgCommand !ClrStack

			Write-Verbose -Message "Exception : $Exception "
			Write-Verbose -Message "ClrStack : $ClrStack "

			$Analyses += New-Object -TypeName PSObject -Property @{
				FullName  = $CurrentFullName
				Exception = $Exception[1]
				Message   = $Exception[2]
				ClrStack  = $ClrStack -join "`r`n"
			}

			Write-Verbose -Message 'Disconnecting new DBG Session'
			Exit-DbgSession #Disconnect-Windbg
		}
	}
	end
	{
		#returning the data array
		return $Analyses
	}
}
#endregion

Clear-Host
# Getting the this script path
$CurrentScript = $MyInvocation.MyCommand.Path
# Getting the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent

# Creating CSV file name based on the script full file path and by appending the timestamp at the end of the file name
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '_'+$(Get-Date  -Format 'yyyyMMddTHHmmss')+'.csv')

# Without pipeline use
#$Analyses = New-PDBGCrashAnalysis -FullName "C:\Tools\Dumps\w3wp.exe_160518_000457.dmp", "C:\Tools\Dumps\w3wp.exe_160518_002041.dmp" -Verbose
# With pipeline use
# Looking for dumps in the script folder (and subfolders)
$Analyses = Get-ChildItem -Path $CurrentDir -Filter 'w3wp*.dmp' -Recurse | New-PDBGCrashAnalysis -Verbose
$Analyses |
Group-Object -Property Message |
Sort-Object -Property Count -Descending |
Select-Object -Property @{
	Name       = 'Message'
	Expression = {
		$_.Name
	}
}, Count
#$Analyses | Format-List * -Force
$Analyses | Export-Csv -Path $CSVFile -Force -NoTypeInformation
Write-Host -Object "Results are available in '$CSVFile'"