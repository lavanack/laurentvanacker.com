#requires -version 4 -Module WebAdministration

#region Function Definitions
function Expand-String 
{ 
	<#
			.SYNOPSIS
			Expands a single quoted string containing a reference to a PowerShell variable or to an environment variable.

			.DESCRIPTION
			Expands a single quoted string containing a reference to a PowerShell variable or to an environment variable.

			.PARAMETER Value
			The string to expand (Mandatory)

			.PARAMETER EnvironmentVariable
			A switch to speicify a string containing a reference to an environment variable

			.EXAMPLE
			'$($host.Version)' | Expand-string
			Expands the $host.Version PowerShell Built-in variable

			.EXAMPLE
			Expand-String -Value "%temp%" -EnvironmentVariable
			Expands the %Temp% MS-DOS environment variable
		
			.INPUTS
			System.String

			.OUTPUTS
			System.String

	#>
	[CmdletBinding()]
	param( 
		[Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)] 
		[string]$Value, 

		[switch]$EnvironmentVariable 
	)
	#If we specified that the specified value is related to an environment variable
	if($EnvironmentVariable)
	{
		[System.Environment]::ExpandEnvironmentVariables($Value)
	} 
	else 
	{
		$ExecutionContext.InvokeCommand.ExpandString($Value)
	} 
} 

function Get-PhysicalPath
{
	<#
			.SYNOPSIS
			Returns the expanded physical path(s) for the website(s) specified as argument.

			.DESCRIPTION
			Returns the expanded physical path(s) for the website(s) specified as argument.

			.PARAMETER Site
			Optional parameter to specify the web site name(s) for which you want get the physical path. It can contains a collection of web site names. If you omit the function will return the physical path for all hosted web sites.

			.EXAMPLE
			Get-PhysicalPath

			.EXAMPLE
			Get-PhysicalPath -Site "Default Web Site"

			.EXAMPLE
			Get-PhysicalPath -Site "Default Web Site", "www.contoso.com"

			.INPUTS
			System.String[]

			.OUTPUTS
			System.String[]

	#>	
	[CmdletBinding()]
	param( 
		[Parameter(Mandatory = $false)] 
		[Alias('Name')]
		#Web site name(s)
		[String[]]$Site
	)
	#Array for storing all physical path related to the specified web sites
	$PhysicalPaths = @()
	#If no site has been specified we get all hosted web sites
	if (!$Site)
	{
		$WebSites = Get-Website
	}
	#If we specified one or multiple web site names we filter to get only those related to the specified names
	else
	{
		$WebSites = Get-Website | Where-Object -FilterScript {
			$_.Name -in $Site
		}
	}
	#For each specified website
	$WebSites | ForEach-Object  -Process { 
		#Getting the physical path of the sites and storing it in the array
		$PhysicalPaths += Expand-String -Value $_.PhysicalPath -EnvironmentVariable
		Write-Verbose -Message "Adding Physical Path for Site: $($_.Name) (Path:$($_.PhysicalPath))"

		#Getting the physical path of the nested applications and storing it in the array
		Get-WebApplication -Site $_.Name | ForEach-Object  -Process { 
			$PhysicalPaths += Expand-String -Value $_.PhysicalPath -EnvironmentVariable
			Write-Verbose -Message "`tAdding Physical Path for Application: $($_.Path) (Path:$($_.PhysicalPath))"
		}

		#Getting the physical path of the nested virtual directories and storing it in the array
		Get-WebVirtualDirectory -Site $_.Name | ForEach-Object  -Process {
			$PhysicalPaths += Expand-String -Value $_.PhysicalPath -EnvironmentVariable
			Write-Verbose -Message "`tAdding Physical Path for Virtual Directory: $($_.Path) (Path:$($_.PhysicalPath))"
		}
	}
	#Spkiiping duplicate entries
	$PhysicalPaths = @($PhysicalPaths | Select-Object -Unique)
	#Returning physical paths
	return $PhysicalPaths
}

function Get-DebuggableAttribute
<#
		.SYNOPSIS
		Returns an hashtable containing all assemblies and related assemblies found in the specified physical paths or web site name(s)

		.DESCRIPTION
		Returns an hashtable containing all assemblies and related assemblies found in the specified physical paths or web site name(s)
		The keys are the found assemblies (under the form a custom PowerShell object) and the values are arays containing referenced assemblies (under the form a custom PowerShell object)

		.PARAMETER Site
		Optional parameter to specify the web site name(s) from where you want get assembly informations. If you omit the function will return the physical path for all hosted web sites.

		.PARAMETER Path
		Optional parameter to specify the physical path(s) from where you want get assembly informations.

		.EXAMPLE
		Get-DebuggableAttribute

		.EXAMPLE
		Get-DebuggableAttribute -Path "C:\inetpub\wwwroot","D:\inetpub\wwwroot"

		.EXAMPLE
		Get-DebuggableAttribute -Path "C:\inetpub\wwwroot" -Verbose

		.EXAMPLE
		Get-DebuggableAttribute -Site "Default Web Site" -Verbose

		.INPUTS
		System.String[]

		.OUTPUTS
		System.Array

#>	
{
	[CmdletBinding(DefaultParameterSetName = 'Site')]
	param(
		[Parameter(Mandatory = $false,ParameterSetName = 'Site')] 
		[ValidateNotNullOrEmpty()]
		[Alias('Name')]
		#if Web site names have been specified
		[String[]]$Site,
		
		[Parameter(Mandatory = $false,ParameterSetName = 'File',ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
					Test-Path -Path $_ -PathType Container
		})]
		#if file paths have been specified
		[alias('FullName')]
		[String[]]$Path
	)
	
	Write-Verbose -Message "Parameter Set : $($psCmdlet.ParameterSetName)"
	#if Web site names have been specified
	if (($psCmdlet.ParameterSetName) -eq 'Site')
	{
		if ($Site)
		{
			$PhysicalPaths = Get-PhysicalPath -Site $Site
		}
		else
		{
			$PhysicalPaths = Get-PhysicalPath
		}
	}
	#if file paths have been specified
	elseif (($psCmdlet.ParameterSetName) -eq 'File')
	{
		$PhysicalPaths = $Path
	}
	
	#Array for storing all data
	$DebuggableAttribute = @()
	#Going through physical path collection
	ForEach ($CurrentPhysicalPath in $PhysicalPaths)
	{
		#For every *.dll file inside the path
		ForEach ($CurrentDLL in Get-ChildItem -Path $CurrentPhysicalPath -Recurse -File -Filter *.dll)
		{
			Write-Verbose -Message "Processing $($CurrentDLL.Name) ..."
			try 
			{ 
				#Loading the DLL
				$AssemblyLoaded = [System.Reflection.Assembly]::LoadFile($CurrentDLL.FullName)
				#Getting the DLL attributes 
				$attributes = $AssemblyLoaded.GetCustomAttributes([System.Diagnostics.DebuggableAttribute], $false)
				Write-Verbose -Message "$($CurrentDLL.FullName) was successfully loaded."
				$Details = 'Non debuggable DLL'
				if ($attributes.IsJITTrackingEnabled -eq $true)
				{
					if ($attributes.IsJITOptimizerDisabled -eq $true)
					{
						$Details = 'Non-optimized debug DLL'
					}
					elseif ($attributes.IsJITTrackingEnabled -eq $false)
					{
						$Details = 'Optimized debug DLL'
					}
				}
				else
				{
					if ($attributes.IsJITOptimizerDisabled -eq $true)
					{
						$Details = 'Non-optimized release DLL'
					}
					elseif ($attributes.IsJITTrackingEnabled -eq $false)
					{
						$Details = 'Optimized release DLL'
					}
				}
				#Storing data into a PSObject
				$CurrentAssemblyObject = New-Object -TypeName PSObject -Property @{
					ServerName             = $Env:ComputerName
					Name                   = $AssemblyLoaded.GetName()
					Location               = $AssemblyLoaded.Location
					IsJITOptimizerDisabled = $attributes.IsJITOptimizerDisabled
					IsJITTrackingEnabled   = $attributes.IsJITTrackingEnabled
					ImageRuntimeVersion    = $AssemblyLoaded.ImageRuntimeVersion
					IsValidDotNetAssembly  = $true
					Details                = $Details
				}
				$DebuggableAttribute += $CurrentAssemblyObject
			} 
			catch  
			{
				# it is not a valid dotnet assembly 
				Write-Verbose -Message "$($CurrentDLL.FullName) was not successfully loaded and is now tagged as a no valid .Net assembly"
				Write-Warning -Message "[Exception] $_.Exception.Message"
				#Storing data into a PSObject
				$CurrentAssemblyObject = New-Object -TypeName PSObject -Property @{
					ServerName             = $Env:ComputerName
					Name                   = $null
					Location               = $CurrentDLL.FullName
					IsJITOptimizerDisabled = $null
					IsJITTrackingEnabled   = $null
					ImageRuntimeVersion    = $null
					IsValidDotNetAssembly  = $false
					Details                = $null
				}
				#Storing the new created object into the collection				
				$DebuggableAttribute += $CurrentAssemblyObject
			} 
			$AssemblyLoaded = $null
		}
	}
	#Returning the collection
	return $DebuggableAttribute
}

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
# Creating CSV file name based on the script full file path and by appending the timestamp at the end of the file name
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '_'+$(Get-Date  -Format 'yyyyMMddTHHmmss')+'.csv')

# Get assembly infos for a given web site in verbose mode
# $DebuggableAttribute = Get-DebuggableAttribute -Site 'Default Web Site' -Verbose

# Get assembly infos for a all hosted web sites
$DebuggableAttribute = Get-DebuggableAttribute

# Get assembly infos for a all hosted web sites in verbose mode
# $DebuggableAttribute = Get-DebuggableAttribute -Verbose

# Get assembly infos for two given web sites in verbose mode
# $DebuggableAttribute = Get-DebuggableAttribute -Site "Default Web Site", "www.contoso.com" -Verbose

# Get assembly infos for a given directory in verbose mode
# $DebuggableAttribute = Get-DebuggableAttribute -Path "C:\inetpub\wwwroot" -Verbose

# Get assembly infos for a given directory by using a pipeline in verbose mode
# $DebuggableAttribute = Get-Item -Path "C:\inetpub\wwwroot" | Get-DebuggableAttribute -Verbose

$DebuggableAttribute

# Export the assembly to a default CSV file in the current directory
$DebuggableAttribute | Export-Csv -Path $CSVFile -Force -NoTypeInformation
Write-Host -Object "Results are available in '$CSVFile'"

    