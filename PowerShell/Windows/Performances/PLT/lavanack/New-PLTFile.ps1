#requires -version 3 -RunAsAdministrator
#region Function definition
Function Get-InstalledLanguagePack
{
	[CmdletBinding()]
	Param()
	$InstalledLanguagePack = [System.Collections.ArrayList]@(([regex]::Matches($(Invoke-Expression -Command "dism.exe /online /Get-intl"),"([a-z]+-[a-z]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).value | Where {$_ -ne "en-US"} |  Select-Object -Unique | Sort-Object))
	if (!$InstalledLanguagePack)
    {
        $InstalledLanguagePack = [System.Collections.ArrayList]::new()
    }
    $InstalledLanguagePack.Insert(0, "en-US")
	return $InstalledLanguagePack
}

Function Install-LanguagePack
{
	[CmdletBinding()]
	Param(
        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path $_})]
        [Alias("Source")]
        [String]$Fullname,

        [Switch]$EnUs,

        [Alias("Reboot")]
        [Switch]$Restart
	)
    [array]$InstalledLanguagePack = Get-InstalledLanguagePack

    if ($InstalledLanguagePack)
    {
        $LanguagePackToInstall = Get-ChildItem -Path $Fullname -File | Where-Object -FilterScript { $_.BaseName -notmatch $($InstalledLanguagePack -join "|") }
    }
    else
    {
        $LanguagePackToInstall = Get-ChildItem -Path $Fullname -File
    }
    $Index=0
    Import-Module DISM

    $Updated = $false
    foreach ($CurrentLangToInstall in $LanguagePackToInstall)
    {
        $Index++
        Write-Verbose -Message "Installing $($CurrentLangToInstall.FullName) ..."
        Write-Progress -Activity "[$Index/$($LanguagePackToInstall.Count)] Installing $($CurrentLangToInstall.FullName) ..." -Status $("{0:N0} %" -f ($Index/$LanguagePackToInstall.Count * 100)) -PercentComplete ($Index/$LanguagePackToInstall.Count * 100)
        Add-WindowsPackage -PackagePath $CurrentLangToInstall.FullName -Online -NoRestart -Verbose
        $Updated = $true
    }

    #Add-WindowsPackage -PackagePath $Fullname -Online -NoRestart -Verbose
    if ($EnUs)
    {
        if ((Get-WinUILanguageOverride).Name -ne "en-us")
        {
            Write-Verbose "Setting WinUILanguageOverride to en-US ..."
            Set-WinUILanguageOverride "en-US" -Verbose
            $Updated = $true
        }
        else
        {
            Write-Verbose "WinUILanguageOverride already in en-US ..."
        }
    }
    if (($Restart) -and ($Updated))
    {
        Restart-Computer -Force
    }
}

function Push-WinUILanguageOverride
{
	[CmdletBinding()]
	Param(
        [ValidateSet("Logoff", "Reboot")]
        [String]$Action
	)
    begin
    {
    }
    process
    {
	    $CurrentWinUILanguageOverride=Get-WinUILanguageOverride
	    Write-Verbose "`$CurrentWinUILanguageOverride: $CurrentWinUILanguageOverride"
		$CurrentWinUILanguageOverride=$CurrentWinUILanguageOverride.Name
        [array]$InstalledLanguagePack = Get-InstalledLanguagePack
		$CurrentIndex=$InstalledLanguagePack.IndexOf($CurrentWinUILanguageOverride)
	    Write-Verbose "`$CurrentIndex: $CurrentIndex"
		if ($CurrentIndex -lt 0)
		{
			$CurrentWinUILanguageOverride = $InstalledLanguagePack -match $CurrentWinUILanguageOverride
			$CurrentIndex=$InstalledLanguagePack.IndexOf($CurrentWinUILanguageOverride)
		}

		if ($CurrentIndex -ge ($InstalledLanguagePack.Count-1))
		{
			Write-Verbose -Message "All language packs have been processed"
			return $null
		}
		else
		{
            $NextIndex=$CurrentIndex+1
		}

        Write-Verbose "Setting Win UI Language to: $($InstalledLanguagePack[$NextIndex])"
        Set-WinUILanguageOverride $InstalledLanguagePack[$NextIndex] -Verbose
        Write-Verbose "Waiting 5 seconds ..."
        Start-Sleep -Seconds 5 
        if ($Action -eq "Logoff")
        {
            logoff
        }
        elseif ($Action -eq "Reboot")
        {
            Restart-Computer -Force
        }
        else
        {
            return $InstalledLanguagePack[$NextIndex]
        }
    }
    end
    {
    }
}

Function Get-InstalledLanguagePack
{
	[CmdletBinding()]
	Param()
	$InstalledLanguagePack = Invoke-Expression -Command "dism.exe /online /Get-intl"
	$InstalledLanguagePack = [System.Collections.ArrayList](([regex]::Matches($InstalledLanguagePack,"([a-z]+-[a-z]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).value | Where {$_ -ne "en-US"} |  Select-Object -Unique | Sort-Object))
	if (!$InstalledLanguagePack)
    {
        $InstalledLanguagePack = [System.Collections.ArrayList]::new()
    }
    $InstalledLanguagePack.Insert(0, "en-US")
	return $InstalledLanguagePack
}

function Compare-PLTFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript({
					Test-Path -Path $_ -PathType Container
		})]
		#The directory where are stored the generated XML File
		[Alias('Directory', 'Path')]
		[String]$FullName
	)

	$PLTFiles=Get-ChildItem -Filter *_PFL.xml -File -Path $FullName -Recurse | Group-Object -Property Name -AsHashTable -AsString

	$Differences = New-Object -TypeName 'System.Collections.ArrayList'
	foreach ($XMLFile in $PLTFiles.Keys)
	{
		Write-Verbose -Message "Processing $XMLFile ..."
		$HT=@{}
		foreach ($CurrentXMLFile in $PLTFiles[$XMLFile])
		{
			Write-Verbose -Message "Processing $($CurrentXMLFile.FullName) ..."
			$OS = $($CurrentXMLFile.Directory.Name)
			Write-Verbose -Message "Operation System: $OS"
			Write-Verbose -Message "`$CurrentXMLFile: $($CurrentXMLFile.FullName)"
			[xml] $XMLContent = Get-Content -Path $($CurrentXMLFile.FullName)
			$LanguageNodes=$XMLContent.SelectNodes("/Counters/Counter")
			foreach ($CurrentLanguageNode in $LanguageNodes)
			{
				if ($HT.ContainsKey($CurrentLanguageNode.en))
				{
					$Data=$HT[$CurrentLanguageNode.en]
					if ($Data.Value -ne $CurrentLanguageNode.org)
					{
						Write-Verbose -Message "Difference found for [$($CurrentLanguageNode.en)] in $XMLFile ..."
						Write-Verbose -Message "[$($CurrentLanguageNode.en)]: [$OS]$($CurrentLanguageNode.org) vs. [$($Data.OS)]$($Data.Value)"
						$CurrentDifference = New-Object -TypeName PSObject -Property @{ EN = $CurrentLanguageNode.en; Locale = $($XMLFile -replace "_PFL.xml", ""); OS1 = $OS; Value1 = $CurrentLanguageNode.org; OS2 = $Data.OS; Value2 = $Data.Value}
                        $null = $Differences.Add($CurrentDifference)
					}
				}
				else
				{
					$Data = New-Object -TypeName PSObject -Property @{ OS = $OS; Value = $CurrentLanguageNode.org }
					$HT.Add($CurrentLanguageNode.en, $Data)
				}
			}
		}   
	}
	return $Differences
}

function New-PLTLangFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript({
					Test-Path -Path $_ -PathType Container
		})]
		#The directory where are stored the generated XML File
		[Alias('Directory', 'Path')]
		[String]$FullName
	)
	$PLTFiles=Get-ChildItem -Filter *_PFL.xml -File -Path $FullName -Recurse | Group-Object -Property Directory -AsHashTable

	foreach ($Directory in $PLTFiles.Keys)
	{
		$XMLFile = Join-Path -Path $($Directory.FullName) -ChildPath "PLT-lang.xml"
		Write-Verbose -Message "Generating $XMLFile ..."
		$XMLWriter = New-Object -TypeName System.XMl.XmlTextWriter -ArgumentList ($XMLFile, [System.Text.Encoding]::UTF8)
		$XMLWriter.Formatting = [ System.Xml.Formatting]::Indented
		$XMLWriter.Indentation = 1
		$XMLWriter.IndentChar = "`t"
		$XMLWriter.WriteStartDocument()
		#Adding a comment to have the date of the generation
		$XMLWriter.WriteComment("Generated (UTC): $(Get-Date -Format 'U')")
		$XMLWriter.WriteStartElement('languages')
		foreach ($CurrentPLTFile in $PLTFiles[$Directory])
		{
			Write-Verbose -Message "Adding locale: $($CurrentCulture.DisplayName)"
			$CurrentCulture=[cultureinfo]::GetCultureInfo($CurrentPLTFile.BaseName  -replace "_PFL", "")
			$XMLWriter.WriteStartElement('language')
			$XMLWriter.WriteElementString('displayName',$CurrentCulture.DisplayName)
			$XMLWriter.WriteElementString('fileName', $CurrentCulture.Name+"_PFL.xml")
			$XMLWriter.WriteEndElement()
		}
		$XMLWriter.WriteEndElement()
		$XMLWriter.WriteEndDocument()
		$XMLWriter.Flush()
		$XMLWriter.Close()
	}
}

function Get-ProcessedLanguage
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript({
					Test-Path -Path $_ -PathType Container
		})]
		#The directory where are stored the generated XML File
		[Alias('Directory', 'Path')]
		[String]$FullName
	)
	Write-Verbose -Message "`$FullName: $FullName"
    $ProcessedLanguages = (Get-ChildItem -Path $FullName -Filter "*-*.xml" -File).BaseName -replace "_.*$", ""
	Write-Verbose -Message "`$ProcessedLanguages (*$($ProcessedLanguages.Count)): $($ProcessedLanguages -join ", ")"
	return $ProcessedLanguages
}

#Getting Performance counter data from the local registry
function Get-PerformanceCounter
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True)]
        #The directory where are stored the generated XML File
		[object[]]$ProcessedLanguages,
		#Switch to force the performance data collection event if this language has already been processed
		[Switch]$Force
	)

	#Getting the current UI culture
	$CurrentUICulture = ([cultureinfo]::CurrentUICulture).Name
    Write-Verbose -Message "`$CurrentUICulture: $CurrentUICulture"
    Write-Verbose -Message "`Get-WinUILanguageOverride: $((Get-WinUILanguageOverride).Name)"
	if (($CurrentUICulture -notin $ProcessedLanguages) -or ($Force))
	{

		if (($CurrentUICulture -eq "en-US") -and ((Get-WinUILanguageOverride).Name -ne "en-US"))
        {
			Write-Verbose -Message "$CurrentUICulture has already been processed"
            return $null
        }
		elseif ($CurrentUICulture -notin $ProcessedLanguages)
		{
			Write-Verbose -Message "[New] $CurrentUICulture will be processed"
		}
		elseif ($Force)
		{
			Write-Verbose -Message "[Force] $CurrentUICulture will be processed"
		}
        else
        {
            return $null
        }
		#Hashtable for storing the performance counter data. The Index is the key
		$PerformanceCounters = @{}
		#Getting all performance counters
		$RegistryPerformanceCounters = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage' -Name Counter).Counter
		$PerformanceCountersNumber = $RegistryPerformanceCounters.Count

		for($i = 2; $i -lt $PerformanceCountersNumber; $i += 2)	
		{
			#Getting the performance counter index
			$CurrentIndex = $RegistryPerformanceCounters[$i]
			#Getting the performance counter name
			$CurrentPerformanceCounterName = $RegistryPerformanceCounters[$i+1]
			$PercentComplete = ($i/$PerformanceCountersNumber)
			Write-Progress -Id 2 -Activity "[$i/$PerformanceCountersNumber] Retrieving $CurrentUICulture - $('{0:D5}' -f [int]$CurrentIndex): $CurrentPerformanceCounterName" -Status ('Processing {0:p0}' -f $PercentComplete) -PercentComplete ($PercentComplete*100)
			#Only counter with a valid name
			if (($CurrentPerformanceCounterName) -and ($CurrentPerformanceCounterName.Length -gt 0))
			{
				Write-Verbose -Message "Getting Performance Counter with Index $('{0:D5}' -f [int]$CurrentIndex): [$CurrentPerformanceCounterName]"
				$CounterObject = New-Object -TypeName PSObject -Property @{
					#the index of the counter
					Index = $CurrentIndex
					#The name of the counter in the current locale, culture. Ie: en-US, fr-FR ...
					$CurrentUICulture = $CurrentPerformanceCounterName
				}
				$PerformanceCounters.Add($CurrentIndex,$CounterObject)
			}
		}
		Write-Progress -Id 2 -Completed -Activity 'Performance Counters Collection Complete !'
		Write-Host -Object 'Performance Counters Collection Complete !'
	}
	else
	{
		$PerformanceCounters = $null
		Write-Verbose -Message "[Skip] $CurrentUICulture has already been processed"
	}
	return $PerformanceCounters
}

#Importing performance counter data from a specified CSV file
function Import-PerformanceCounter
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({
					Test-Path -Path $_ -PathType Leaf
		})]
		#CSV file full name
		[String]$FullName
	)
	#Hashtable for storing the performance counter data. The Index is the key
	$PerformanceCounters = @{}
	Write-Verbose -Message "Importing the Performance Counters from $FullName"
	#Importing performance counter data with a valid Index
	$ImportedPerformanceCounters = Import-Csv -Path $FullName -Encoding 'UTF8'  | Where-Object -FilterScript {
		$_.Index
	}
	$Counter = 0
	#Going through the imported performance counter data
	foreach ($CurrentImportedPerformanceCounter in $ImportedPerformanceCounters)
	{
		$Counter++
		$PercentComplete = ($Counter/$ImportedPerformanceCounters.Count) 
		Write-Progress -Activity "[$Counter/$($ImportedPerformanceCounters.Count)] Importing Performance Counter with Index $('{0:D5}' -f [int]$CurrentImportedPerformanceCounter.Index)" -Status ('Processing {0:p0}' -f $PercentComplete) -PercentComplete ($PercentComplete*100)
		#If the counter with the current index has not been alreay imported
		if (!$PerformanceCounters.ContainsKey($CurrentImportedPerformanceCounter.Index))
		{
			#We add it to the Hashtable
			$PerformanceCounters.Add($CurrentImportedPerformanceCounter.Index, $CurrentImportedPerformanceCounter)
			Write-Verbose -Message "Importing Performance Counter with Index $('{0:D5}' -f [int]$($CurrentImportedPerformanceCounter.Index)): $CurrentImportedPerformanceCounter"
		}
		else
		{
			#else we raise a non-terminating error
			Write-Error -Message "$($CurrentImportedPerformanceCounter.Index) was already imported"
		}
	}
	Write-Progress -Completed -Activity 'Performance Counters Import Complete !'
	Write-Host -Object 'Performance Counters Import Complete !'
	return $PerformanceCounters
}

#Exporting performance counter data into a specified CSV file
function Export-PerformanceCounter
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
					Test-Path -Path (Split-Path -Path $_ -Parent) -PathType Container
		})]
		#CSV file full name
		[Alias('FilePath')]
		[String]$Path,
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
        [ValidateNotNullOrEmpty()]
		[hashtable]$PerformanceCounters
	)
	$PerformanceCounters.Values |
	Sort-Object -Property Index |
	Select-Object -Property Index, * -ErrorAction Ignore |
	Export-Csv -Path  $Path -Force -NoTypeInformation -Encoding 'UTF8'
	Write-Host -Object "The Performance Counters are exported to $Path"
}

#Merging the imported and the local performance counter 
function Merge-PerformanceCounter
{
	[CmdletBinding()]
	Param(
		#The imported performance counter
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)][ValidateNotNullOrEmpty()]
		[hashtable]$ImportedPerformanceCounters,
		#The local performance counter
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)][ValidateNotNullOrEmpty()]
		[Alias('LocalPerformanceCounters')]
		[hashtable]$CurrentCulturePerformanceCounters,
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)][ValidateNotNullOrEmpty()]
		#The current UI culture
		[String]$CurrentUICulture,
		#Switch to force the performance data if a counter with the same index already exists
		[Switch]$Force
	)
	#We work from the imported data
	$MergedPerformanceCounters = $ImportedPerformanceCounters
	#Going through the current localized performance counter
	foreach ($CurrentCulturePerformanceCounterValue in $CurrentCulturePerformanceCounters.Values)
	{
		Write-Verbose -Message "[Merge] Processing Performance Counter with Index $('{0:D5}' -f [int]$($CurrentCulturePerformanceCounterValue.Index)): $CurrentCulturePerformanceCounterValue"
		#If the index of the current localized counter already exists in the imported counter list: we can match the counter in different locales
		if ($MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index])
		{
			#If the counter name for the current culture is unknow, we add it to the hastable (the index is the key)
			if (-not ($MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].PSObject.Properties[$CurrentUICulture]))
			{
				Write-Verbose -Message "Updating the Performance Counter with Index $('{0:D5}' -f [int]$($CurrentCulturePerformanceCounterValue.Index)) with $CurrentUICulture=$($CurrentCulturePerformanceCounterValue.$CurrentUICulture)"
				$MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index] | Add-Member -MemberType NoteProperty -Name "$CurrentUICulture" -Value $CurrentCulturePerformanceCounterValue.$CurrentUICulture
				# $MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].PSObject.Properties[$CurrentUICulture]=$CurrentCulturePerformanceCounterValue.$CurrentUICulture
			}
			#If the counter name for the current culture is empty or null, we update it in the hastable (the index is the key)
			elseif (($MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].PSObject.Properties[$CurrentUICulture] -eq $null) -or ($MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].PSObject.Properties[$CurrentUICulture].Length -le 0))
			{
				Write-Verbose -Message "Updating $CurrentUICulture for the Performance Counter with Index $('{0:D5}' -f [int]$($CurrentCulturePerformanceCounterValue.Index)) because the previous value was null or empty"
				#$ImportedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].$CurrentUICulture=$CurrentCulturePerformanceCounterValue.$CurrentUICulture
				$MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].$CurrentUICulture = $CurrentCulturePerformanceCounterValue.$CurrentUICulture
			}
			#else (valid counter name) we update only if -force is specified
			elseif ($Force)
			{
				Write-Verbose -Message "Updating $CurrentUICulture for the Performance Counter with Index $('{0:D5}' -f [int]$($CurrentCulturePerformanceCounterValue.Index)) because -Force was explicit specified"
				$MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index].$CurrentUICulture = $CurrentCulturePerformanceCounterValue.$CurrentUICulture
			}
		}
		#else if it is a new counter
		else
		{
			Write-Verbose -Message "Setting the Performance Counter with Index $('{0:D5}' -f [int]$($CurrentCulturePerformanceCounterValue.Index)) with $CurrentUICulture=$($CurrentCulturePerformanceCounterValue.$CurrentUICulture)"
			$MergedPerformanceCounters[$CurrentCulturePerformanceCounterValue.Index] = $CurrentCulturePerformanceCounterValue
		}
	}
	Write-Host -Object 'PLT Files Merge Complete !'
	return $MergedPerformanceCounters
}

#creting a PLT file for all merged data
function ConvertTo-PLTFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
        [ValidateNotNullOrEmpty()]
		[hashtable]$PerformanceCounters,
		#Output directory: where to store the generated PLT file (XML format)
		[Parameter(Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $False)]
        [ValidateScript({
					Test-Path -Path $_ -PathType Container
		})]
		[Alias('Path')]
		[String]$OutputDir,

		#Switch to force XML file generation event if the file already exists
		[Switch]$Force
	)
	#Getting the source OS version 
	#$OSVersion = [Environment]::OSVersion.Version.Major.ToString()+'.'+[Environment]::OSVersion.Version.Minor.ToString()
	#Hashtable for XMLWriter where the locale is the key and the value if the XML content
	$XMLWriters = @{}
	$Languages = ($PerformanceCounters.Values |
		Get-Member -MemberType NoteProperty |
		Where-Object -FilterScript {
			@('Index', 'en-us') -notcontains $_.Name
	}).Name
	if (-not($Force))
	{
		$ProcessedLanguages = Get-ProcessedLanguage -Directory $OutputDir
		$Languages = $Languages  | Where-Object -FilterScript { $ProcessedLanguages -notcontains $_ }
	}
	#for each non en-us languages
	if ($Languages)
	{
		#For each performance counter data 
		$PerformanceCounters.Values | ForEach-Object `
		-Begin {
			#Before processing the first item in the collection we build an XMLWriter for the current language and store it in the Hashtable
			$Counter = 0
			$Languages | ForEach-Object -Process { 
				#Adding a prefix to identify the source OS
				$XMLWriter = New-Object -TypeName System.XMl.XmlTextWriter -ArgumentList ($(Join-Path -Path $OutputDir -ChildPath "$($_)_PFL.xml"), [System.Text.Encoding]::UTF8)
				$XMLWriter.Formatting = [ System.Xml.Formatting]::Indented
				$XMLWriter.Indentation = 1
				$XMLWriter.IndentChar = "`t"
				$XMLWriter.WriteStartDocument()
				#Adding a comment to have the date of the generation
				$XMLWriter.WriteComment("Generated (UTC): $(Get-Date -Format 'U')")
				#Adding a comment to have the OS Version because a same performance counter index may vary with the OS
				$XMLWriter.WriteComment("OS Version: $((Get-WmiObject -Class win32_operatingsystem).caption)")
				$XMLWriter.WriteStartElement('Counters')
				$XMLWriters.Add($_, $XMLWriter)
			}
		} `
		-Process { 
			#For every performance data
			$Counter++
			$PercentComplete = ($Counter/$PerformanceCounters.Count) 
			$CurrentPerformanceCounter = $_
			$Languages | ForEach-Object -Process {
				Write-Progress -Activity "[$Counter/$($PerformanceCounters.Count)] Generating PLT File for $_" -Status ('Processing {0:p0}' -f $PercentComplete) -PercentComplete ($PercentComplete*100)
				#If the counter doesn't exist in the current locale
				if (-not ($CurrentPerformanceCounter.$_))
				{
					Write-Warning -Message "The Performance counter with index $('{0:D5}' -f [int]$($CurrentPerformanceCounter.Index)) has no value for $($_). It will be skipped"
				}
				#If the counter doesn't exist in the en-us locale
				elseif (-not ($CurrentPerformanceCounter.'en-US'))
				{
					Write-Warning -Message "The Performance counter with index $('{0:D5}' -f [int]$($CurrentPerformanceCounter.Index)) has no value for en-US. It will be skipped"
				}
				#We generated the XML content for the counter: en-us and current locale matching
				else
				{
					if ($CurrentPerformanceCounter.$_ -ne $CurrentPerformanceCounter.'en-US')
					{
						$XMLWriter = $XMLWriters[$_]
						$XMLWriter.WriteComment("Counter Id: $($CurrentPerformanceCounter.Index)")
						$XMLWriter.WriteStartElement('Counter')
						$XMLWriter.WriteElementString('org',$CurrentPerformanceCounter.$_)
						$XMLWriter.WriteElementString('en',$CurrentPerformanceCounter.'en-US')
						$XMLWriter.WriteEndElement()
					}
					else
					{
						Write-Verbose -Message "[$($CurrentPerformanceCounter.$_)] is an english Perfomance Counter name. It will be skipped"
					}
				}
			}
		} `
		-End { 
			#After collection processing: We generate the XML files
			$Languages | ForEach-Object -Process {
				#Adding a prefix to identify the source OS
				$CurrentPLTFile = Join-Path -Path $OutputDir -ChildPath "$($_)_PFL.xml"
				$XMLWriter = $XMLWriters[$_]
				$XMLWriter.WriteEndElement()
				$XMLWriter.WriteEndDocument()
				$XMLWriter.Flush()
				$XMLWriter.Close()
				Write-Host -Object "The $CurrentPLTFile has been generated"
			}
		}
	}
	else
	{
		if ($Force)
		{
			Write-Verbose -Message "No non-english language found. The PLT file(s) won't be generated"
		}
		else
		{
			Write-Verbose -Message "No new non-english language found. The PLT file(s) won't be generated"
		}
	}
	Write-Progress -Completed -Activity 'PLT Files Generation Complete !'
	Write-Host -Object 'PLT Files Generation Complete !'
}

function New-PLTFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True)]
        [ValidateScript({  Test-Path -Path $_ -PathType Container })]
		[Alias('Path')]
		[String]$OutputDir,
		[Parameter(Mandatory = $True)]
        [ValidateScript({ Test-Path -Path (Split-Path -Path $_ -Parent) -PathType Container })]
		[String]$PerformanceCounterCSVFile
	)    

    #Getting local performance counters
    [array]$ProcessedLanguages = Get-ProcessedLanguage -Directory $OutputDir -Verbose
    $CurrentCulturePerformanceCounters = Get-PerformanceCounter -ProcessedLanguages $ProcessedLanguages -Verbose #Force
    if ($CurrentCulturePerformanceCounters)
    {

	    #Hashtable for potential performance counters to import
	    $ImportedPerformanceCounters = @{}
	    #If we have a file for importing performance counters
	    if (Test-Path -Path $PerformanceCounterCSVFile -PathType Leaf)
	    {
		    $ImportedPerformanceCounters = Import-PerformanceCounter -FullName $PerformanceCounterCSVFile -Verbose
	    }

	    #If we have no imported performance counters
	    if ($ImportedPerformanceCounters.Count -le 0)
	    {
		    Write-Verbose -Message 'No Imported Performance Counters'
		    #Export the performance counters to a CSV file
		    Export-PerformanceCounter -Path $PerformanceCounterCSVFile -PerformanceCounter $CurrentCulturePerformanceCounters -Verbose
		    #Generating PLT File
		    ConvertTo-PLTFile -PerformanceCounter $CurrentCulturePerformanceCounters -OutputDir $OutputDir -Verbose
	    }
	    else
	    {
		    #Merging local and imported performance counter data
		    $MergedPerformanceCounters = Merge-PerformanceCounter -ImportedPerformanceCounters $ImportedPerformanceCounters -CurrentCulturePerformanceCounters $CurrentCulturePerformanceCounters -CurrentUICulture $CurrentUICulture -Verbose #-Force 
		    #We export the performance counters to a CSV file
		    Export-PerformanceCounter -Path $PerformanceCounterCSVFile -PerformanceCounter $MergedPerformanceCounters -Verbose
		    #Generating PLT File
		    ConvertTo-PLTFile -PerformanceCounter $MergedPerformanceCounters -OutputDir $OutputDir -Verbose
	    }
    }
    else
    {
	    Write-Verbose -Message "$CurrentUICulture has already been processed ..."
    }

}

#endregion

#CAUTION : Performance Counter Index are not neccessary the same accross the OS. So work with only one OS version at a time
Clear-Host
#Install-Module -Name Autologon
#Import-Module -Name Autologon

# Getting the this script path
$CurrentScript = $MyInvocation.MyCommand.Path
# Getting the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#Getting the current UI culture (ie. : en-US, fr-FR ...)
$CurrentUICulture = ([cultureinfo]::CurrentUICulture).Name

#Getting the source OS Information
$null=(Get-WmiObject Win32_OperatingSystem).caption -match "^\w+\s+(?<OSName>.+)\s+\w+$"
$OSName = $Matches["OSName"]

#Dedicated folder per OS
$OSDir = Join-Path -Path $CurrentDir -ChildPath $OSName
$null = New-Item -ItemType Directory -Path $OSDir -Force

#CSV to keep the performances counter processing across the OSes
$PerformanceCounterCSVFile = Join-Path -Path $OSDir -ChildPath $((Get-Item $CurrentScript).BaseName + ".csv")
#CSV to track the counter name differences across the OSes
$DifferencesCSVFile = Join-Path -Path $CurrentDir -ChildPath "Differences.csv"


#To do once before the generation of the PLT file : Installing language packs and set to en-US and restart the server
#Install-LanguagePack -Source D:\x64\langpacks -EnUs -Restart


#PLT File for the translation current language ==> en-US
New-PLTFile -OutputDir $OSDir -PerformanceCounterCSVFile $PerformanceCounterCSVFile

#File referencing all translation files for PLT
New-PLTLangFile -FullName $OSDir -Verbose

#Next language pack to process and reboot (and you just have to recall this script until the last language pack is processed)
Push-WinUILanguageOverride -Verbose -Action Reboot

#Uncomment only when you want to find counter name inconsistencies across the os versions 
#$Differences = Compare-PLTFile -FullName $CurrentDir -Verbose | Sort-Object -Property EN | Select-Object -Property * -Unique
#$Differences | Select-Object -Property EN, Locale, OS1, Value1, OS2 , Value2 | Export-Csv -Path $DifferencesCSVFile -NoTypeInformation
