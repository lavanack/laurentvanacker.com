#requires -version 4 -Module WebAdministration

Import-Module -Name WebAdministration

#Region Function definition
<#Get the pair Instance, PID for the running worker processes from Performance Data Collection
		Instance  PID
		--------  ---
		w3wp#6   4504
		w3wp#5   5848
		w3wp#4   5088
		w3wp#3   5520
		w3wp#2   3884
		w3wp#1   5476
		w3wp     5964
#>
function Get-W3WPDataFromPerformanceMonitor
{
	[CmdletBinding()]
	Param()
	#Returned results will be stored into this array 
	$Data = @()
	#Regular expression pattern to find the instance name in the counter path
	$Pattern = @([regex]'^.*\((?<INSTANCE>(.*))\).*$')
	#Get Path a,d PID from running worker processes from Performance Monitor
	$Counters = Get-Counter -Counter '\Process(w3wp*)\ID Process' -ErrorAction SilentlyContinue |
	Select-Object -ExpandProperty CounterSamples |
	Select-Object -Property CookedValue, Path
	#Processing the returned collection
	foreach ($CurrentCounter in $Counters)
	{
		#Regular expression matching to keep only the instance name (for instance: w3wp#1)        
		$CurrentMatches = $CurrentCounter.Path |
		Select-String -Pattern $Pattern |
		Select-Object -ExpandProperty matches
		if ($CurrentMatches)
		{
			#Getting the instance name (for instance: w3wp#1)        
			$CurrentInstance = $CurrentMatches.Groups[$currentMatches.Groups.Count-1].Value
			#Creating an object with the instance name and the path
			$CurrentData = New-Object -TypeName PSObject -Property @{
				PID      = $CurrentCounter.CookedValue
				Instance = $CurrentInstance
			}
			#Storing the object into the array
			$Data += $CurrentData
		}
	}
	#Returning the data 
	return $Data
}

<#Get the link between the applications, the sites and the site ids from ServerManager
		Applications                                             Site                          SiteId
		------------                                             ----                          ------
		{Default Web Site/}                                      Default Web Site                   1
		{www.contoso.com/}                                       www.contoso.com                    2
		{www.northwindtraders.com/, www.northwindtraders.com/HR} www.northwindtraders.com           3
		{www.microsoft.com/}                                     www.microsoft.com                  4
		{intranet.northwindtraders.com/}                         intranet.northwindtraders.com      5
#>
function Get-WebsitesFromServerManager
{
	[CmdletBinding()]
	Param()
	#Loading the Web Administration DLL for handling ServerManager
	#$null = [System.Reflection.Assembly]::LoadFrom( "$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll" )
	Add-Type -Path "$env:systemroot\system32\inetsrv\Microsoft.Web.Administration.dll"
	#Creating a ServerManager Object
	$ServerManager = New-Object -TypeName Microsoft.Web.Administration.ServerManager
	#Getting applications and related sites and site ids.
	$WebApplications = $ServerManager.sites | Select-Object -Property Applications, @{
		Name       = 'Site'
		Expression = {
			$_.Name
		}
	}, @{
		Name       = 'SiteId'
		Expression = {
			$_.Id
		}
	}
	#Return them
	return $WebApplications
}

<#Get the pair ApplicationPoolName, PID for the running worker processes from Web Configuration
		ApplicationPoolName      PID 
		-------------------      --- 
		DefaultAppPool           5964
		HR                       5476
		www.contoso.com          3884
		www.northwindtraders.com 5520
		www.microsoft.com        5088
		www.contoso.com          5848
		www.contoso.com          4504
#>
function Get-W3WPDataFromWebConfiguration
{
	return Get-WebConfiguration system.applicationHost/applicationPools/workerProcesses/* | Select-Object -Property @{Name="ApplicationPoolName"; Expression={$_.appPoolName}}, @{Name="PID"; Expression={$_.ProcessId}}
}

<#Get the data by using the 3 previous functions to have a clear overview of the hosted web applications
		Instance                 ApplicationPool          SiteId Site                          Application                    PID                W3SVCPath         
		--------                 ---------------          ------ ----                          -----------                    ---                ---------         
		{w3wp}                   DefaultAppPool                1 Default Web Site              Default Web Site/              {5964}             _LM_W3SVC1_ROOT   
		{w3wp#2, w3wp#5, w3wp#6} www.contoso.com               2 www.contoso.com               www.contoso.com/               {3884, 5848, 4504} _LM_W3SVC2_ROOT   
		{w3wp#3}                 www.northwindtraders.com      3 www.northwindtraders.com      www.northwindtraders.com/      {5520}             _LM_W3SVC3_ROOT   
		{w3wp#1}                 HR                            3 www.northwindtraders.com      www.northwindtraders.com/HR    {5476}             _LM_W3SVC3_ROOT_HR
		{w3wp#4}                 www.microsoft.com             4 www.microsoft.com             www.microsoft.com/             {5088}             _LM_W3SVC4_ROOT   
		{w3wp#3}                 www.northwindtraders.com      5 intranet.northwindtraders.com intranet.northwindtraders.com/ {5520}             _LM_W3SVC5_ROOT   

#>
function Get-W3WPData
{
	[CmdletBinding()]
	Param()

	#the pair Instance, PID for the running worker processes from Performance Data Collection
	$W3WPDataFromPerformanceMonitor = Get-W3WPDataFromPerformanceMonitor
	#Getting the pair ApplicationPoolName, PID for the running worker processes from WMI
	#$W3WPDataFromWebConfiguration = Get-W3WPDataFromWMI
	$W3WPDataFromWebConfiguration = Get-W3WPDataFromWebConfiguration
	#Getting the link between the applications, the sites and the site ids from ServerManager
	$WebsitesFromServerManager = Get-WebsitesFromServerManager

	#Returned results will be stored into this array 
	$Data = @()
	#Hastable to get the worker process instance (from performance monitor) by using the PID as a key
	$W3WPDataFromPerformanceMonitorHT = $W3WPDataFromPerformanceMonitor | Group-Object -Property PID -AsHashTable -AsString
	#Processing each website
	foreach ($CurrentWebsite in $WebsitesFromServerManager)
	{
		#Processing each application for the processed website (from ServerManager)
		foreach ($CurrentWebApplication in $CurrentWebsite.Applications)
		{
			#Creating an object with the application, the website, the website id, the application pool name, the pids (can be multiple in case of web gardening) and the instances (can be multiple in case of web gardening) from performance monitor
			$ApplicationData = New-Object -TypeName PSObject -Property @{
				Application     = $($CurrentWebsite.Site+$CurrentWebApplication.Path)
				Site            = $CurrentWebsite.Site
				SiteId          = $CurrentWebsite.SiteId
				ApplicationPool = $CurrentWebApplication.ApplicationPoolName
				PID             = @()
				Instance        = @()
			}
			#Processing each worker process from data coming from WMI
			foreach ($CurrentW3WPData in $W3WPDataFromWebConfiguration)
			{
				#If the application pools are matching between the WMI and ServerManager data
				if ($ApplicationData.ApplicationPool -eq $CurrentW3WPData.ApplicationPoolName)
				{
					#Adding the PID to the PID collection
					$ApplicationData.PID += $CurrentW3WPData.PID
					#Adding the worker process instance to the worker process instance collection
					$ApplicationData.Instance += $W3WPDataFromPerformanceMonitorHT[$CurrentW3WPData.PID -as [string]].Instance
					#The PID and the associated instance are stored in the same order into the two differents collections
				}
			}
			#region Generating the W3SVC Path under the form _LM_W3SVC<ID>_ROOT[_APPLICATION] like _LM_W3SVC3_ROOT_HR
			$W3SVCPath = $ApplicationData.Application.Substring($ApplicationData.Application.IndexOf('/')+1)
			$W3SVCPath = $W3SVCPath -replace '/', '_'
			if ($W3SVCPath)
			{
				$W3SVCPath = '_LM_W3SVC' + $ApplicationData.SiteId + '_ROOT_'+ $W3SVCPath
			}
			else
			{
				$W3SVCPath = '_LM_W3SVC' + $ApplicationData.SiteId + '_ROOT'
			}
			$W3SVCPath = $W3SVCPath.ToUpper()
			#endregion
			#Adding the W3SVC Path as a property of the object we have previously created 
			$ApplicationData | Add-Member -MemberType NoteProperty -Name 'W3SVCPath' -Value $W3SVCPath
			#Storing the object into the array
			$Data += $ApplicationData
		}
	}
	#Returning the data 
	return $Data
}
#endregion

Clear-Host

$Data = Get-W3WPData
$Data | Format-Table -Property * -Force -AutoSize