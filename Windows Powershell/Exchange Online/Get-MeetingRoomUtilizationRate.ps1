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
#For an Microsoft 365 Test Tenant : http://demos.microsoft.com/
#requires -version 3

#=======================================================================================
#region function definitions
#=======================================================================================
Function Get-AccessToken
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantName, 
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $ClientID, 
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $redirectUri, 
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $resourceAppIdURI, 
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [string] $CredPrompt = "Auto"
    )

    Write-Host -Object 'Checking for AzureAD module...'
    $AadModule = Get-Module -Name 'AzureAD' -ListAvailable
    if ($null -eq $AadModule) 
    {
        Write-Host -Object "AzureAD Powershell module is not installed. The module can be installed by running 'Install-Module AzureAD' from an elevated PowerShell prompt. Stopping." -ForegroundColor Yellow
        exit
    }
    if ($AadModule.count -gt 1) 
    {
        $Latest_Version = ($AadModule |
            Select-Object -Property version |
        Sort-Object)[-1]
        $AadModule = $AadModule | Where-Object -FilterScript {
            $_.version -eq $Latest_Version.version
        }
        $adal = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
        $adalforms = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
    }
    else 
    {
        $adal = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
        $adalforms = Join-Path -Path $AadModule.ModuleBase -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
    }
    $null = [System.Reflection.Assembly]::LoadFrom($adal)
    $null = [System.Reflection.Assembly]::LoadFrom($adalforms)
    $authority = "https://login.microsoftonline.com/$TenantName"
    $authContext = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $authority
    $platformParameters = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters' -ArgumentList $CredPrompt
    $authenticationResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $ClientID, $redirectUri, $platformParameters)
    
    if ( !$authenticationResult.IsFaulted )
    {
        return $authenticationResult.Result
    }
    else
    {
        return $null
    }
}

#Create a new custom object for storing a history of a meeting room for the specified period 
Function New-RoomHistory
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        #The start date of the history
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartDate = $((Get-Date).AddYears(-1)),

        #The end date of the history
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [datetime]$EndDate = $(Get-Date),

        #Skipping some days ?
        [Parameter(Mandatory = $False)]
        [system.dayofweek[]]$Skip, 

        #Conflicting Meeting
        [Parameter(Mandatory = $False)]
        [switch]$ConflictingMeetings
    )


    #Hashtable where the key is a day (from the start date to the end date) and the value a custom object. We will get one hashtable per meeting room
    $RoomHistory = @{}
    Write-Verbose -Message 'Adding Measure-UtilizationRate Script Method to the Room History Hashtable ...'

    Write-Verbose -Message 'Adding ConflictingMeetings Note Property to the Room History Hashtable ...'
    #Extending the hashtable by adding a script property to get the overall utilization rate of the meeting room
    Add-Member -InputObject $RoomHistory -MemberType NoteProperty -Name 'ConflictingMeetings' -Value $ConflictingMeetings

    #Extending the hashtable by adding a script method to the hashtable to measure the utilization rate of a room
	Add-Member -InputObject $RoomHistory ScriptMethod Measure-UtilizationRate {
		param( [int]$start, [int]$end) foreach($CurrentKey in $this.Keys) 
		{
			$($this[$CurrentKey]).'Measure-UtilizationRate'($start,$end, $this.ConflictingMeetings)
		}
	}

    Write-Verbose -Message 'Adding UtilizationRate Script Property to the Room History Hashtable ...'
    #Extending the hashtable by adding a script property to get the overall utilization rate of the meeting room
    Add-Member -InputObject $RoomHistory -MemberType ScriptProperty -Name 'UtilizationRate' -Value {
        ($this.Values | Measure-Object -Property UtilizationRate -Average).Average
    }
    #From the start to the end dates					
    for ($Index = $StartDate.Date; $Index -lt $EndDate; $Index = $Index.AddDays(1))
    { 
        #If we have to skip some days (for instance Saturday and Sunday)
        if ($Index.DayOfWeek -in $Skip)
        {
            Write-Verbose -Message "Skipping $($Index.ToLongDateString()) ..."
            Continue
        }
        #For each day we create a custom object with the date the array of the time slots, the utilization rate and the total meeting duration for the time range
        $DayData = New-Object -TypeName PSObject -Property @{
            Date                = $Index.Date
            AdjustedMeetingTime = @()
            MeetingTime         = @()
            UtilizationRate     = 0
            Duration            = 0
        }
        #Extending the object by adding a script property to get the Day Of week
        Add-Member -InputObject $DayData -MemberType ScriptProperty -Name 'DayOfWeek' -Value {
            $this.Date.DayOfWeek
        }
        #Extending the object by adding a script property to get the meeting times (| separated)
        Add-Member -InputObject $DayData -MemberType ScriptProperty -Name 'MeetingTimes' -Value {
            ($this.MeetingTime | Sort-Object) -join '|'
        }
        #Extending the object by adding a script property to get the meeting times (| separated)
        Add-Member -InputObject $DayData -MemberType ScriptProperty -Name 'AdjustedMeetingTimes' -Value {
            ($this.AdjustedMeetingTime | Sort-Object) -join '|'
        }
        #Extending the object by adding a script property to get the meeting number 
        Add-Member -InputObject $DayData -MemberType ScriptProperty -Name 'MeetingNb' -Value {
            $this.MeetingTime.Count
        }
        #Extending the object by adding a script property to get the adjusted meeting number 
        Add-Member -InputObject $DayData -MemberType ScriptProperty -Name 'AdjustedMeetingNb' -Value {
            $this.AdjustedMeetingTime.Count
        }
        #Extending the object by adding a script method to get the utilization rate of the meeting room for all days (only between the start and end times)
        Add-Member -InputObject $DayData ScriptMethod Measure-UtilizationRate { 
			param( [int]$start, [int]$end, $ConflictingMeetings) 
            $this.Duration = 0
            if ($ConflictingMeetings)
            {
                $this.AdjustedMeetingTime = [array](Join-MeetingTime -MeetingTime $this.MeetingTime)
            }
            else
            {
                $this.AdjustedMeetingTime = $this.MeetingTime
            }
            foreach($CurrentMeetingTime in $this.AdjustedMeetingTime)
            {
                Write-Verbose "`$CurrentMeetingTime : $CurrentMeetingTime"
                $CurrentMeetingTimeStart, $CurrentMeetingTimeEnd = $CurrentMeetingTime.Split("-")
                $CurrentMeetingTimeStart = [datetime]$CurrentMeetingTimeStart.Trim()
                $CurrentMeetingTimeEnd = [datetime]$CurrentMeetingTimeEnd.Trim()
                if ($CurrentMeetingTimeStart.Hour -lt $start)
                {
                    $CurrentMeetingTimeStart=[datetime]"$($CurrentMeetingTimeStart.ToShortDateString()) $($start):00:00"
                }
                if ($end -ge 24)
                {
                    $CurrentMeetingTimeEnd=[datetime]"$($CurrentMeetingTimeStart.AddDays(1).ToShortDateString()) 00:00:00"
                }
                elseif (($CurrentMeetingTimeEnd.Hour -gt $end) -or ($CurrentMeetingTimeEnd.Hour -eq 0))
                {
                    $CurrentMeetingTimeEnd=[datetime]"$($CurrentMeetingTimeStart.ToShortDateString()) $($end):00:00"
                }
                Write-Verbose "`$CurrentMeetingTimeStart : $CurrentMeetingTimeStart"
                Write-Verbose "`$CurrentMeetingTimeEnd : $CurrentMeetingTimeEnd"
                $this.Duration += (New-TimeSpan -Start $CurrentMeetingTimeStart -End $CurrentMeetingTimeEnd).TotalMinutes
                Write-Verbose "Duration  : $this.Duration"
            }
            Write-Verbose -Message "Measure-UtilizationRate [$($this.Date.ToShortDateString())] Final `$this.Duration : $($this.Duration) ..."
			$this.UtilizationRate = $this.Duration/(($end-$start)*60)*100
            Write-Verbose -Message "Measure-UtilizationRate [$($this.Date.ToShortDateString())] Utilization Rate : $($this.UtilizationRate) ..."
        }
																										
        Write-Verbose -Message "Adding empty meeting entry for [$($Index.ToShortDateString())]"
        $RoomHistory.Add($Index, $DayData)
    }
    return $RoomHistory
}

#Import the Exchange Web Service API
Function Import-EWSManagedAPI
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        #The start date of the history
        [Parameter(Mandatory = $False)]
        [string]$EWSManagedApiFullName = $null
    )
    # Check EWS Managed API available - Download link : https://www.microsoft.com/en-us/download/details.aspx?id=42951
    # Find and load the managed API
    if ( ![string]::IsNullOrEmpty($EWSManagedApiFullName) )
    {
        if ( Test-Path $EWSManagedApiFullName )
        {
            Write-Verbose -Message "Loading $EWSManagedApiFullName ..."
            [void][Reflection.Assembly]::LoadFile($EWSManagedApiFullName)
            return $True
        }
        else
        {
            Write-Verbose -Message "Managed API not found at specified location: $EWSManagedApiFullName"
        }
    }
	
    $WebServicesDLL = Get-ChildItem -Recurse -Path 'C:\Program Files (x86)\Microsoft\Exchange\Web Services' -File -Filter 'Microsoft.Exchange.WebServices.dll' -ErrorAction SilentlyContinue
    if (!$WebServicesDLL)
    {
        $WebServicesDLL = Get-ChildItem -Path 'C:\Program Files\Microsoft\Exchange\Web Services' -File -Recurse -Filter 'Microsoft.Exchange.WebServices.dll' -ErrorAction SilentlyContinue
    }
	
    if ($WebServicesDLL)	
    {
        Write-Verbose -Message "Loading $($WebServicesDLL.FullName) ..."
        [void][Reflection.Assembly]::LoadFile($WebServicesDLL.FullName)
        return $True
    }
    else
    {
        return $False
    }
}

#Instantiate a new exchange service object
Function New-EWSExchangeService
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        #The mailbox
        [Parameter(ParameterSetName = 'AccessToken', Mandatory = $False)]
        [Parameter(ParameterSetName = 'Credential', Mandatory = $False)]
        [Parameter(ParameterSetName = 'Mailbox', Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]$MailBox,
		
        #The Exchange version
        [parameter(ParameterSetName = 'AccessToken', Mandatory = $False)]
        [parameter(ParameterSetName = 'Credential', Mandatory = $False)]
        [parameter(ParameterSetName = 'Mailbox', Mandatory = $False)]
        [ValidateSet('2007SP1','2010','2010SP1','2010SP2','2013','2013SP1')]
        [String]$ExchangeVersion = '2013SP1',

        #Tracing the exchange service ?
        [Parameter(Mandatory = $False)]
        [Switch]$Trace,

        #Office 365
        [Parameter(Mandatory = $False)]
        [Switch]$Office365,

        #Impersonation
        [Parameter(Mandatory = $False)]
        [Switch]$Impersonate,

        #Whether to allow insecure redirects when performing autodiscover
        [Parameter(Mandatory = $False)]	
        [switch]$AllowInsecureRedirection,

        #The Exchange service URL
        [Parameter(Mandatory = $False)]
        [AllowEmptyString()]
        [AllowNull()]
        [ValidateScript({
                    $_ -match '^https?'
        })]
        [string]$URL,

        #The credential
        [Parameter(ParameterSetName = 'Credential', Mandatory = $False)]
        [AllowNull()]
        [PSCredential]$Credential,

        #The Access Token
        [Parameter(ParameterSetName = 'AccessToken', Mandatory = $False)]
        [Object]$AccessToken
    )

    Write-Verbose -Message "`$ExchangeVersion : $ExchangeVersion"
    #Accoding to the specified exchange version
    switch ($ExchangeVersion)
    {
        '2007SP1' 
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1
            break 
        }
        '2010'    
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010
            break 
        }
        '2010SP1' 
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2
            break 
        }
        '2010SP2' 
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2
            break 
        }
        '2013'    
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013
            break 
        }
        '2013SP1' 
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1
            break 
        }
        Default   
        {
            $ExVer = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1
            break 
        }
    }
    # create EWS Service object for the target mailbox name
    $ExchangeService = New-Object -TypeName Microsoft.Exchange.WebServices.Data.ExchangeService -ArgumentList ($ExVer)
    #Enabling trace if specified
    if ($Trace)
    {
        $ExchangeService.TraceEnabled = $True
        $ExchangeService.TraceFlags = [Microsoft.Exchange.WebServices.Data.TraceFlags]::All
        $ExchangeService.TraceEnablePrettyPrinting = $True
    }
    if ($null -ne $AccessToken)
    {
        if ($AccessToken -is [string])
        {
            $ExchangeService.Credentials = New-Object -TypeName Microsoft.Exchange.WebServices.Data.OAuthCredentials -ArgumentList ($AccessToken)
        }
        else
        {
            $ExchangeService.Credentials = New-Object -TypeName Microsoft.Exchange.WebServices.Data.OAuthCredentials -ArgumentList ($AccessToken.AccessToken)
        }
    }
    else
    {
        #If a credential has been specified we use it else we use the default credentials
        if ($null -eq $Credential)
        {
            $ExchangeService.UseDefaultCredentials = $True
        }
        else
        {
            $ExchangeService.Credentials = New-Object -TypeName Microsoft.Exchange.WebServices.Data.WebCredentials -ArgumentList $Credential
        }
    }

    #If a URL has been specified we use it else we use the auto discover feature
    if (($null -eq $URL) -or ($URL.Length -le 0))
    {
        try
        {
            Write-Verbose -Message "Performing autodiscover for $MailBox"
            if ( $AllowInsecureRedirection )
            {
                $ExchangeService.AutodiscoverUrl($MailBox, {
                        $True
                })
            }
            else
            {
                $ExchangeService.AutodiscoverUrl($MailBox)
            }
            if ([string]::IsNullOrEmpty($ExchangeService.Url))
            {
                throw "$MailBox : autodiscover failed"
            }
            else
            {
                Write-Verbose -Message "EWS Url found: $($ExchangeService.Url)"
            }
        }
        catch
        {
            Write-Verbose -Message "$MailBox : error occurred during autodiscover: $($Error[0])"
            throw
        }
    }
    else
    {
        $ExchangeService.Url = $URL
    }
    if ($Office365)
    {
        <# 
                Speed up the AutodiscoverUrl() method response time by skipping 
                a lookup for an SCP record in local AD since we know in this case 
                we're accessing O365
        #>

        $ExchangeService.EnableScpLookup = $False
        $ExchangeService.HttpHeaders.Add('X-AnchorMailbox', $MailBox)
        #$ExchangeService.HttpHeaders.Add("X-PublicFolderMailbox", $MailBox)
    }
    if ($Impersonate)
    {
        $ExchangeService.ImpersonatedUserId = New-Object -TypeName Microsoft.Exchange.WebServices.Data.ImpersonatedUserId -ArgumentList ([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $MailBox)
        $ExchangeService.HttpHeaders.Add('X-AnchorMailbox', $MailBox)
    }
    return $ExchangeService
}

#Get Exchange Room lists
Function Get-EWSRoomList
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        #The Exchange Service
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExchangeService,

        #The Filter
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [string]$Filter,

        #Tracing the exchange service ?
        [Parameter(Mandatory = $False)]
        [Switch]$Address
    )
    if ($Filter)
    {
            $RoomList = $ExchangeService.GetRoomLists() | Where-Object -FilterScript {
                $_.Name -like $Filter
            }
    }
    else
    {
        $RoomList = $ExchangeService.GetRoomLists()
    }
    if ($Address)
    {
        return $RoomList.Address 
    }
    else
    {
        return $RoomList
    }
}


#Return the oldest date between two dates
Function Get-MinDate
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [datetime]$Date1,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [datetime]$Date2
    )
    if ($Date1 -lt $Date2)
    {
        return $Date1
    }
    else
    {
        return $Date2
    }
}

#Return the newest date between two dates
Function Get-MaxDate
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [datetime]$Date1,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [datetime]$Date2
    )
    if ($Date1 -gt $Date2)
    {
        return $Date1
    }
    else
    {
        return $Date2
    }
}

#Get the meeting data
Function Get-EWSMeetingRoomData
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        #The Exchange Service
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ExchangeService,

        #The start date of the history
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartDate = $((Get-Date).AddYears(-1)),

        #The start date of the history
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [datetime]$EndDate = $(Get-Date),

        #The room list
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias("Address")]
        [Microsoft.Exchange.WebServices.Data.EmailAddress[]]$RoomList,

        #Skipping some days ?
        [Parameter(Mandatory = $False)]
        [system.dayofweek[]]$Skip,

        #The Filter
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [string]$Filter,

        #Conflicting Meeting
        [Parameter(Mandatory = $False)]
        [switch]$ConflictingMeetings
    )
    begin
    {
        #Hashtable for storing all meeting room data
        $RoomData = @{}
        $AllConflictingMeetings=@()

    }
    process
    {
        foreach ($CurrentRoomList in $RoomList) 
        {
            try 
            {
                #Index for the progress bar
                $RoomListIndex = 0
                #Going through the room lists

                $RoomListIndex++
                Write-Progress -Id 1 -Activity "[$($RoomListIndex)/$($RoomList.Count)] Processing $($CurrentRoomList) ..." -Status "$([Math]::Round($RoomListIndex/$RoomList.Count * 100)) %"  -PercentComplete ($RoomListIndex/$RoomList.Count * 100)
                Write-Verbose -Message "Room List Name : $($CurrentRoomList)"
                #Getting all rooms from the processed room list
                if ($Filter)
                {
                    $Rooms = $ExchangeService.GetRooms($CurrentRoomList) | Where-Object -FilterScript {
                        $_.Name -like $Filter
                    }
                }
                else
                {
                    $Rooms = $ExchangeService.GetRooms($CurrentRoomList)
                }
                $RoomIndex = 0
                #Going through the rooms
                foreach ($Room in $Rooms)
                {
                    $RoomIndex++
                    Write-Progress -Id 2 -Activity "[$($RoomIndex)/$($Rooms.Count)] Processing $($Room.Name) ..." -Status "$([Math]::Round($RoomIndex/$Rooms.Count * 100)) %"  -PercentComplete ($RoomIndex/$Rooms.Count * 100)
                    Write-Verbose -Message "Creating a Room History for the [$($Room.Name)] meeting room..."
                    $RoomHistory = New-RoomHistory -StartDate $StartDate -EndDate $EndDate -Skip $Skip -ConflictingMeetings:$ConflictingMeetings
					
                    Write-Verbose -Message "[$($CurrentRoomList)] $($Room.Name) ..."

                    #We use a ItemView instead a Calendar view because a calendar view is not pageable
                    $propset = New-Object -TypeName Microsoft.Exchange.WebServices.Data.PropertySet -ArgumentList ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties) 
                    #Setting the property set
                    $propset.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::Start) 
                    $propset.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::End)  

                    $PropsetForProperties = New-Object -TypeName Microsoft.Exchange.WebServices.Data.PropertySet -ArgumentList ([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties) 
                    #Setting the property set
                    $PropsetForProperties.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::Start) 
                    $PropsetForProperties.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::End)  
                    if ($ConflictingMeetings)
                    {
                        $PropsetForProperties.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::ConflictingMeetings) 
                        $PropsetForProperties.Add([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::ConflictingMeetingCount) 
                    }

                    # Optional: reduce the query overhead by viewing the inbox 10 items at a time
                    $ItemView = New-Object -TypeName Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList (10)
                    $ItemView.PropertySet = $propset 
                    
                    #Setting the search criterias : Appointement and between the specified start and end times
                    $SearchFilterItemClass = New-Object -TypeName Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo -ArgumentList ([Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass, 'IPM.Appointment')
                    $SearchFilterStartDate = New-Object -TypeName Microsoft.Exchange.WebServices.Data.SearchFilter+IsGreaterThanOrEqualTo -ArgumentList ([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::Start, $StartDate)
                    $SearchFilterEndDate = New-Object -TypeName Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThanOrEqualTo -ArgumentList ([Microsoft.Exchange.WebServices.Data.AppointmentSchema]::End, $EndDate)
                    $SearchFilterCollection = New-Object -TypeName Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection -ArgumentList ([Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)	
                    $SearchFilterCollection.add($SearchFilterItemClass)
                    $SearchFilterCollection.add($SearchFilterStartDate)
                    $SearchFilterCollection.add($SearchFilterEndDate)
			
                    #Calendar folder
                    $Calendar = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Calendar
                    #Getting the folder if for the calendar folder of the room
                    $RoomCalendarFolderId = New-Object -TypeName Microsoft.Exchange.WebServices.Data.FolderId -ArgumentList ($Calendar, $Room.Address) 
					
                    #For paging
                    $HasMoreItems = $True

                    # Now retrieve the matching items and process
                    while ($HasMoreItems)
                    {
                        #Exception Management
                        try
                        {
                            #Get items based on our search criterias and using paging (10 items per loop)
                            $FoundAppointments = $ExchangeService.FindItems($RoomCalendarFolderId,$SearchFilterCollection,$ItemView)
                            #For ConflictingMeetings and ConflictingMeetingCount
                            $null = $ExchangeService.LoadPropertiesForItems($FoundAppointments, $PropsetForProperties)

                            #Going through appointements
                            foreach($CurrentAppointment in $FoundAppointments)
                            {
                                #Skipping week end days
                                if ($CurrentAppointment.Start.DayOfWeek -in $Skip)
                                {
                                    Write-Verbose -Message "Skipping $($CurrentAppointment.Start.ToLongDateString()) ..."
                                    Continue
                                }
                                $CurrentMeetingTimeStart = $CurrentAppointment.Start
                                $CurrentMeetingTimeEnd = $CurrentAppointment.End
                                if ([string]::IsNullOrEmpty($CurrentAppointment.Location))
                                {
                                    $CurrentAppointmentLocation=$Room.Name
                                }
                                else
                                {
                                    $CurrentAppointmentLocation=$CurrentAppointment.Location
                                }

                                Write-Verbose -Message "[Current Meeting] $CurrentAppointmentLocation : $CurrentMeetingTimeStart-$CurrentMeetingTimeEnd"									
                                #Write-Verbose -Message "`$CurrentMeetingTimeStart : $($CurrentMeetingTimeStart)"									
                                #Write-Verbose -Message "`$CurrentMeetingTimeEnd : $($CurrentMeetingTimeEnd)"									
                                $CurrentMeetingTime = "$($CurrentMeetingTimeStart)-$($CurrentMeetingTimeEnd)"
                                Write-Verbose -Message "`$CurrentMeetingTime : $CurrentMeetingTime"									
                                #The loop is for meeting across multiple days    
                                for($CurrentDate=$CurrentMeetingTimeStart.Date; $CurrentDate -le $CurrentMeetingTimeEnd.Date; $CurrentDate=$CurrentDate.AddDays(1))
                                {
                                    #If we have to skip some days (for instance Saturday and Sunday)
                                    if ($CurrentDate.DayOfWeek -in $Skip)
                                    {
                                        Write-Verbose -Message "Skipping $CurrentDate ..."
                                        Continue
                                    }
                                    Write-Verbose -Message "`$CurrentDate : $($CurrentDate.ToShortDateString())"
                                    #Getting the data for this day
                                    $CurrentData = $RoomHistory[$CurrentDate.Date]
                                    if ($ConflictingMeetings)
                                    {
                                        #If we found conflicting meetings
                                        if ($CurrentAppointment.ConflictingMeetings)
                                        {
                                            #If a meeting with the same time slot was already process we skip the new one
                                            if ($CurrentMeetingTime -in $CurrentData.MeetingTime)
                                            {
                                                Write-Verbose -Message "[Skipping] Duplicate meeting entry (based on start and end times/ found and already processed) for [$($Room.Name)][$CurrentMeetingTime]"									
                                                continue
                                            }
                                            else
                                            {
                                                $CurrentConflictingMeetings = $CurrentAppointment.ConflictingMeetings | Where-Object -FilterScript { 
                                                    (-not (($_.End -le $CurrentAppointmentTimeStart) -or ($_.Start -ge $CurrentAppointmentTimeEnd) -or ($_.Start.DayOfWeek -in $Skip)))
                                                }
                                                foreach ($CurrentConflictingMeeting in $CurrentConflictingMeetings)
                                                {
                                                    Write-Verbose -Message "[Conflicting Meeting] $($CurrentConflictingMeeting.Location) : $($CurrentConflictingMeeting.Start)-$($CurrentConflictingMeeting.End)"									
                                                    $CurrentMeetingTimeStart = Get-MinDate -Date1 $CurrentAppointment.Start -Date2 $CurrentConflictingMeeting.Start
                                                    $CurrentMeetingTimeEnd = Get-MaxDate -Date1 $CurrentAppointment.End -Date2 $CurrentConflictingMeeting.End
                                                    if ([string]::IsNullOrEmpty($CurrentConflictingMeeting.Location))
                                                    {
                                                        $CurrentConflictingMeetingLocation=$Room.Name
                                                    }
                                                    else
                                                    {
                                                        $CurrentConflictingMeetingLocation=$CurrentConflictingMeeting.Location
                                                    }
                                                    if ($CurrentAppointmentLocation -ne $CurrentConflictingMeetingLocation)
                                                    {
                                                        Write-Verbose -Message "[Skipping] The Conflicting Meeting/Meeting location is not the same : [$CurrentConflictingMeetingLocation] vs. [$CurrentAppointmentLocation]"									
                                                        continue
                                                    }
                                                    $AllConflictingMeetings += New-Object -TypeName PSCustomObject -Property @{MeetingLocation = $CurrentAppointmentLocation; MeetingStart=$CurrentAppointment.Start; MeetingEnd=$CurrentAppointment.End;ConflictingMeetingLocation = $CurrentConflictingMeetingLocation; ConflictingMeetingStart=$CurrentConflictingMeeting.Start; ConflictingMeetingEnd=$CurrentConflictingMeeting.End; NewMeetingStart=$CurrentMeetingTimeStart; NewMeetingEnd=$CurrentMeetingTimeEnd}
                                                }
                                                $CurrentMeetingTime = "$($CurrentMeetingTimeStart)-$($CurrentMeetingTimeEnd)"
                                                Write-Verbose -Message "`$CurrentMeetingTime : $CurrentMeetingTime"									
                                                if ($CurrentMeetingTime -in $CurrentData.MeetingTime)
                                                {
                                                    Write-Verbose -Message "[Skipping] Duplicate meeting entry (based on start and end times/ found and already processed) for [$($Room.Name)][$CurrentMeetingTime]"									
                                                }
                                            }
                                        }
                                    }
                                    #The loop is for meeting across multiple days    
                                    $NewCurrentMeetingTimeStart = Get-MaxDate -Date1 $CurrentMeetingTimeStart -Date2 $CurrentDate
                                    $NewCurrentMeetingTimeEnd = Get-MinDate -Date1 $CurrentMeetingTimeEnd -Date2 $CurrentDate.AddDays(1)
                                    Write-Verbose -Message "`$NewCurrentMeetingTimeStart : $NewCurrentMeetingTimeStart"									
                                    Write-Verbose -Message "`$NewCurrentMeetingTimeEnd : $NewCurrentMeetingTimeEnd"									
                                    
                                    if ($CurrentMeetingTimeStart -eq $CurrentMeetingTimeEnd)
                                    {
                                        continue
                                    }
                                    $CurrentMeetingTime = "$($NewCurrentMeetingTimeStart)-$($NewCurrentMeetingTimeEnd)"
                                    Write-Verbose -Message "`$CurrentMeetingTime : $CurrentMeetingTime"									
                                    if ($CurrentMeetingTime -in $CurrentData.MeetingTime)
                                    {
                                        Write-Verbose -Message "[Skipping] Duplicate meeting entry (based on start and end times/ found and already processed) for [$($Room.Name)][$CurrentMeetingTime]"									
                                    }
                                    else
                                    {
                                        $CurrentData.MeetingTime += $CurrentMeetingTime
                                    }
                                }
                            }

                            $HasMoreItems = $FoundAppointments.MoreAvailable
                            $ItemView.Offset = $FoundAppointments.NextPageOffset
                            Write-Verbose -Message "Has More Items : $HasMoreItems"
                            Write-Verbose -Message "Next Page Offset : $($FoundAppointments.NextPageOffset)"
                            Write-Verbose -Message "Offset : $($ItemView.Offset)"
                        }
                        catch
                        {
                            Write-Verbose -Message "[Exception] $($_.Exception.Message)"
                            $HasMoreItems = $False
                        }
                    }
                    if (!($RoomData[$Room.Name]))
                    {
                        $RoomData.Add($Room.Name, $RoomHistory)
                    }
                    else
                    {
                        Write-Verbose -Message "[SKIP] $($Room.Name) already processed ..."
                    }
                }
                Write-Progress -Id 2 -Activity 'Completed' -Completed
            }
            #Exception Management
            catch
            {
                Write-Verbose -Message $_.Exception.Message
                throw
            }
            Write-Progress -Id 1 -Activity 'Completed' -Completed
        }

    }
    end
    {
        if ($ConflictingMeetings)
        {
            $TimeStamp=Get-Date -UFormat '%Y%m%dT%H%M%S'
            $ConflictingMeetingsCSVFile = Join-Path $env:TEMP -ChildPath "ConflictingMeetings_$TimeStamp.csv"
            $AllConflictingMeetings | Select-Object -Property MeetingLocation, MeetingStart, MeetingEnd, ConflictingMeetingLocation, ConflictingMeetingStart, ConflictingMeetingEnd, NewMeetingStart, NewMeetingEnd | Export-Csv -Path $ConflictingMeetingsCSVFile -NoTypeInformation -Encoding UTF8
        }
        return $RoomData
    }
}

#Merge different conflicting or adjacent meeting to the biggest time range : 09:00-11:30 + 10:00-14:00 + 14:00-17:00 ==> 09:00-17:00 
Function Join-MeetingTime
{
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        [Parameter(Mandatory = $False)]
        [string[]]$MeetingTime
    )
    $Results = @()
    $index = 0
    Write-Verbose "`$MeetingTime : $MeetingTime"
    $Tokens = $MeetingTime | Sort-Object
    Write-Verbose "`$Tokens : $Tokens"
    $Tokens = $Tokens -split "-"
    $Dates = @()
    for($index=0; $index -lt $Tokens.Count;$index++)
    {
        if (($index % 2) -eq 0)
        {
            $Type="Start"
        }
        else
        {
            $Type="End"
            if ($Tokens[$index] -eq $Tokens[$index+1])
            {
                $index++
                continue
            }
        }
        $CurrentDate = New-Object -TypeName PSCustomObject -Property @{Date=$Tokens[$index]; Type=$Type}
        Write-Verbose "Adding `$CurrentDate : $CurrentDate"
        $Dates += $CurrentDate
    }
    $Dates = $Dates | Sort-Object -Property Date
    $Index=0

    While($Index -lt $Dates.Count)
    {
        $CurrentMeetingTimeStart=$Dates[$index].Date
        Write-Verbose "`$CurrentMeetingTimeStart : $CurrentMeetingTimeStart"
        $Level = 1
        While ($Level -gt 0)
        {
            $Index++
            Write-Verbose "$Index : $($Dates[$index].Type)"
            if ($Dates[$index].Type -eq "Start")
            {
                $Level++
            }
            else
            {
                $Level--
            }
            Write-Verbose "`$Level : $Level"
        }
        $CurrentMeetingTimeEnd = $Dates[$index].Date
        Write-Verbose "`$CurrentMeetingTimeEnd : $CurrentMeetingTimeEnd"
        $index++
        $CurrentMeeting = "$CurrentMeetingTimeStart-$CurrentMeetingTimeEnd"
        Write-Verbose "`$CurrentMeeting : $CurrentMeeting"
        $Results += $CurrentMeeting
    }
    return $Results
}

#Get the utilisation rate for the meeting rooms
Function Measure-MeetingRoomUtilizationRate
{
    <#
            .SYNOPSIS
            Measure the meeting room utilization rates from a specified hastable

            .DESCRIPTION
            Measure the meeting room utilization rates from a specified hastable

            .PARAMETER MeetingRoomData
            The hashtable(s) containing the room meeting data

            .PARAMETER StartTime
            The Start time from where we measure

            .PARAMETER EndTime
            The end time to where we measure

            .PARAMETER OutputDir
            The folder where to generate the CSV file (one per meeting room)

            .EXAMPLE
            New-RoomHistory -Skip Saturday, Sunday
            Create a hastable for history by skipping the Saturdays and Sundays from one year ago to today

            .EXAMPLE
            $MeetingRoomData | Measure-MeetingRoomUtilizationRate -StartTime 8 -EndTime 18 -OutputDir c:\MeetingData -Verbose
            Measure the utilizationr rate fom the meeting data in the specified hasthable from 08:00 AM to 06:00PM and generates on CSV file per meeting room in the c:\MeetingData folder
    #>
    [CmdletBinding(PositionalBinding = $True)]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $False)]
        [ValidateNotNullOrEmpty()]
        [Hashtable[]]$MeetingRoomData,
		
        [Parameter(Mandatory = $False)]
        [ValidateScript({
                    $_ -in 0..23
        })]
        [int]$StartTime = 0,
		
        [Parameter(Mandatory = $False)]
        [ValidateScript({
                    $_ -in 1..24
        })]
        [int]$EndTime = 24,
		
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [String]$OutputDir
    )
    begin
    {
        $null = New-Item -Path $OutputDir -ItemType Directory -Force
    }
    process
    {
        #If we specified an array of hastable outside a pipeline context 
        Foreach ($CurrentMeetingRoomData in $MeetingRoomData)
        {
            #Array for data consolidation
            $ConsolidatedData = @()
            #Index for the progress bar
            $RoomListIndex = 0
            #Going through all the rooms
            foreach ($CurrentRoomName in $CurrentMeetingRoomData.Keys)
            {
                $RoomListIndex++
                #Destination CSV file
                $CurrentRoomHistoryCSVFile = Join-Path -Path $OutputDir -ChildPath ($CurrentRoomName+$(' - History_{0:D2}00-{1:D2}00.csv' -f $StartTime, $EndTime))
                $CurrentRoomHistoryCSVFile = $CurrentRoomHistoryCSVFile -replace '\[', '(' -replace ']', ')'
                Write-Progress -Id 1 -Activity "[$($RoomListIndex)/$($CurrentMeetingRoomData.Count)] Exporting Data for $CurrentRoomName into $CurrentRoomHistoryCSVFile ..." -Status "$([Math]::Round($RoomListIndex/$CurrentMeetingRoomData.Count * 100)) %"  -PercentComplete ($RoomListIndex/$CurrentMeetingRoomData.Count * 100)
                Write-Verbose -Message "Processing Room [$($CurrentRoomName)] ..."
                $CurrentRoomHistory = $CurrentMeetingRoomData[$CurrentRoomName]
                #Call the Measure-UtilizationRate for every meeting room
                $CurrentRoomHistory.'Measure-UtilizationRate'($StartTime, $EndTime)
                Write-Host -Object "Exporting data to $CurrentRoomHistoryCSVFile"
                #Exporting to the CSV file
                if ($CurrentRoomHistory.ConflictingMeetings)
                {
                    $CurrentRoomHistory.Values |
                    Sort-Object -Property Date |
                    Select-Object -Property @{
                        Name       = 'Date'
                        Expression = {
                            $_.Date.ToShortDateString()
                        }
                    }, DayOfWeek, MeetingTimes, MeetingNb, AdjustedMeetingTimes, AdjustedMeetingNb, Duration, UtilizationRate |
                    Export-Csv -Path $CurrentRoomHistoryCSVFile -NoTypeInformation -Encoding UTF8
                }
                else
                {
                    $CurrentRoomHistory.Values |
                    Sort-Object -Property Date |
                    Select-Object -Property @{
                        Name       = 'Date'
                        Expression = {
                            $_.Date.ToShortDateString()
                        }
                    }, DayOfWeek, MeetingTimes, MeetingNb, Duration, UtilizationRate |
                    Export-Csv -Path $CurrentRoomHistoryCSVFile -NoTypeInformation -Encoding UTF8
                }
                					
                #Getting the start and end dates from the hashtable
                $Dates = $CurrentRoomHistory.Keys | Sort-Object
                $StartDate = $Dates | Select-Object -First 1
                $EndDate = $Dates | Select-Object -Last 1
                #Creating a new custom object for the overall utilization rate of the processed meeting room
                $CurrentRoomData = New-Object -TypeName PSCustomObject -Property @{
                    RoomName             = $CurrentRoomName
                    TotalUtilizationRate = '{0:N2}' -f $CurrentRoomHistory.UtilizationRate
                    StartDate            = $StartDate
                    EndDate              = $EndDate
                    StartTime            = $StartTime
                    EndTime              = $EndTime
                }
                Write-Verbose -Message "`$CurrentRoomData : $CurrentRoomData"
                #Storing the custom object in the array for consolidation
                $ConsolidatedData += $CurrentRoomData
					
                Write-Verbose -Message "`$CurrentRoomData : $CurrentRoomData"
            }
            Write-Progress -Id 1 -Activity 'Completed' -Completed
            #CSV file for data consolidation
            $ConsolidatedDataCSVFile = Join-Path -Path $OutputDir -ChildPath $('ConsolidatedData_{0:D2}00-{1:D2}00.csv' -f $StartTime, $EndTime)
            #Exporting consildated data
            $ConsolidatedData |
            Sort-Object -Property TotalUtilizationRate -Descending |
            Export-Csv -Path $ConsolidatedDataCSVFile -NoTypeInformation -Encoding UTF8
        }
    }
    end
    {
    }
}
#endregion

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
# To get the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript

try
{
    $AzureADModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
}
catch
{
    throw 'Prerequisites not installed (AzureAD PowerShell module not installed)'
}

#Azure AD only applications v1.0 : Web app / API ==> EWSNativeApp
$resourceAppIdURI = 'https://outlook.office365.com'
$ClientID = '12345678-1234-1234-1234-123456789012'   #AKA Application ID
$TenantName = 'tenant.onmicrosoft.com'            #Your Tenant Name
$CredPrompt = 'Always'                                 #Auto, Always, Never, RefreshSession
$redirectUri = 'http://localhost'                    #Your Application's Redirect URI
$Method = 'Get'                                      #GET or PATCH

$MeetingRoomData = $null
#Getting meeting room data
$Whoami = 'user@tenant.OnMicrosoft.com'
$Start = Get-Date

$isImportSuccessful = Import-EWSManagedAPI -Verbose
if (!$isImportSuccessful)
{
    throw 'Unable to load EWS Managed API'
}      				

$AccessToken = Get-AccessToken -TenantName $TenantName -ClientID $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceAppIdURI -CredPrompt $CredPrompt -Verbose 
$ExchangeService = New-EWSExchangeService -MailBox $Whoami -URL 'https://outlook.office365.com/EWS/Exchange.asmx' -AccessToken $AccessToken -Office365 -AllowInsecureRedirection -Verbose #-Trace 
$EWSRoomLists = Get-EWSRoomList -ExchangeService $ExchangeService -Address #-Filter "*france*"
$MeetingRoomData = $EWSRoomLists | Get-EWSMeetingRoomData -ExchangeService $ExchangeService -Skip Saturday, Sunday -Verbose #-Filter "*Paris*"

#Measuring meeting room utilization
if ($MeetingRoomData)
{
    $MeetingRoomData | Measure-MeetingRoomUtilizationRate -StartTime 8 -EndTime 18 -OutputDir $CurrentDir -Verbose
    #$MeetingRoomData | Measure-MeetingRoomUtilizationRate -StartTime 8 -EndTime 12 -OutputDir $CurrentDir -Verbose
    #$MeetingRoomData | Measure-MeetingRoomUtilizationRate -StartTime 14 -EndTime 18 -OutputDir $CurrentDir -Verbose
}
$End = Get-Date
$TimeSpan = New-TimeSpan -Start $Start -End $End
$TimeSpan.ToString()