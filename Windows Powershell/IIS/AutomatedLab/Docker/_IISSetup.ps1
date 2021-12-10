$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force

#setup ASP.Net, Remote IIS management, FREB & Request Monitor
Install-WindowsFeature Web-Mgmt-Service, Web-Asp-Net45, Web-Http-Tracing, Web-Request-Monitor
#Setting Web Management Service
New-ItemProperty -Path HKLM:\software\microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force
Set-Service -Name WMSVC -StartupType automatic

#Changing default logging fields
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,ProtocolVersion,Host,HttpSubStatus"

#Add a custom log field for X-FORWARDED-FOR and TLS Usage in the IIS log files
if ('OriginalIP' -notin (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "collection").LogFieldName)
{
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='OriginalIP';sourceName='X-FORWARDED-FOR';sourceType='RequestHeader'}
    #From https://laurentvanacker.com/index.php/2020/09/03/nouvelle-fonctionnalite-iis-pour-aider-a-identifier-une-version-tls-obsolete-new-iis-functionality-to-help-identify-weak-tls-usage/
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'}
}

#Configuring the  Application Pool Defaults
#Configuring LogEventOnRecycle to log all recycling events
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/applicationPoolDefaults/recycling" -name "logEventOnRecycle" -value "Time,Requests,Schedule,Memory,IsapiUnhealthy,OnDemand,ConfigChange,PrivateMemory"
#Disabling the periodic recycling
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart" -name "time" -value "00:00:00"

#Setting configHistory to 20
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/configHistory" -name "maxHistories" -value 20

Write-Host "Configuring IIS Configuration Auditing with a 10 MB log size"
$logName = "Microsoft-IIS-Configuration/Operational"
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.IsEnabled=$true
$log.MaximumSizeInBytes=10MB
$log.SaveChanges()

#Add user for Remote IIS Manager Login
New-LocalUser -Name IISAdmin -Password $SecurePassword -AccountNeverExpires -PasswordNeverExpires | Add-LocalGroupMember -Group "Administrators"