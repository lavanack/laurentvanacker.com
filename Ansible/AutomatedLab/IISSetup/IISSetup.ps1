#requires -RunAsAdministrator 
trap {
  Write-Host 'Stopping Transcript ...'
  Stop-Transcript
  [console]::beep(3000, 750)
  break
} 
Clear-Host
$Error.Clear()
Import-Module DISM

$CurrentDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$TimeStamp = '{0:yyyyMMddTHHmmss}' -f (Get-Date)
$LogDir = "$env:WINDIR\Temp\Logs\$env:COMPUTERNAME"

$RootLog = 'E:\LogFiles'
$IISTemp = 'D:\Temp\Microsoft\IIS'


$FailedRequestLogPath = "$RootLog\Microsoft\IIS\FailedReqLogFile"
$DefaultIISLogFilePath = "$RootLog\Microsoft\IIS\Websites"
$AspCompiledTemplatePath = "$IISTemp\ASP Compiled Templates"
$IISTempCompressedFilePath = "$IISTemp\IIS Temporary Compressed Files"
$TempAppPoolPath = "$IISTemp\appPools"

New-Item -Path $IISTemp -Type Directory -Force
New-Item -Path "$LogDir\Archives" -Type Directory -Force
New-Item -Path "$DefaultIISLogFilePath" -Type Directory -Force

Rename-Item -Path "$LogDir\*.error" '*.err' -ErrorAction SilentlyContinue
Move-Item "$LogDir\*.*" "$LogDir\Archives" -Force

#Write-Host "Installing Net Framework 3"
#Enable-WindowsOptionalFeature -FeatureName NetFX3 -Online -Source "$CurrentDir\sources\sxs" -NoRestart -LimitAccess -All

Write-Host 'Installing Web Server Role (Basics Features)'
Enable-WindowsOptionalFeature -FeatureName IIS-WebServer -Online -NoRestart -All

Write-Host 'Configuring IIS Configuration Auditing with a 10 MB log size'
$logName = 'Microsoft-IIS-Configuration/Operational'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.IsEnabled = $true
$log.MaximumSizeInBytes = 10MB
$log.SaveChanges()

Write-Host 'Installing ASP.Net 2.0'
Enable-WindowsOptionalFeature -FeatureName IIS-ASPNet -Online -NoRestart -All

Write-Host 'Installing ASP.Net 4.6'
Enable-WindowsOptionalFeature -FeatureName IIS-ASPNet45 -Online -NoRestart -All

Write-Host 'Installing Integrated Authentication'
Enable-WindowsOptionalFeature -FeatureName IIS-WindowsAuthentication -Online -NoRestart

Write-Host 'Installing Request Monitoring'
Enable-WindowsOptionalFeature -FeatureName IIS-RequestMonitor -Online -NoRestart

Write-Host 'Configuring The Anonymous Authentication to use the AppPoolId'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'userName' -value ''

#Write-Host "IMPORTANT : Configuring AllowSubDirConfig attributes to prohibit the use of the web.config in the document directory (except for the root)"
#Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/virtualDirectoryDefaults" -name "allowSubDirConfig" -value "True"

Write-Host 'Installing HTTP Tracing'
Enable-WindowsOptionalFeature -FeatureName IIS-HttpTracing -Online -NoRestart

Write-Host 'Installing Scripting Tools'
Enable-WindowsOptionalFeature -FeatureName IIS-ManagementScriptingTools -Online -NoRestart

Write-Host 'Changing default logging fields'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/logFile' -name 'logExtFileFlags' -value 'Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,ProtocolVersion,Host,HttpSubStatus'

Write-Host 'Adding a custom log fields in the IIS log files'
if ('OriginalIP' -notin (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name 'collection').LogFieldName) {
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name '.' -value @{logFieldName = 'OriginalIP'; sourceName = 'X-FORWARDED-FOR'; sourceType = 'RequestHeader' }
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name '.' -value @{logFieldName = 'crypt-protocol'; sourceName = 'CRYPT_PROTOCOL'; sourceType = 'ServerVariable' }
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name '.' -value @{logFieldName = 'crypt-cipher'; sourceName = 'CRYPT_CIPHER_ALG_ID'; sourceType = 'ServerVariable' }
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name '.' -value @{logFieldName = 'crypt-hash'; sourceName = 'CRYPT_HASH_ALG_ID'; sourceType = 'ServerVariable' }
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -name '.' -value @{logFieldName = 'crypt-keyexchange'; sourceName = 'CRYPT_KEYEXCHANGE_ALG_ID'; sourceType = 'ServerVariable' }
}

Write-Host 'Installing Dynamic Compression'
Enable-WindowsOptionalFeature -FeatureName IIS-HttpCompressionDynamic -Online -NoRestart

Write-Host 'Setting a compression level of 9 for static compression : http://weblogs.asp.net/owscott/archive/2009/02/22/iis-7-compression-good-bad-how-much.aspx'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpCompression/scheme[@name='gzip']" -name 'staticCompressionLevel' -value 9

Write-Host 'Setting a compression level of 4 for dynamic compression : http://weblogs.asp.net/owscott/archive/2009/02/22/iis-7-compression-good-bad-how-much.aspx'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpCompression/scheme[@name='gzip']" -name 'dynamicCompressionLevel' -value 4

Write-Host 'Disabling Static and Dynamic Compression for CPU GTE 80 percent (default values 100 percent and 90 percent)'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/httpCompression' -name 'dynamicCompressionDisableCpuUsage' -value 80
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/httpCompression' -name 'staticCompressionDisableCpuUsage' -value 80

Write-Host 'Enabling Static and Dynamic Dynamic Compression for CPU LTE 50 percent (default values 50 percent and 50 percent)'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/httpCompression' -name 'dynamicCompressionEnableCpuUsage' -value 50
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/httpCompression' -name 'staticCompressionEnableCpuUsage' -value 50

#Write-Host "Allow the generated HTML markup from ASP.NET to be compressed before being added to the page output cache"
#Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/urlCompression" -name "doDynamicCompression" -value "True"

Write-Host 'Configuring the  Application Pool Defaults'
Write-Host 'Configuring LogEventOnRecycle to log all recycling events'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/applicationPools/applicationPoolDefaults/recycling' -name 'logEventOnRecycle' -value 'Time,Requests,Schedule,Memory,IsapiUnhealthy,OnDemand,ConfigChange,PrivateMemory'
Write-Host 'Disabling the periodic recycling'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart' -name 'time' -value '00:00:00'

Write-Host 'Adding the %SYSTEMROOT%\system32\inetsrv to the system path'
[Environment]::SetEnvironmentVariable( 'Path', "$env:Path;$Env:SystemRoot\system32\inetsrv", [System.EnvironmentVariableTarget]::Machine )

Import-Module WebAdministration
Write-Host 'Stopping the Default Web Site'
Stop-WebSite -Name 'Default Web Site' -ErrorAction Ignore

# Move AppPool isolation directory 
New-Item -Path "$TempAppPoolPath" -Type Directory -Force

Get-Item -Path HKLM:\System\CurrentControlSet\Services\WAS\Parameters | New-ItemProperty -Name ConfigIsolationPath -Value $TempAppPoolPath -Force

New-Item -Path $FailedRequestLogPath -Type Directory -Force
New-Item -Path $DefaultIISLogFilePath -Type Directory -Force
New-Item -Path $AspCompiledTemplatePath -Type Directory -Force
New-Item -Path $IISTempCompressedFilePath -Type Directory -Force
New-Item -Path "$IISTemp\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.Net Files" -Type Directory -Force
New-Item -Path "$IISTemp\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.Net Files" -Type Directory -Force
New-Item -Path "$IISTemp\Microsoft.NET\Framework64\v2.0.50727\Temporary ASP.Net Files" -Type Directory -Force
New-Item -Path "$IISTemp\Microsoft.NET\Framework\v2.0.50727\Temporary ASP.Net Files" -Type Directory -Force

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/traceFailedRequestsLogging' -name 'directory' -value $FailedRequestLogPath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/logfile' -name 'directory' -value $DefaultIISLogFilePath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/log/centralBinaryLogFile' -name 'directory' -value $DefaultIISLogFilePath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/log/centralW3CLogFile' -name 'directory' -value $DefaultIISLogFilePath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/siteDefaults/ftpServer/logFile' -name 'directory' -value $DefaultIISLogFilePath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.ftpServer/log/centralLogFile' -name 'directory' -value $DefaultIISLogFilePath

# Move config history location, temporary files, the path for the Default Web Site and the custom error locations
# Moving the configHistory setting
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/asp/cache' -name 'disktemplateCacheDirectory' -value $AspCompiledTemplatePath
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.webServer/httpCompression' -name 'directory' -value $IISTempCompressedFilePath

Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/configHistory' -name 'maxHistories' -value 20

# Doing a Backup of the IIS Metabase
Backup-WebConfiguration -name BackupAfterInitialConfiguration_$TimeStamp
