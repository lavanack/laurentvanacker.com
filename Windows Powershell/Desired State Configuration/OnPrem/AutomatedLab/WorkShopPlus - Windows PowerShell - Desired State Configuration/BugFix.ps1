#region Switching to French Keyboard
Set-WinUserLanguageList -LanguageList fr-fr -Force
#endregion

#region PowerShell 4 
#Add-Type -AssemblyName System.IO.Compression.FileSystem
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Source = "https://www.laurentvanacker.com/downloads/PackageManagement.zip"
#$Source = "http://vmalhypvusc1931.centralus.cloudapp.azure.com/PackageManagement.zip"
$Destination = Join-Path -Path $env:SystemDrive\ -ChildPath $(Split-Path -Path $Source -Leaf)
Invoke-WebRequest -Uri $Source -OutFile $Destination -UseBasicParsing
#endregion

#Upgrade WMF 5

#region Forcing the use of TLS 1.2 and the French Keyboard via the profile for all users on all hosts
$null=New-Item -Path $(Split-Path $profile.AllUsersAllHosts -Parent) -ItemType Directory -Force
"Write-Host 'Adding SecurityProtocolType to TLS 1.2'`r`n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`r`nWrite-Host 'Switching to French Keyboard'`r`nSet-WinUserLanguageList -LanguageList fr-fr -Force`r`n" | Out-File -FilePath $Profile.AllUsersAllHosts -Force -Append
#endregion


#region PowerShell 5 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Source = "https://www.laurentvanacker.com/downloads/PackageManagement.zip"
#$Source = "http://vmalhypvusc1931.centralus.cloudapp.azure.com/PackageManagement.zip"
$Destination = Join-Path -Path $env:SystemDrive\ -ChildPath $(Split-Path -Path $Source -Leaf)
Expand-Archive -Path $Destination -DestinationPath $env:ProgramFiles -Force
#endregion

#Register-PSrepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2