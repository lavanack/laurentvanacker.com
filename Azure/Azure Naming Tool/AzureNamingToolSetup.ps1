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
#region Global variables
$ASPNetCoreHostingBundleURI = "https://download.visualstudio.microsoft.com/download/pr/321a2352-a7aa-492a-bd0d-491a963de7cc/6d17be7b07b8bc22db898db0ff37a5cc/dotnet-hosting-6.0.14-win.exe"
$NetSDKURI = "https://download.visualstudio.microsoft.com/download/pr/4a725ea4-cd2c-4383-9b63-263156d5f042/d973777b32563272b85617105a06d272/dotnet-sdk-6.0.406-win-x64.exe"
$AzNamingToolURI = "https://codeload.github.com/microsoft/CloudAdoptionFramework/zip/refs/heads/master"
$AzNamingToolURI = "https://github.com/microsoft/CloudAdoptionFramework/archive/refs/heads/master.zip"
$ASPNetCoreHostingBundleFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $ASPNetCoreHostingBundleURI -Leaf)
$NetSDKFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $NetSDKURI -Leaf)
$AzNamingToolFile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $AzNamingToolURI -Leaf)
$AzureNamingToolWebSiteName = 'AzureNamingTool'
#endregion

Install-WindowsFeature -Name Web-Server -IncludeManagementTools

#region .Net Core pre-requisites
<#
#From https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script

#From https://github.com/dotnet/install-scripts
#region Installing winget via the WingetTools Powershell module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name WingetTools -Force -Verbose
Install-WinGet -Preview -PassThru -Verbose
$CommandLine = 'winget install Microsoft.DotNet.SDK.7'
Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $CommandLine -Wait

Invoke-Expression -Command "& { $(Invoke-RestMethod https://dot.net/v1/dotnet-install.ps1) } -runtime aspnetcore"
#>#region Downloading and Installing .Net Hosting Bundle Installer for hosting the web app
Invoke-WebRequest -Uri $ASPNetCoreHostingBundleURI -OutFile $ASPNetCoreHostingBundleFile
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$ASPNetCoreHostingBundleFile /install /passive /norestart" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$ASPNetCoreHostingBundleFile /repair /passive /norestart" -Wait
net stop was /y
net start w3svc    
#endregion 

#region Downloading and Installing .Net SDK for creating the web app
Invoke-WebRequest -Uri $NetSDKURI  -OutFile $NetSDKFile
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$NetSDKFile /install /passive /norestart" -Wait
#endregion
#endregion

#region IIS Setup
$AzureNamingToolWebSitePath =  "C:\WebSites\$AzureNamingToolWebSiteName"
$null = New-Item -Path $AzureNamingToolWebSitePath -ItemType Directory -Force
#applying the required ACL (via PowerShell Copy and Paste)
Get-Acl C:\inetpub\wwwroot | Set-Acl C:\WebSites
    
#PowerShell module for IIS Management
Import-Module -Name WebAdministration

#region : Default Settings
#Removing "Default Web Site"
Remove-WebSite -Name 'Default Web Site'
#Configuring The Anonymous Authentication to use the AppPoolId
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "userName" -value ""
#Disabling the Anonymous authentication for all websites
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/AnonymousAuthentication" -name "enabled" -value "False"
#endregion 

#region : .Net Core website management
#Creating a dedicated application pool
New-WebAppPool -Name "$AzureNamingToolWebSiteName" -Force

#Creating a dedicated web site
New-WebSite -Name "$AzureNamingToolWebSiteName" -Port 80 -IPAddress * -PhysicalPath $AzureNamingToolWebSitePath -ApplicationPool "$AzureNamingToolWebSiteName" -Force
    
#Setting up the dedicated application pool to "No Managed Code"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/applicationPools/add[@name='$AzureNamingToolWebSiteName']" -name "managedRuntimeVersion" -value ""

#Enabling the Anonymous authentication
#Creating a dedicated web site
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -location "$AzureNamingToolWebSiteName" -filter 'system.webServer/security/authentication/AnonymousAuthentication' -name 'enabled' -value 'True'
#endregion

#Downloading Azure Naming Tool Zip file from GitHub
Invoke-WebRequest -Uri $AzNamingToolURI -OutFile $AzNamingToolFile
#Expanding the downloaded Zip file
Expand-Archive -Path $AzNamingToolFile -DestinationPath "$env:TEMP\" -Force

#region dotnet: Create, publish and deploy the app
#cf. https://docs.microsoft.com/en-us/aspnet/core/getting-started/?view=aspnetcore-6.0&tabs=windows#create-a-web-app-project
#cf. https://docs.microsoft.com/en-us/aspnet/core/tutorials/publish-to-iis?view=aspnetcore-6.0&tabs=netcore-cli#publish-and-deploy-the-app
Set-Location -Path "$env:TEMP\CloudAdoptionFramework-master\ready\AzNamingTool"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "dotnet build --verbosity detailed" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "dotnet publish --configuration Release --verbosity detailed --force" -Wait
$Source = (Get-ChildItem -Path '.\bin\Release\' -Recurse -Filter 'publish' -Directory).FullName
Copy-Item -Path "$Source\*" -Destination $AzureNamingToolWebSitePath -Recurse -Force
#endregion
