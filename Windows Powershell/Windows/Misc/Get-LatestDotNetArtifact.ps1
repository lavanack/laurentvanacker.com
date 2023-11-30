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
[CmdletBinding()]
param
(
)

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#region Latest DotNet Core Hosting Bundle
$LatestNetCoreHostingBundleURI = (Invoke-WebRequest https://dotnet.microsoft.com/permalink/dotnetcore-current-windows-runtime-bundle-installer).links.href | Where-Object -FilterScript { $_ -match "\.exe$"} | Select-Object -Unique
$LatestDotNetCoreSDKFilePath = Join-Path -Path $CurrentDir -ChildPath $(($LatestNetCoreHostingBundleURI -split "/")[-1])
Start-BitsTransfer -Source $LatestNetCoreHostingBundleURI -Destination $LatestDotNetCoreSDKFilePath
Write-Verbose "Latest DotNet Core Hosting Bundle is available at '$LatestDotNetCoreSDKFilePath'"
#endregion

#region Latest DotNet SDK
$LatestDotNetCoreSDKURI = (Invoke-WebRequest https://dotnet.microsoft.com/en-us/download).links.href | Where-Object -FilterScript { $_ -match "sdk.*windows.*-x64"}
$LatestDotNetCoreSDKURI = "https://dotnet.microsoft.com$($LatestDotNetCoreSDKURI)"
$LatestDotNetCoreSDKURI = (Invoke-WebRequest $LatestDotNetCoreSDKURI).links.href | Where-Object -FilterScript { $_ -match "sdk.*win.*-x64"} | Select-Object -Unique
$LatestDotNetCoreSDKFilePath = Join-Path -Path $CurrentDir -ChildPath $(($LatestDotNetCoreSDKURI -split "/")[-1])

Start-BitsTransfer -Source $LatestDotNetCoreSDKURI -Destination $LatestDotNetCoreSDKFilePath
Write-Verbose "Latest DotNet Core SDK is available at '$LatestDotNetCoreSDKFilePath'"
#endregion