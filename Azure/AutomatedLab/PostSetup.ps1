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
#requires -Version 5 -Modules Az.Compute, Az.Storage, Az.Resources

[CmdletBinding()]
param
(
    [string] $ResourceGroupName = "rg-automatedlab-storage-use-001",
    [string] $StorageAccountName = "automatedlablabsources",
    [string] $ShareName = "isos"
)

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$CurrentScriptName = Split-Path -Path $CurrentScript -Leaf
#$TranscriptFileName = $CurrentScriptName -replace ".ps1$", "$("_{0:yyyyMMddHHmmss}.txt" -f (Get-Date))"
$TranscriptFileName = $CurrentScriptName -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))"
$TranscriptFile = Join-Path -Path "C:\Temp" -ChildPath $TranscriptFileName
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader

#region Azure Connection
# Ensures you do not inherit an AzContext in your dirbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity (Azure Automation account)
$AzureContext = (Connect-AzAccount -Identity).context
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
#endregion

#region Set Storage Account Configuration
$MyPublicIp = (Invoke-WebRequest -uri "https://ipv4.seeip.org" -UseBasicParsing).Content
$null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Enabled -AllowSharedKeyAccess $true -NetworkRuleSet (@{ipRules = (@{IPAddressOrRange = $MyPublicIp; Action = "allow" }); defaultAction = "deny" })
Start-Sleep -Seconds 10
#endregion

#region Customizing Taksbar 
#There is an invisible char (BOM) insite the double quotes. Do not remove It
#Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/ccmexec/PowerShell/master/customize%20TaskBar%20and%20Start%20Windows%2011/customizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/refs/heads/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar%20v1.1.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
#endregion

#region My Github Repo Local Setup
$SourceControlDir = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter "Source Control").FullName
$LabSourcesDir = (Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem | Where-Object -FilterScript { $_.Used }).Root -Directory -Filter "LabSources").FullName
$GitHubDir = Join-Path -Path $SourceControlDir -ChildPath "GitHub"
$GitHubRepoName = "laurentvanacker.com"
$GitHubRepoDir = Join-Path -Path $GitHubDir -ChildPath $GitHubRepoName
$GitSetup = @"
REM From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
git config --system core.longpaths true
git config --global user.name "Laurent VAN ACKER"
git config --global user.email laurent.vanacker@free.fr
git lfs install
git clone https://github.com/lavanack/$GitHubRepoName.git "$GitHubRepoDir"
C:\Tools\junction -accepteula $env:SystemDrive\$GitHubRepoName "$GitHubRepoDir"
"@
$GitSetupFilePath = "C:\Temp\GitSetup.cmd"
$null = New-Item -Path $GitSetupFilePath -ItemType File -Value $GitSetup -Force
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$GitSetupFilePath" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#Remove-Item -Path $GitSetupFilePath -Force

<#
#From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --system core.longpaths true" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git lfs install" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Set-Location -Path $GitHubDir
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/laurentvanacker.com.git" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "C:\Tools\junction -accepteula c:\laurentvanacker.com ""$GitHubRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Set-Location -Path $GitHubRepoDir
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git lfs pull" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.name ""Laurent VAN ACKER""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.email laurent.vanacker@free.fr" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#>
#endregion

#region AutomatedLab ISO downloads
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddDays(1)
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName).Value[0]

#region Get Download Urwdl - Version #1
$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey
$StorageShareSASToken = New-AzStorageShareSASToken -Context $context -ExpiryTime $ExpiryTime -Permission "rwdl" -ShareName $ShareName -FullUri
#endregion

#region Get Download Urwdl - Version #2
$env:AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$storageAccountKey;EndpointSuffix=core.windows.net"
$StorageShareSASToken = New-AzStorageShareSASToken -ExpiryTime $ExpiryTime -Permission "rwdl" -ShareName $ShareName -FullUri 
#endregion

#region Get Download Urwdl - Version #3
$Context = New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=$StorageAccountName;AccountKey=$StorageAccountKey"
$StorageShareSASToken = New-AzStorageShareSASToken -Context $Context -ExpiryTime $ExpiryTime -Permission rwdl -ShareName $ShareName -FullUri 
#endregion

#Go to the latest azcopy folder
Get-ChildItem -Path "C:\Tools\azcopy_windows*" | Sort-Object -Property Name -Descending | Select-Object -First 1 | Push-Location
$ISOFolder = $(Join-Path -Path $LabSourcesDir -ChildPath "ISOs")
$env:AZCOPY_CRED_TYPE = "Anonymous"
$env:AZCOPY_CONCURRENCY_VALUE = "AUTO"
./azcopy.exe sync $StorageShareSASToken $ISOFolder --delete-destination=true --log-level=INFO --put-md5
$env:AZCOPY_CRED_TYPE = ""
$env:AZCOPY_CONCURRENCY_VALUE = ""
Pop-Location
#endregion

#region Set Storage Account Configuration
#$null = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Disabled -AllowSharedKeyAccess $false
#endregion

#region Addition Software setup/upgrade
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements" -Wait
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install --exact --id=Notepad++.Notepad++" -Wait
#endregion

Stop-Transcript