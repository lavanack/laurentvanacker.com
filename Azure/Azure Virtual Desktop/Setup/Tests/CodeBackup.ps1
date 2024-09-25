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
Param (
)

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$ParentDir = Split-Path -Path $CurrentDir -Parent
$StartTime = Get-Date
$BackupDir = Join-Path -Path $ParentDir -ChildPath "Backup"
$BackupDir = Join-Path -Path $BackupDir -ChildPath $("CodeBackup_{0:yyyyMMddHHmmss}" -f $StartTime)

Set-Location -Path $ParentDir
$null = New-Item -Path $BackupDir -ItemType Directory -Force
#Backing up all powershell scripts
Get-ChildItem -Path $ParentDir -Filter *.ps1 -File | Copy-Item -Destination $BackupDir -Force
#Backing up all PSAzureVirtualDesktop module versions
Split-Path -Path (Get-Module -Name PSAzureVirtualDesktop -ListAvailable).ModuleBase -Parent | Select-Object -Unique | Copy-Item -Destination $BackupDir -Recurse -Force
#Compressing files and folders
$DestinationPath = "$BackupDir.zip"
Compress-Archive -Path $BackupDir -DestinationPath $DestinationPath -CompressionLevel Optimal -Force
#Removing the backup folder (keeping only the archive file)
Remove-Item -Path $BackupDir -Recurse -Force 
Get-ChildItem -Path $DestinationPath
#Copying the Item in the clipboard
Get-Item -Path $DestinationPath | Set-Clipboard
