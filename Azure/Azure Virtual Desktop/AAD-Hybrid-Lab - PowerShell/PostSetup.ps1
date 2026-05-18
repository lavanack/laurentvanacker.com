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
#requires -Version 5 -RunAsAdmin

[CmdletBinding()]
param
(
)

#region Main Code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --force" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Git.Git" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Microsoft.Sysinternals.Suite" -Wait
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "winget install -e --id Notepad++.Notepad++" -Wait


$GitHubDir = New-Item -Path "C:\Source Control\GitHub\" -ItemType Directory -Force
$GitHubMainRepoName = "laurentvanacker.com"
$GitHubMainRepoDir = Join-Path -Path $GitHubDir -ChildPath $GitHubMainRepoName
$GitHubPSAVDRepoName = "PSAzureVirtualDesktop"
$GitHubPSAVDRepoDir = Join-Path -Path $GitHubDir -ChildPath $GitHubPSAVDRepoName

#region Customizing Taksbar 
#There is an invisible char (BOM) insite the double quotes. Do not remove It
#Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/ccmexec/PowerShell/master/customize%20TaskBar%20and%20Start%20Windows%2011/customizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/refs/heads/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar%20v1.1.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
#endregion

#region My Github Repo Local Setup

#region Version 1
$GitSetup = @"
REM From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
git config --system core.longpaths true
git config --global user.name "Laurent VAN ACKER"
git config --global user.email laurent.vanacker@free.fr
git lfs install
git clone https://github.com/lavanack/{0}.git "{1}"
C:\Tools\junction -accepteula $env:SystemDrive\{0} "{1}"
git clone https://github.com/lavanack/{0}.git "{3}"
C:\Tools\junction -accepteula $env:SystemDrive\{2} "{3}"
"@ -f $GitHubMainRepoName, $GitHubMainRepoDir, $GitHubPSAVDRepoName, $GitHubPSAVDRepoDir

$GitSetupFilePath = "C:\Temp\GitSetup.cmd"
$null = New-Item -Path $GitSetupFilePath -ItemType File -Value $GitSetup -Force
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$GitSetupFilePath" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#Remove-Item -Path $GitSetupFilePath -Force
#endregion

#region Version 2
#From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --system core.longpaths true" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.name ""Laurent VAN ACKER""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.email laurent.vanacker@free.fr" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git lfs install" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/$GitHubMainRepoName.git ""$GitHubMainRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "junction -accepteula $env:SystemDrive\$GitHubMainRepoName ""$GitHubMainRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/$GitHubPSAVDRepoName.git ""$GitHubPSAVDRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "junction -accepteula $env:SystemDrive\$GitHubPSAVDRepoName ""$GitHubPSAVDRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#endregion
#endregion

#rehion Installing Requires PowerShell Modules
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PowerShellGet -Force -Verbose
Find-Module -Name Az.DesktopVirtualization -AllowPrerelease -RequiredVersion 5.4.6-preview | Install-Module -Force -Verbose
Install-Module -Name PSAzureVirtualDesktop -AllowClobber -SkipPublisherCheck -Force -Verbose
#endregion
#endregion