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
#requires -Version 5

[CmdletBinding()]
param
(
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


#region Customizing Taksbar 
#There is an invisible char (BOM) insite the double quotes. Do not remove It
#Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/ccmexec/PowerShell/master/customize%20TaskBar%20and%20Start%20Windows%2011/customizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/refs/heads/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar%20v1.1.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
#endregion

#region Addition Software setup/upgrade
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
#endregion

#region My Github Repo Local Setup
$SourceControlDir = Join-Path -Path $env:SystemDrive -ChildPath "Source Control"
$GitHubDir = Join-Path -Path $SourceControlDir -ChildPath "GitHub"
$GitHubRepoName = "laurentvanacker.com"
$GitHubRepoDir = Join-Path -Path $GitHubDir -ChildPath $GitHubRepoName
$null = New-Item -Path $GitHubRepoDir -ItemType Directory -Force

#region Version 1
$GitSetup = @"
REM From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
git config --system core.longpaths true
git config --global user.name "Laurent VAN ACKER"
git config --global user.email laurent.vanacker@free.fr
git lfs install
git clone https://github.com/lavanack/{0}.git "{1}"
C:\Tools\junction -accepteula $env:SystemDrive\{0} "{1}"
"@ -f $GitHubRepoName, $GitHubRepoDir

$GitSetupFilePath = "C:\Temp\GitSetup.cmd"
$null = New-Item -Path $GitSetupFilePath -ItemType File -Value $GitSetup -Force
#Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "$GitSetupFilePath" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#Remove-Item -Path $GitSetupFilePath -Force
#endregion

#region Version 2
#From https://support.atlassian.com/bamboo/cb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --system core.longpaths true" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.name 'Laurent VAN ACKER'" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git config --global user.email laurent.vanacker@free.fr" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git lfs install" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/$GitHubRepoName.git ""$GitHubRepoDir""" -Wait -WorkingDirectory "$env:ProgramFiles\Git\cmd"
#endregion
#endregion

#region Installing VSCode
$VSCodeExtension = [ordered]@{
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'PowerShell'                 = "ms-vscode.powershell"
    'Git Graph'                  = 'mhutchie.git-graph'
    'Git History'                = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History'           = 'pomber.git-file-history'
    'indent-rainbow'             = 'oderwat.indent-rainbow'
    'markdownlint'               = 'davidanson.vscode-markdownlint'
    'Markdown All in One'        = 'yzhang.markdown-all-in-one'
    'GitHub Copilot'             = 'github.copilot'
    'GitHub Copilot Chat'        = 'github.copilot-chat'

}
#Installing VSCode with Powershell extension (and optional additional ones)
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
#endregion

#region Powershell Modules
#Releasing Execution Policy
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force
#Set-PSRepository  -Name PSGallery -InstallationPolicy Trusted
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
#Install-Module -Name Az.Accounts, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users, PSCloudPC -Scope AllUsers -Force -Verbose
#endregion

Write-Host "Done ..."

Stop-Transcript