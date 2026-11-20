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
#Installing Python
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$CurrentScriptName = Split-Path -Path $CurrentScript -Leaf
$TranscriptDirPath = "C:\AVDImage"
$TranscriptDir = New-Item -Path $TranscriptDirPath -ItemType Directory -Force

$TranscriptFile = Join-Path -Path $TranscriptDir -ChildPath ($CurrentScriptName -replace ".ps1$", "$("_{0}.txt" -f (Get-Date -Format 'yyyyMMddHHmmss'))")
Start-Transcript -Path $TranscriptFile -IncludeInvocationHeader


#region Getting the URI of lastest release of Python
$PythonUri = ((Invoke-WebRequest -Uri "https://www.python.org/downloads/windows" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match "-amd64.exe$"}).href | Select-Object -First 1
<#
$null = ((Invoke-WebRequest -Uri "https://www.python.org/downloads/windows" -UseBasicParsing).Links | Where-Object -FilterScript { ($_.OuterHTML -match "Latest Python .* Release - Python (?<LatestVersion>[^<]+)") }).href | Select-Object -First 1
$LatestVersion = $Matches["LatestVersion"]
$PythonUri = ((Invoke-WebRequest -Uri "https://www.python.org/downloads/windows" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match "$LatestVersion-amd64.exe$"}).href | Select-Object -First 1
#>
#endregion 

#region Downloading Python
$FileName = $(Split-Path -Path $PythonUri -Leaf) -replace "\?.+"
$OutFile = Join-Path -Path $env:TEMP -ChildPath $FileName
If (-not(Test-Path -Path $OutFile)) {
    Write-Verbose -Message "Downloading Python ..."
    Invoke-WebRequest -Uri $PythonUri -UseBasicParsing -OutFile $OutFile -Verbose
}
#endregion 

#region Installing Python
$ArgumentList = @( "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1", "Include_launcher=1", "InstallLauncherAllUsers=1", "Include_test=0" )

Start-Process -FilePath $OutFile -ArgumentList $ArgumentList -Verb runas -Wait -PassThru
#endregion 

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 

Stop-Transcript