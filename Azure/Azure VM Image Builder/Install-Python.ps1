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

#region Getting the URI of lastest release of Python
$PythonUri = ((Invoke-WebRequest -Uri "https://www.python.org/downloads/windows" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match "-amd64.exe$"}).href | Select-Object -First 1
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
Start-Process -FilePath $OutFile -ArgumentList '/quiet' -Verb runas -Wait
#endregion 

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 