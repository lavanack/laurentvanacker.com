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
product in which the Sample Code is embedded; (ii) to include a valid<
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#Installing Notepad++

#region Getting the lastest release of Notepad++ 
$NotepadPlusPlusVersion = (Invoke-RestMethod  -Uri "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest").tag_name -replace "v"
#endregion 

#region Downloading Notepad++ 
$NotepadPlusPlusUri = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("x64.exe") }).browser_download_url)
$Outfile = Join-Path -Path $env:TEMP -ChildPath $(Split-Path -Path $NotepadPlusPlusUri -Leaf)
If (-not(Test-Path -Path $Outfile)) {
    Write-Verbose -Message "Downloading Notepad++ v$NotepadPlusPlusVersion ..."
    Invoke-WebRequest -Uri $NotepadPlusPlusUri -UseBasicParsing -OutFile $Outfile -Verbose
}
#endregion 

#region Installing Notepad++ 
Start-Process -FilePath $Outfile -ArgumentList '/S' -Verb runas -Wait
#endregion 
