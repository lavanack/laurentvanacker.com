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
#Installing WinSCP

#region Getting the URI of lastest release of WinSCP
$WinSCPUri = ((Invoke-WebRequest -Uri "https://winscp.net/eng/download.php" -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match "/download/WinSCP-\d\.\d\.\d-Setup.exe/download"}).href
$WinSCPUri = "https://winscp.net{0}" -f $WinSCPUri
$WinSCPUri = ((Invoke-WebRequest -Uri $WinSCPUri -UseBasicParsing).Links | Where-Object -FilterScript { $_.href -match "\.exe"}).href | Select-Object -First 1
#endregion 

#region Downloading WinSCP
$FileName = $(Split-Path -Path $WinSCPUri -Leaf) -replace "\?.+"
$Outfile = Join-Path -Path $env:TEMP -ChildPath $FileName
If (-not(Test-Path -Path $Outfile)) {
    Write-Verbose -Message "Downloading winSCP ..."
    Invoke-WebRequest -Uri $WinSCPUri -UseBasicParsing -OutFile $Outfile -Verbose
}
#endregion 

#region Installing WinSCP 
Start-Process -FilePath $Outfile -ArgumentList '/SILENT /ALLUSERS' -Verb runas -Wait
#endregion 
