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
#Installing AzCopy

#region Getting the URI of latest release of AzCopy
$AzCopyUri = "https://aka.ms/downloadazcopy-v10-windows"
#endregion 

#region Downloading AzCopy
$OutFile = Join-Path -Path $env:TEMP -ChildPath 'azcopy_windows_amd64_latest.zip'
If (-not(Test-Path -Path $OutFile)) {
    Write-Verbose -Message "Downloading AzCopy ..."
    Invoke-WebRequest -Uri $AzCopyUri -UseBasicParsing -OutFile $OutFile -Verbose
}
#endregion 

#region Installing/Unzipping AzCopy
$DestinationPath = "C:\Tools"
$null = New-Item -Path $DestinationPath -ItemType Directory -Force
Expand-Archive -Path $OutFile -DestinationPath $DestinationPath -Force
#endregion 

#region Updating System Path
$LatestAzCopyPath = (Get-ChildItem -Path $DestinationPath -Filter "azcopy_windows*" -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1).FullName
$Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($LatestAzCopyPath -notin ($Path -split ';')) {
    [Environment]::SetEnvironmentVariable('Path', "$Path;$LatestAzCopyPath", 'Machine')
}
#endregion 

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 