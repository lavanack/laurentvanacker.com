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
#Installing Azure Storage Explorer


#region Getting the latest release of Azure Storage Explorer
#$StorageExplorerURI = 'https://go.microsoft.com/fwlink/?LinkId=708343&clcid=0x409'
$StorageExplorerURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/microsoft/AzureStorageExplorer/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("x64.exe") }).browser_download_url)
#endregion

#region Downloading Azure Storage Explorer
$OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $StorageExplorerURI -Leaf)
Invoke-WebRequest -Uri $StorageExplorerURI -OutFile $OutFile
#endregion

#region Installing Azure Storage Explorer
Start-Process -FilePath $OutFile -ArgumentList "/SILENT", "/CLOSEAPPLICATIONS", "/ALLUSERS" -Wait
#endregion

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 