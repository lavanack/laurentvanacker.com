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
#Installing Git


#region Getting the latest release of Git
#From https://raw.githubusercontent.com/lavanack/infrastructure-as-code-utilities/refs/heads/main/shared-bootstrap/Install-GitForWindows.ps1
$GitURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("64-bit.exe") }).browser_download_url)
#endregion

#region Downloading Git
$OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $GitURI -Leaf)
Invoke-WebRequest -Uri $GitURI -OutFile $OutFile
#endregion

#region Installing Git
Start-Process -FilePath $OutFile -ArgumentList "/SILENT", "/CLOSEAPPLICATIONS" -Wait
#endregion

#region Installing Git LFS
Push-Location -Path "$env:ProgramFiles\Git\cmd\git.exe"
git lfs install
Pop-Location
#endregion

#region Cleanup
Remove-Item -Path $OutFile -Force
#endregion 