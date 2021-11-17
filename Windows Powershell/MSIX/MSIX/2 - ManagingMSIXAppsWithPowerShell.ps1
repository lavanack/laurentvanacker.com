#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

Set-Location $CurrentDir
#Managing MSIX with PowerShell :https://docs.microsoft.com/en-us/windows/msix/desktop/powershell-msix-cmdlets
$MSIXFilePath = Get-ChildItem -Path $CurrentDir -Filter *.msix -File
$MSIXFilePath
Add-AppxPackage -Path $MSIXFilePath -Verbose
Get-AppxPackage -Name "notepad*"
Get-AppxPackage -Name "notepad*" | Remove-AppxPackage -Verbose
Get-AppxPackage -Name "notepad*"