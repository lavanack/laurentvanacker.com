﻿#Mode details on https://automatedlab.org/en/latest/Wiki/Basic/install/
#This script needs to be called twice (The Hyper-V installation will reboot the server at the start of the first call)
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Disabling IE ESC
function Disable-IEESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}
#Disable-IEESC

function Disable-PrivacyExperience {
    $RegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"

    # Create the OOBE key if it doesn't exist
    if (-not (Test-Path $RegKey)) {
        New-Item -Path $RegKey -Force
    }

    # Set the DisablePrivacyExperience value
    Set-ItemProperty -Path $RegKey -Name "DisablePrivacyExperience" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 1
    Write-Host "Privacy Experience has been disabled." -ForegroundColor Green
}
Disable-PrivacyExperience
#endregion 

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All

#region Installing Hyper-V
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -ne 'Enabled') {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Restart-Computer -Force
}

#endregion
#Inializing the disk and creating/formating a new volume
#Get-Disk -Number 1 | Clear-Disk -RemoveData -Confirm:$false -PassThru | Set-Disk -IsOffline $true -Verbose
$Disk = Get-Disk -Number 1 | Where-Object PartitionStyle -Eq "RAW" | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -NewFileSystemLabel Data

$HyperVPath = "$($Disk.DriveLetter):\Virtual Machines\Hyper-V"
$null = New-Item -Path $HyperVPath -ItemType Directory -Force
Set-VMHost -VirtualHardDiskPath $HyperVPath -VirtualMachinePath $HyperVPath

$SourceControlGitHub = New-Item -Path "$($Disk.DriveLetter):\Source Control\GitHub" -ItemType Directory -Force

#region Installing and Seting up AutomatedLab
#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

#Install-Module -Name AutomatedLab -RequiredVersion 5.42.0 -SkipPublisherCheck -AllowClobber -Force
Install-Module -Name AutomatedLab -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force -Verbose
$AzModules = "Az.Accounts", "Az.Storage", "Az.Compute", "Az.Network", "Az.Resources", "Az.Websites"
Install-Module -Name $AzModules -Scope AllUsers -Force -Verbose

#  Disable (which is already the default) and in addition skip dialog
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'

#releasing Execution Policy
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force

# Pre-configure Lab Host Remoting
Start-Service -Name WinRM
Enable-LabHostRemoting -Force

New-LabSourcesFolder -DriveLetter $Disk.DriveLetter
#endregion

<#
winget install --exact --id=Microsoft.Azure.StorageExplorer
winget install --exact --id=Microsoft.Azure.AZCopy.10
winget install --exact --id=GitHub.cli
winget install --exact --id=Microsoft.PowerShell
winget install --exact --id=sysinternals --location "C:\Tools"
#>

#region Installing AzCopy
$AzCopyURI = 'https://aka.ms/downloadazcopy-v10-windows'
$OutputFile = Join-Path -Path $CurrentDir -ChildPath 'azcopy_windows_amd64_latest.zip'
Invoke-WebRequest -Uri $AzCopyURI -OutFile $OutputFile
Expand-Archive -Path $OutputFile -DestinationPath C:\Tools -Force
Remove-Item -Path $OutputFile -Force
#endregion

#region Installing StorageExplorer
#$StorageExplorerURI = 'https://go.microsoft.com/fwlink/?LinkId=708343&clcid=0x409'
$StorageExplorerURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/microsoft/AzureStorageExplorer/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("x64.exe") }).browser_download_url)
$OutputFile = Join-Path -Path $CurrentDir -ChildPath 'StorageExplorer.exe'
Invoke-WebRequest -Uri $StorageExplorerURI -OutFile $OutputFile
Start-Process -FilePath $OutputFile -ArgumentList "/SILENT", "/CLOSEAPPLICATIONS", "/ALLUSERS" -Wait
Remove-Item -Path $OutputFile -Force
#endregion

#region Installing Git
#From https://raw.githubusercontent.com/lavanack/infrastructure-as-code-utilities/refs/heads/main/shared-bootstrap/Install-GitForWindows.ps1
$GitURI = $(((Invoke-RestMethod  -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest").assets | Where-Object -FilterScript { $_.name.EndsWith("64-bit.exe") }).browser_download_url)
$OutputFile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $GitURI -Leaf)
Invoke-WebRequest -Uri $GitURI -OutFile $OutputFile
Start-Process -FilePath $OutputFile -ArgumentList "/SILENT", "/CLOSEAPPLICATIONS" -Wait
Remove-Item -Path $OutputFile -Force
#endregion

#region Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
#endregion 

#region Installing VSCode with useful extensions : Silent Install
$VSCodeExtension = [ordered]@{
    "PowerShell"                 = "ms-vscode.powershell"
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'Git Graph'                  = 'mhutchie.git-graph'
    'Git History'                = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History'           = 'pomber.git-file-history'
    'indent-rainbow'             = 'oderwat.indent-rainbow'
}

Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }  -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
#endregion

#region Junction creation to avoid to host AutomatedLab VMs on the system partition
$SysinternalsSuiteURI = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$OutputFile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $SysinternalsSuiteURI -Leaf)
Invoke-WebRequest -Uri $SysinternalsSuiteURI -OutFile $OutputFile
Expand-Archive -Path $OutputFile -DestinationPath C:\Tools -Force
New-Item -Path "$($Disk.DriveLetter):\AutomatedLab-VMs" -ItemType Directory -Force
Start-Process -FilePath C:\Tools\junction.exe -ArgumentList '-accepteula', "C:\AutomatedLab-VMs", "$($Disk.DriveLetter):\AutomatedLab-VMs" -Wait
Remove-Item -Path $OutputFile -Force
#endregion

<#
#region Customizing Taksbar 
#There is an invisible char (BOM) insite the double quotes. Do not remove It
Invoke-Expression -Command "& { $((Invoke-RestMethod https://raw.githubusercontent.com/Ccmexec/PowerShell/master/Customize%20TaskBar%20and%20Start%20Windows%2011/CustomizeTaskbar.ps1) -replace "﻿") } -MoveStartLeft -RemoveWidgets -RemoveChat -RemoveSearch -RunForExistingUsers" -Verbose
#endregion

#region Cloning my GitHub repository
Set-Location -Path $SourceControlGitHub
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "git clone https://github.com/lavanack/laurentvanacker.com.git" -Wait
#endregion 
#>
