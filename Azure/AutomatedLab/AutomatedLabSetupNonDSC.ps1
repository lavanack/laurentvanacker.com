#Mode details on https://automatedlab.org/en/latest/Wiki/Basic/install/
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
#endregion 

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All

#region Installing Hyper-V
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -ne 'Enabled')
{
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

$null = New-Item -Path "$($env:SystemDrive)\Source Control\GitHub" -ItemType Directory -Force

#region Installing and Seting up AutomatedLab
#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

#Install-Module -Name AutomatedLab -RequiredVersion 5.42.0 -SkipPublisherCheck -AllowClobber -Force
Install-Module -Name AutomatedLab -SkipPublisherCheck -AllowClobber -Force
$AzModules = "Az.Accounts", "Az.Storage", "Az.Compute", "Az.Network", "Az.Resources", "Az.Websites"
Install-Module -Name $AzModules -Force -Verbose

#  Disable (which is already the default) and in addition skip dialog
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'

#releasing Execution Policy
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force

# Pre-configure Lab Host Remoting
Enable-LabHostRemoting -Force

New-LabSourcesFolder -DriveLetter $Disk.DriveLetter
#endregion

#region  Installing Git
$GitURI = ((Invoke-WebRequest -Uri 'https://git-scm.com/download/win').Links | Where-Object -FilterScript { $_.InnerText -eq "64-bit Git For Windows Setup"}).href
$OutputFile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $GitURI -Leaf)
Invoke-WebRequest -Uri $GitURI -OutFile $OutputFile
Start-Process -FilePath $OutputFile -ArgumentList "/SILENT", "/CLOSEAPPLICATIONS" -Wait
#endregion

#region Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
#endregion 

#region Installing VSCode with useful extensions : Silent Install
$VSCodeExtension = [ordered]@{
    #"PowerShell" = "ms-vscode.powershell"
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
}

Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }  -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
#endregion

#region Junction creation to avoid to host AutomatedLab VMs on the system partition
$SysinternalsSuiteURI = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$OutputFile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $SysinternalsSuiteURI -Leaf)
Invoke-WebRequest -Uri $SysinternalsSuiteURI -OutFile $OutputFile
Expand-Archive -Path $OutputFile -DestinationPath C:\Tools -Force
Start-Process -FilePath C:\Tools\junction.exe -ArgumentList '-accepteula', "$($Disk.DriveLetter)\AutomatedLab-VMs", "C:\AutomatedLab-VMs" -Wait
#endregion
