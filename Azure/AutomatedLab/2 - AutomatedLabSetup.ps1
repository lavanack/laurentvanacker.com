#Mode details on https://automatedlab.org/en/latest/Wiki/Basic/install/
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
Disable-IEESC
#endregion 

#region Installing Hyper-V
if (-not(Get-WindowsFeature -Name Hyper-V).Installed)
{
    Install-WindowsFeature Hyper-V -IncludeManagementTools -Restart
}

#endregion
#Inializing the disk and creating/formating a new volume
#Get-Disk -Number 2 | Clear-Disk -RemoveData -Confirm:$false -PassThru | Set-Disk -IsOffline $true -Verbose
$Disk = Get-Disk | Where-Object PartitionStyle -Eq "RAW" | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -NewFileSystemLabel Data

$HyperVPath = "$($Disk.DriveLetter):\Virtual Machines\Hyper-V"
$null = New-Item -Path $HyperVPath -ItemType Directory -Force
Set-VMHost -VirtualHardDiskPath $HyperVPath -VirtualMachinePath $HyperVPath

#region Installing and Seting up AutomatedLab
#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Install-Module AutomatedLab -SkipPublisherCheck -AllowClobber -Force -Verbose

#  Disable (which is already the default) and in addition skip dialog
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'

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
    'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
}
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) }  -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
#endregion
