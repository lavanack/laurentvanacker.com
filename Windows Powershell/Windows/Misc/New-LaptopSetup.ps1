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
#requires -Version 5 -RunAsAdministrator 

[CmdletBinding(PositionalBinding = $false)]
Param (
)

Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Installing Hyper-V
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -ne 'Enabled')
{
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Restart-Computer -Force
}

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All
$HyperVPath = "$env:SystemDrive\Virtual Machines\Hyper-V"
$null = New-Item -Path $HyperVPath -ItemType Directory -Force
Set-VMHost -VirtualHardDiskPath $HyperVPath -VirtualMachinePath $HyperVPath
#endregion


#region Disabling IP V6
#Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
#endregion

#region Local Admin Setup
$LocalAdminCredential = Get-Credential -UserName localadmin -Message "Enter the local admin credential"
$LocalAdminUser = New-LocalUser -Name $LocalAdminCredential.UserName -Password $LocalAdminCredential.Password -AccountNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member $LocalAdminUser
#endregion

#region Folder Setup
$null = New-Item -Path "$env:SystemDrive\Temp", "$env:SystemDrive\Tools", "$env:SystemDrive\Source Control\GitHub" -ItemType Directory -Force
[Environment]::SetEnvironmentVariable("PATH", "$env:Path;$env:SystemDrive\Tools;$env:SystemDrive\LabSources\Tools\SysInternals", "Machine")
#endregion

#region High performance
$Result = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-string | Select-String -Pattern "GUID:\s(?<guid>.*)\s+\("
$SchemeId = $Result.Matches.Captures[0].Groups["guid"].Value
powercfg /s $SchemeId
#endregion

#region Software Setup
#region WinGet
winget upgrade --all --silent --accept-package-agreements --accept-source-agreements

winget install --exact --id=Microsoft.Office
winget install --exact --id=Microsoft.Teams
winget install --exact --id=Mozilla.Firefox
winget install --exact --id=Mozilla.Thunderbird
winget install --exact --id=Notepad++.Notepad++
winget install --exact --id=Microsoft.PowerToys
winget install --exact --id=VideoLAN.VLC
winget install --exact --id=RARLab.WinRAR
winget install --exact --id=Bitwarden.Bitwarden
winget install --exact --id=Foxit.FoxitReader
winget install --exact --id=Intel.IntelDriverAndSupportAssistant
winget install --exact --id=WiresharkFoundation.Wireshark
winget install --exact --id=Microsoft.VisualStudioCode.Insiders
#winget install --exact --id=Microsoft.VisualStudioCode
winget install --exact --id=Microsoft.AzureCLI
winget install --exact --id=Synology.SurveillanceStationClient
winget install --exact --id=Synology.CloudStationDrive 
winget install --exact --id=WinMerge.WinMerge
winget install --exact --id=NordSecurity.NordVPN
winget install --exact --id=Brother.iPrintScan
winget install --exact --id=Microsoft.WindowsTerminal
winget install --exact --id=Microsoft.PowerShell
winget install --exact --id=Microsoft.Azure.StorageExplorer
winget install --exact --id=GitHub.cli
winget install --exact --id=Microsoft.WindowsApp

#region Git
winget install --exact --id=Git.Git
git config --global user.name "Laurent VAN ACKER"
git config --global user.email laurent.vanacker@free.fr
git lfs install
#From https://support.atlassian.com/bamboo/kb/git-checkouts-fail-on-windows-with-filename-too-long-error-unable-to-create-file-errors/
git config --system core.longpaths true
#region Repo cloning
Push-Location -Path "$env:SystemDrive\Source Control\GitHub"
git clone https://github.com/lavanack/laurentvanacker.com.git
git clone https://github.com/lavanack/PSAzureVirtualDesktop.git
Pop-Location 
#endregion
#endregion

winget install "Microsoft Whiteboard" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Lenovo Vantage" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Microsoft 365 Copilot" --accept-package-agreements --accept-source-agreements --source msstore
winget install "WhatsApp" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Snapchat" --accept-package-agreements --accept-source-agreements --source msstore
winget install "NVIDIA Control Panel" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Portail d'entreprise" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Power BI Desktop" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Disney+" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Netflix" --accept-package-agreements --accept-source-agreements --source msstore
winget install "Prime Video pour Windows" --accept-package-agreements --accept-source-agreements --source msstore
#winget install "Windows Terminal" --accept-package-agreements --accept-source-agreements --source msstore
#endregion

#region Other Ways
<#
#Installing Powershell 7+ : Silent Install
Invoke-Expression -Command "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

$FireFoxSetup = Join-Path -Path $env:TEMP -ChildPath "FirefoxSetup.exe"
Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest&os=win64&lang=en-GB" -OutFile $FireFoxSetup
& $FireFoxSetup /S /PreventRebootRequired=true
#>

$VSCodeExtension = [ordered]@{
    #'Live Share Extension Pack' = 'ms-vsliveshare.vsliveshare-pack'
    "PowerShell" = "ms-vscode.powershell"
    'Git Graph' = 'mhutchie.git-graph'
    'Git History' = 'donjayamanne.githistory'
    'GitLens - Git supercharged' = 'eamodio.gitlens'
    'Git File History' = 'pomber.git-file-history'
    'indent-rainbow' = 'oderwat.indent-rainbow'
    'markdownlint' = 'davidanson.vscode-markdownlint'
    'Markdown All in One' = 'yzhang.markdown-all-in-one'
    'GitHub Copilot' = 'github.copilot'
    'GitHub Copilot Chat' = 'github.copilot-chat'

}
#Installing VSCode with Powershell extension (and optional additional ones)
Invoke-Expression -Command "& { $(Invoke-RestMethod https://raw.githubusercontent.com/PowerShell/vscode-powershell/master/scripts/Install-VSCode.ps1) } -AdditionalExtensions $($VSCodeExtension.Values -join ',')" -Verbose
#endregion
#endregion

#region Powershell Modules
#Releasing Execution Policy
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force
Set-PSRepository  -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name AutomatedLab, Az, Microsoft.Graph -Scope AllUsers -AllowClobber -SkipPublisherCheck -Verbose

#region AutomatedLab 
#  Disable (which is already the default) and in addition skip dialog
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'

# Pre-configure Lab Host Remoting
Enable-LabHostRemoting -Force
New-LabSourcesFolder -DriveLetter $env:SystemDrive
#endregion
#endregion

#region Other applications
Start-Process "https://aka.ms/casebuddy"
Start-Process "ms-phone://"
#endregion

#region Outlook: Enable Meeting Copy
#From https://techcommunity.microsoft.com/discussions/outlookgeneral/enable-meeting-copy/3981146/replies/3999316
Set-ItemProperty -Path  'HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\Calendar' -Name "EnableMeetingCopy" -Type ([Microsoft.Win32.RegistryValueKind]::Dword) -value 1
#endregion 

#region Windows Subsystem for Linux
wsl --install
#endregion
