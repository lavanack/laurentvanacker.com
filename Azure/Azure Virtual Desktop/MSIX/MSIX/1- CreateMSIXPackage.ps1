﻿#requires -Version 5 -RunAsAdministrator 
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#Timestamp URL server
#http://timestamp.digicert.com

Set-Location -Path $CurrentDir


Set-WinUserLanguageList -LanguageList fr-fr -Force
#region Installing winget via the WingetTools Powershell module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name WingetTools -Force -Verbose
Install-WinGet -Preview -PassThru -Verbose
#endregion

$CommandLine = 'winget install "MSIX Packaging Tool" --source msstore --accept-source-agreements --accept-package-agreements'
Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $CommandLine -Wait

# Install only the PowerShell module to have VHD Management cmdlets
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).State -ne 'Enabled')
{
    #Manage MSIX app attach
    # Install only the PowerShell module to have VHD Management cmdlets
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All
    Restart-Computer -Force
}
Set-Location $CurrentDir
#10 years from now
$ExpirationDate = (Get-Date).AddYears(10)
$ClearTextPassword = 'P@ssw0rd'
#Full file path for the certificate export file
$PFXFilePath = Join-Path -Path $CurrentDir -ChildPath MSIXDigitalSignature.pfx
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
#Remove any previously existing certificate
Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object -FilterScript {$_.Subject -eq "CN=Contoso Software, O=Contoso Corporation, C=US"} | Remove-Item -Verbose -Force 

#If we don't already have a PFX file we can use ==> Generating a Self-signed certificate expiring in 10 years
if (-not(Test-Path -Path $PFXFilePath))
{
    #$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=Contoso Software, O=Contoso Corporation, C=US" -KeyUsage DigitalSignature -FriendlyName "'MSIX Code Signing Certificate" -CertStoreLocation "Cert:\CurrentUser\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") -NotAfter $ExpirationDate
    $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=Contoso Software, O=Contoso Corporation, C=US" -KeyUsage DigitalSignature -FriendlyName "'MSIX Code Signing Certificate" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "cert:\LocalMachine\My" -NotAfter $ExpirationDate
    $cert | Export-PfxCertificate -FilePath $PFXFilePath -Password $SecurePassword
    #Remove the newly generated certificate
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object -FilterScript {$_.Subject -eq "CN=Contoso Software, O=Contoso Corporation, C=US"} | Remove-Item -Verbose -Force 
}

#Getting notepad++ latest version if possible
$HTMLResponse = Invoke-WebRequest -Uri "https://notepad-plus-plus.org/downloads/"
if ($HTMLResponse.Content -match "Current Version (?<version>\d\.\d\.\d)")
{
    #Get the latest version
    $NotepadPlusPlusVersion=$Matches["Version"]
}
else
{
    #Update this line to reflect the latest release of Notepad++ 
    $NotepadPlusPlusVersion="8.4.8"
}
#Downloading notepad++ 
$NotepadPlusPlusUri = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v$NotepadPlusPlusVersion/npp.$NotepadPlusPlusVersion.Installer.x64.exe"
$Outfile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $NotepadPlusPlusUri -Leaf)
If (-not(Test-Path -Path $Outfile))
{
    Write-Verbose -Message "Downloading Notepad++ v$NotepadPlusPlusVersion ..."
    Invoke-WebRequest -Uri $NotepadPlusPlusUri -UseBasicParsing -OutFile $Outfile -Verbose
}


#Uninstalling any previously installed notepad++ program (if any)
#https://github.com/MicrosoftDocs/PowerShell-Docs/issues/4619
Get-Package "notepad*" -ErrorAction Ignore | ForEach-Object -Process { Start-Process $($_.Meta.Attributes["UninstallString"])}
Get-AppxPackage -Name "notepad*" | Remove-AppxPackage -Verbose

#region : Demonstration via GUI
#    - Proceed as explained on https://christiaanbrinkhoff.com/2020/12/02/the-future-of-application-virtualization-learn-here-how-to-create-and-configure-msix-app-attach-packages-containers-on-windows-10-enterprise-multi-and-single-session-build-2004-and-higher-for-win/#Prepare
#    - Use previoulsy downloaded NotePad++ installer, the self-signed certificate and http://timestamp.digicert.com as Timestamp server URL
#endregion

#Log files
start $env:LOCALAPPDATA\packages\Microsoft.MsixPackagingTool_8wekyb3d8bbwe\LocalState\DiagOutputDir\

$MSIXFilePath = Get-ChildItem -Path $CurrentDir -Filter *.msix -File
$MSIXFilePath

#Uninstalling any previously installed notepad++ program (if any)
#https://github.com/MicrosoftDocs/PowerShell-Docs/issues/4619
#Get-AppxPackage -Name "notepad*" | Remove-AppxPackage -Verbose
Get-Package "notepad*" -ErrorAction Ignore | ForEach-Object -Process { Start-Process $($_.Meta.Attributes["UninstallString"])}

#To create a VHD
$MSIXVHD = Join-Path -Path $CurrentDir -ChildPath notepadplusplus.vhd
Remove-Item $MSIXVHD -Force -ErrorAction Ignore
New-VHD -SizeBytes 1GB -Path $MSIXVHD -Dynamic -Confirm:$false

#To mount the newly created VHD, run:
$vhdObject = Mount-VHD -Path $MSIXVHD -Passthru

#To initialize the VHD, run:
$disk = Initialize-Disk -Passthru -Number $vhdObject.Number

#To create a new partition, run:
$partition = New-Partition -AssignDriveLetter -UseMaximumSize -DiskNumber $disk.Number

#To format the partition, run:
Format-Volume -FileSystem NTFS -Confirm:$false -DriveLetter $partition.DriveLetter -NewFileSystemLabel "NotepadPlusPlus_$NotepadPlusPlusVersion"  -Force


$MSIXMgrUri = "https://aka.ms/msixmgr"
$Outfile = Join-Path -Path $CurrentDir -ChildPath $(Split-Path -Path $MSIXMgrUri -Leaf)
$Outfile += ".zip"
If (-not(Test-Path -Path $Outfile))
{
    Write-Verbose -Message "Downloading MSIX Mgr Tool ..."
    Invoke-WebRequest -Uri $MSIXMgrUri -UseBasicParsing -OutFile $Outfile -Verbose
}
Expand-Archive -Path .\msixmgr.zip -Force

& "$CurrentDir\msixmgr\x64\msixmgr.exe" -Unpack -packagePath $MSIXFilePath.FullName -destination "$($partition.DriveLetter):\notepadplusplus" -applyacls

Dismount-VHD -Path $MSIXVHD