Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$ResourceGroupName  = "msws-poshcore-vm-rg"
$Location           = "EastUs"
$StorageAccountName = "mswsposhcorevmsa" # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$DSCFileName        = "WebServerDSC.ps1"
$DSCFilePath        = Join-Path -Path $CurrentDir -ChildPath $DSCFileName
$VMName 	        = "WinSrv2019"
$ConfigurationName  = "WebServerConfiguration"

# Publishing DSC Configuration
Publish-AzVMDscConfiguration $DSCFilePath -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose

$VM = Get-AzVM -Name $VMName

Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$DSCFileName.zip" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $ConfigurationName -Version "2.80" -Location $Location -AutoUpdate -Verbose
$VM | Update-AzVM -Verbose

#Get the Public IP address dynamically
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.IpConfiguration.Id -like "*$VMName*" } | Select-Object -First 1

#Browsing to the new IIS Web Site
Start-Process "http://$($PublicIP.IpAddress)"