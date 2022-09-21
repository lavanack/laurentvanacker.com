Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

$ResourcePrefix     = "dscvmext"
$ResourceGroupName  = "$ResourcePrefix-rg-$Location"
$Location           = "eastus"
$StorageAccountName = "{0}sa{1}" -f $ResourcePrefix, $Location # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name $StorageAccountName 
$StorageAccountName = $StorageAccountName.Substring(0, [system.math]::min(24, $StorageAccountName.Length))
$DSCFileName        = "WebServerDSC.ps1"
$DSCFilePath        = Join-Path -Path $CurrentDir -ChildPath $DSCFileName
$VMName 	        = "{0}ws2019" -f $ResourcePrefix
$VMName             = $VMName.Substring(0, [system.math]::min(15, $VMName.Length))
$ConfigurationName  = "WebServerConfiguration"
$FQDN               = "$VMName.$Location.cloudapp.azure.com".ToLower()

# Publishing DSC Configuration
Publish-AzVMDscConfiguration $DSCFilePath -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -Force -Verbose

#region Adding the DSC extension
$VM = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
Set-AzVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -ArchiveBlobName "$DSCFileName.zip" -ArchiveStorageAccountName $StorageAccountName -ConfigurationName $ConfigurationName -Version "2.80" -Location $Location -AutoUpdate -Verbose
$VM | Update-AzVM -Verbose
#endregion 

#Get the Public IP address dynamically
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.IpConfiguration.Id -like "*$VMName*" } | Select-Object -First 1

#Browsing to the new IIS Web Site
#Start-Process "http://$($PublicIP.IpAddress)"
Start-Process "http://$FQDN"
