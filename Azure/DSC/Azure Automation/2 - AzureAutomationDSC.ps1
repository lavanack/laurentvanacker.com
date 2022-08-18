#requires -Version 5 -RunAsAdministrator 
#To run from the Azure VM
#More info on https://docs.microsoft.com/en-us/azure/automation/automation-dsc-overview
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name xWebAdministration, Az.Storage, Az.Automation -Force

$Location                       = "EastUs"
$ResourcePrefix                 = "dscazaut"
$ResourceGroupName              = "$ResourcePrefix-rg-$Location"
$StorageAccountName             = "{0}sa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$VMName 	                    = "{0}ws2019" -f $ResourcePrefix
$AutomationAccountName          = "{0}aa" -f $ResourcePrefix # Name must be unique. Name availability can be check using PowerShell command Get-AzStorageAccountNameAvailability -Name ""
$ConfigurationName              = "WebServer"

#region Disabling IE Enhanced Security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force
#endregion

#region Logging to Azure and selecting the subscription
Connect-AzAccount
Get-AzSubscription | Out-GridView -PassThru | Select-AzSubscription
#endregion

$modulePath = [string[]](Get-InstalledModule -Name xWebAdministration).InstalledLocation | Split-Path -Parent
$storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName

$AutomationAccount = Get-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not($AutomationAccount))
{
    $AutomationAccount = New-AzAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroupName
}


#region Importing and Compiling the DSC configuration (and importing the required modules)
Import-AzAutomationDscConfiguration -SourcePath $CurrentDir\WebServer.ps1 -Published -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Force

$container = Get-AzStorageContainer -Name modules -Context $storageAccount.Context -ErrorAction SilentlyContinue
if (-not($container))
{
    $container = New-AzStorageContainer -Name modules -Context $storageAccount.Context
}

#$modulePath = Read-Host -Prompt 'Path to your modules'
foreach ($module in (Get-Item $modulePath))
{
   $versionedFolder = $module | Get-ChildItem -Directory | Select-Object -First 1
   $archiveName = '{0}_{1}.zip' -f $module.BaseName, $versionedFolder.BaseName
   Compress-Archive -Path "$($versionedFolder.FullName)/*" -DestinationPath $archiveName -Update
   $content = Set-AzStorageBlobContent -File $archiveName -CloudBlobContainer $container.CloudBlobContainer -Blob $archiveName -Context $storageAccount.Context -Force -ErrorAction Stop
   $token = New-AzStorageBlobSASToken -CloudBlob $content.ICloudBlob -StartTime (Get-Date) -ExpiryTime (Get-Date).AddYears(5) -Protocol HttpsOnly -Context $storageAccount.Context -Permission r -ErrorAction Stop
   $uri = '{4}://{3}.blob.core.windows.net/{0}/{1}{2}' -f $container.Name, $archiveName, $token, $storageAccount.StorageAccountName, 'https'
   $uri
   New-AzAutomationModule -Name $module.BaseName -ContentLinkUri $uri -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Verbose
}

while (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | Where-Object ProvisioningState -eq 'Creating')
{
    Write-Host "Waiting the required modules finish importing ..."
    Start-Sleep -Second 5
}

Start-Sleep -Second 30

$CompilationJob = Start-AzAutomationDscCompilationJob -ConfigurationName $ConfigurationName -ConfigurationData (Import-PowerShellDataFile $CurrentDir\configurationdata.psd1) -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
while($null -eq $CompilationJob.EndTime -and $null -eq $CompilationJob.Exception)
{
    $CompilationJob = $CompilationJob | Get-AzAutomationDscCompilationJob
    Write-Host "Waiting the DSC compilation job completes ..."    
    Start-Sleep -Second 5
}
$CompilationJob | Get-AzAutomationDscCompilationJobOutput –Stream Any
#endregion

#region Setting up the LCM and applying the configuration
#Alternative: https://docs.microsoft.com/en-us/azure/automation/automation-dsc-onboarding#generate-dsc-metaconfigurations-using-a-dsc-configuration
Get-AzAutomationDscOnboardingMetaconfig -ComputerName $env:COMPUTERNAME -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -OutputFolder . -Force
Set-DscLocalConfigurationManager -Path ./DscMetaConfigs -Force
#Register-AzAutomationDscNode -AzureVMName $env:COMPUTERNAME -ResourceGroupName $ResourceGroupName  -AutomationAccountName $AutomationAccountName -NodeConfigurationName $ConfigurationName.$env:COMPUTERNAME -ConfigurationMode ApplyAndAutocorrect
$node = Get-AzAutomationDscNode -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | Set-AzAutomationDscNode -NodeConfigurationName "$ConfigurationName.$env:COMPUTERNAME" -Force

Start-Sleep -Second 5
Update-DscConfiguration -Wait -Verbose
#endregion

Start-Process -FilePath http://localhost:81
Start-Sleep -Second 1
Start-Process -FilePath http://localhost:82

# Get the ID of the DSC node
#$node = Get-AzAutomationDscNode -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName 
# Get an array of status reports for the DSC node
$report = Get-AzAutomationDscNodeReport -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -NodeId $node.Id -Latest
$report
