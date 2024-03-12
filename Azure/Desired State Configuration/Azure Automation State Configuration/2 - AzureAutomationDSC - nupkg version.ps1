#requires -Version 5 -RunAsAdministrator 
#To run from the Azure VM
#More info on https://docs.microsoft.com/en-us/azure/automation/automation-dsc-overview
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#region Function Definitions
function Invoke-FileDownload {
    <#
    .SYNOPSIS
        Given the result of WebResponseObject, download the file to disk without having to specify a name.
    .DESCRIPTION
        Given the result of WebResponseObject, download the file to disk without having to specify a name.
    .PARAMETER WebResponse
        A WebResponseObject from running an Invoke-WebRequest on a file to download
    .EXAMPLE
        # Download the Linux kernel source
        Invoke-FileDownload -Uri 'https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.3.tar.xz'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $Uri,

        [Parameter(Mandatory = $false)]
        [String]
        $Directory = "$PWD"
    )

    # Manually invoke a web request
    $Request = [System.Net.WebRequest]::Create($Uri)
    $Request.AllowAutoRedirect = $true

    try {
        $Response = $Request.GetResponse()
    }
    catch {
        Write-Error 'Error: Web request failed.' -ErrorAction Stop
    }
    finally {
        if ($Response.StatusCode -eq 'OK') {
            $AbsoluteUri = $Response.ResponseUri.AbsoluteUri
            $FileName = [System.IO.Path]::GetFileName($AbsoluteUri)
            if (-not $FileName) { Write-Error 'Error: Failed to resolve file name from URI.' -ErrorAction Stop }
            if (-not (Test-Path -Path $Directory)) { [System.IO.Directory]::CreateDirectory($Directory) }
            $FullPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Directory, $FileName))
            Write-Verbose -Message "Downloading '$FileName' to: '$FullPath'"
            Invoke-WebRequest -Uri $Uri -OutFile $FullPath
            Write-Verbose -Message 'Download complete.'
        }
        if ($Response) { $Response.Close() }
    }
    return $FullPath
}
#endregion

#Installing the NuGet Provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az.Compute, Az.Storage, Az.Automation -Force

#Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 �Online -NoRestart
#region Disabling IE Enhanced Security
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force
#endregion

#region Logging to Azure and selecting the subscription
Connect-AzAccount
Get-AzSubscription | Out-GridView -OutputMode Single | Select-AzSubscription
#endregion

$VMName = $env:COMPUTERNAME
$AzVM = Get-AzVM -Name $VMName 
$Location = $AzVM.Location
$ResourceGroupName = $AzVM.ResourceGroupName
$StorageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName
$StorageAccountName = $StorageAccount.StorageAccountName
$AutomationAccountName = "{0}aa" -f $VMName
$DSCFileName = "WebServer.ps1"
$DSCFilePath = Join-Path -Path $CurrentDir -ChildPath $DSCFileName
$ConfigurationName = "WebServer"
$ConfigurationDataFileName = "configurationdata.psd1"
$ConfigurationDataFilePath = Join-Path -Path $CurrentDir -ChildPath $ConfigurationDataFileName
$Modules = "WebAdministrationDsc"

$NuPkgFilePaths = foreach ($CurrentModule in $Modules) {
    $URI = "https://www.powershellgallery.com/api/v2/package/{0}/" -f $CurrentModule 
    Invoke-FileDownload -Uri $URI -Verbose
}

$AutomationAccount = Get-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not($AutomationAccount)) {
    $AutomationAccount = New-AzAutomationAccount -Name $AutomationAccountName -Location $Location -ResourceGroupName $ResourceGroupName
}


#region Importing and Compiling the DSC configuration (and importing the required modules)
Import-AzAutomationDscConfiguration -SourcePath $DSCFilePath -Published -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Force

$container = Get-AzStorageContainer -Name modules -Context $storageAccount.Context -ErrorAction SilentlyContinue
if (-not($container)) {
    $container = New-AzStorageContainer -Name modules -Context $storageAccount.Context
}

#$modulePath = Read-Host -Prompt 'Path to your modules'
foreach ($CurrentNuPkgFile in (Get-Item $NuPkgFilePaths)) {
    Write-Host -Object "Processing '$CurrentNuPkgFile' ..."
    $content = Set-AzStorageBlobContent -File $CurrentNuPkgFile.Name -CloudBlobContainer $container.CloudBlobContainer -Blob $CurrentNuPkgFile.Name -Context $storageAccount.Context -Force -ErrorAction Stop
    $uri = New-AzStorageBlobSASToken -CloudBlob $content.ICloudBlob -StartTime (Get-Date) -ExpiryTime (Get-Date).AddYears(5) -Protocol HttpsOnly -Context $storageAccount.Context -Permission r -FullUri -ErrorAction Stop
    $ModuleName = $CurrentNuPkgFile.BaseName -replace "\..*$"
    New-AzAutomationModule -Name $ModuleName -ContentLinkUri $uri -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Verbose
}

while (Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | Where-Object -FilterScript { ($_.ProvisioningState -eq 'Creating') }) {
    Write-Host "Waiting the required modules finish importing ..."
    Start-Sleep -Second 5
}

Start-Sleep -Second 30

$ConfigurationData = (Import-PowerShellDataFile $ConfigurationDataFilePath)
#Replacing localhost by the computer name
$($ConfigurationData['AllNodes'])['NodeName'] = $env:COMPUTERNAME
$CompilationJob = Start-AzAutomationDscCompilationJob -ConfigurationName $ConfigurationName -ConfigurationData $ConfigurationData -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
while ($null -eq $CompilationJob.EndTime -and $null -eq $CompilationJob.Exception) {
    $CompilationJob = $CompilationJob | Get-AzAutomationDscCompilationJob
    Write-Host "Waiting the DSC compilation job completes ..."    
    Start-Sleep -Second 5
}
$CompilationJob | Get-AzAutomationDscCompilationJobOutput -Stream Any
#endregion

#region Setting up the LCM and applying the configuration
#Alternative: https://docs.microsoft.com/en-us/azure/automation/automation-dsc-onboarding#generate-dsc-metaconfigurations-using-a-dsc-configuration
Get-AzAutomationDscOnboardingMetaconfig -ComputerName $env:COMPUTERNAME -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -OutputFolder . -Force
Set-DscLocalConfigurationManager -Path ./DscMetaConfigs -Force
#Register-AzAutomationDscNode -AzureVMName $env:COMPUTERNAME -ResourceGroupName $ResourceGroupName  -AutomationAccountName $AutomationAccountName -NodeConfigurationName $ConfigurationName.$env:COMPUTERNAME -ConfigurationMode ApplyAndAutocorrect
$node = Get-AzAutomationDscNode -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | Set-AzAutomationDscNode -NodeConfigurationName "$ConfigurationName.$env:COMPUTERNAME" -Force

Start-Sleep -Second 15
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
