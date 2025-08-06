Clear-Host
$StartTime = Get-Date
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

$Error.clear()
$ModuleName = "PSAzAvd"
$ModuleVersion = '1.0.0.2'
$PSModulePath = Join-Path -Path $($env:ProgramFiles) -ChildPath "WindowsPowerShell\Modules"
$ModuleVersionFolder = Join-Path -Path $PSModulePath -ChildPath "$ModuleName\$ModuleVersion"
$ModuleFilePath = Join-Path -Path $ModuleVersionFolder -ChildPath "$ModuleName.psm1"
$ModuleManifestFilePath = Join-Path -Path $ModuleVersionFolder -ChildPath "$ModuleName.psd1"
$ScriptsToProcess = '.\ScriptsToProcess\ClassLoader.ps1'
#$FunctionToExport = 'Test-Domaincontroller', 'Install-RequiredModule', 'Connect-Azure', 'Register-AzRequiredResourceProvider', 'Install-FSLogixGPOSetting', 'Install-AVDGPOSetting', 'New-AzHostPoolSessionCredentialKeyVault', 'Reset-PooledHostPoolIndex', 'Reset-PersonalHostPoolIndex', 'Set-PooledHostPoolIndex', 'Set-PersonalHostPoolIndex', 'Get-PooledHostPoolIndex', 'Get-PersonalHostPoolIndex', 'New-PooledHostPool', 'New-PersonalHostPool', 'New-AzureComputeGallery', 'Remove-AzAvdHostPoolSetup', 'Test-AzAvdStorageAccountNameAvailability', 'Test-AzAvdKeyVaultNameAvailability', 'New-AzAvdHostPoolBackup', 'New-AzAvdHostPoolSetup', 'New-AzAvdScalingPlan', 'New-AzAvdRdcMan', 'Restart-AzAvdSessionHost', 'Start-MicrosoftEntraIDConnectSync', 'Invoke-AzAvdOperationalInsightsQuery'
$FunctionToExport = 'Test-Domaincontroller', 'Install-RequiredModule', 'Connect-Azure', 'Register-AzRequiredResourceProvider', 'Install-FSLogixGPOSetting', 'Install-AVDGPOSetting', 'New-AzHostPoolSessionCredentialKeyVault', 'New-PooledHostPool', 'New-PersonalHostPool', 'New-AzureComputeGallery', 'Remove-AzAvdHostPoolSetup', 'Test-AzAvdStorageAccountNameAvailability', 'Test-AzAvdKeyVaultNameAvailability', 'New-AzAvdHostPoolBackup', 'New-AzAvdHostPoolSetup', 'New-AzAvdScalingPlan', 'New-AzAvdRdcMan', 'Restart-AzAvdSessionHost', 'Start-MicrosoftEntraIDConnectSync', 'Invoke-AzAvdOperationalInsightsQuery'

$ModuleBase = (Get-Module -Name PSAzureVirtualDesktop -ListAvailable).ModuleBase
$Results = Select-String -Pattern "^function\s+(?<Name>[\w|-]+)" -Path $(Join-Path -Path $ModuleBase -ChildPath "PSAzureVirtualDesktop.psm1" )
$AllFunctions = $Results | ForEach-Object -Process {
    $_.Matches.Groups[1].Captures.value
}

$moduleSettings = @{
    RequiredModules = @('Az.Accounts', @{ ModuleName='Az.Compute'; MinimumVersion='7.1.2' }, 'Az.DesktopVirtualization', 'Az.ImageBuilder', 'Az.ManagedServiceIdentity', 'Az.KeyVault', 'Az.Monitor', 'Az.Network', 'Az.OperationalInsights', 'Az.PrivateDns', 'Az.Resources', 'Az.Storage', @{ ModuleName='Microsoft.Graph.Authentication'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement.Actions'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.DeviceManagement.Administration'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Groups'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Identity.DirectoryManagement'; MaximumVersion='2.17.0' }, @{ ModuleName='Microsoft.Graph.Beta.Identity.SignIns'; MaximumVersion='2.17.0' }, 'PsAzAvd', 'ThreadJob')
    Path = $ModuleManifestFilePath
    Author= 'Laurent VAN ACKER'
    PowerShellVersion = '5.1'
    FunctionsToExport = $FunctionToExport
    Description = 'Build Azure AVD POCs'
    ModuleVersion = $ModuleVersion
    Tags = 'Azure','AVD','POC'
    RootModule = Split-Path -Path $ModuleFilePath -Leaf
    ScriptsToProcess = $ScriptsToProcess
    CompatiblePSEditions = 'Desktop'
    Copyright = $(Get-Date -Format yyyy)
    DotNetFrameworkVersion = '4.0'
    CLRVersion = '4.0'
}

$FunctionPattern = @'

function <FUNCTION> {
    [CmdletBinding()]
    Param (
    )
    return "Hello World !"
}
'@

$FunctionContent = $FunctionToExport | ForEach-Object -Process {
    $FunctionPattern -replace '\<FUNCTION\>', $_
}

$ModuleFileContent = @"
$FunctionContent

Export-ModuleMember -Function $($FunctionToExport -join ', ')
"@

Remove-Module -Name $ModuleName -Force -Verbose -ErrorAction Ignore
$null = New-Item -Path $ModuleFilePath -ItemType File -Value $ModuleFileContent -Force
$ModuleScriptsToProcess = New-Item -Path $(Join-Path -Path $ModuleVersionFolder -ChildPath $ScriptsToProcess) -ItemType File -Force
New-ModuleManifest @moduleSettings

psedit $moduleSettings.Path, $ModuleFilePath, $ModuleScriptsToProcess

Get-Module -Name $ModuleName -ListAvailable
Get-Command -Module $ModuleName
(Get-Module -Name $ModuleName -ListAvailable).ModuleBase
Remove-Module -Name $ModuleName -Force -Verbose -ErrorAction Ignore


<#
#region for counting function calls
$ModuleBase = (Get-Module -Name PSAzureVirtualDesktop -ListAvailable).ModuleBase
$Module = $(Join-Path -Path $ModuleBase -ChildPath "PSAzureVirtualDesktop.psm1" )

$Results = Select-String -Pattern "^function\s+(?<Name>[\w|-]+)" -Path $Module
$AllFunctions = $Results | ForEach-Object -Process {
    $_.Matches.Groups[1].Captures.value
}
$AllFunctions



$Results = Select-String -Pattern "(?<Name>$($AllFunctions -join '|'))" -Path $Module
$AllFunctions = $Results | ForEach-Object -Process {
    $_.Matches.Groups[1].Captures.value
}
$AllFunctions | Group-Object -NoElement | Where-Object -FilterScript { $_.Count -eq 1} | Select-Object -Property Name | Sort-Object -Property Name #Sort-Object -Property Count -Descending
#$AllFunctions | Group-Object -NoElement | Sort-Object -Property Count -Descending
#endregion
#>