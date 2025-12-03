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
#requires -Version 5 #-Modules ActiveDirectoryDsc, ComputerManagementDsc, SqlServerDsc -RunAsAdministrator 

Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#Switching to French Keyboard
Set-WinUserLanguageList fr-fr -Force

#region Applying the configuration
#region Credential Management
#Variable for credentials
$SQLAdmin = "$((Get-ADDomain).Name)\SQLAdministrator"
$ClearTextPassword = 'P@ssw0rd'
#Just use CTRL+V when prompted for the password(s)
$ClearTextPassword | Set-Clipboard

$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force
$ActiveDirectoryAdministratorCredential = New-Object System.Management.Automation.PSCredential($(whoami), $SecurePassword)
$SqlInstallCredential = New-Object System.Management.Automation.PSCredential($(whoami), $SecurePassword)
$SqlServiceCredential = New-Object System.Management.Automation.PSCredential($SQLAdmin, $SecurePassword)
$SqlAgentServiceCredential = New-Object System.Management.Automation.PSCredential($SQLAdmin, $SecurePassword)
$SqlSACredential = New-Object System.Management.Automation.PSCredential('SA', $SecurePassword)

$DSCConfigurationParameters = @{
    ActiveDirectoryAdministratorCredential = $ActiveDirectoryAdministratorCredential 
    SqlInstallCredential                   = $SqlInstallCredential 
    SqlServiceCredential                   = $SqlServiceCredential 
    SqlAgentServiceCredential              = $SqlAgentServiceCredential 
    SqlSACredential                        = $SqlSACredential
    ConfigurationData                      = "$CurrentDir\DSC-CreateDefaultInstance.psd1"
}
#endregion


#region Setting up DSC Event Logs and WinRM
$TargetNodes = 'SQLNODE01' #, 'SQLNODE02'
Invoke-Command -ComputerName $TargetNodes -ScriptBlock {
    #wevtutil set-log "Microsoft-Windows-Dsc/Analytic" /q:True /e:true
    #wevtutil set-log "Microsoft-Windows-Dsc/Debug" /q:True /e:true

    #We have to increase the data authorized to transit via WinRM (Set to 8Mb Here)
    if ((Get-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb).Value -lt 8192) {
        Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 8192		
    }

    "Microsoft-Windows-Dsc/Debug", "Microsoft-Windows-Dsc/Analytic" | ForEach-Object -Process {
        $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $_
        if (-not($log.IsEnabled)) {
            $log.IsEnabled = $true
            $log.SaveChanges()
        }
    }
}
#endregion

#Setting LCM configuration
& "$CurrentDir\Set-LCM.ps1"

#region Generating the DSC Configuration
#Dot sourcing the DSC configuration
. "$CurrentDir\DSC-CreateDefaultInstance.ps1"

#Removing any previously existing MOF files
Remove-Item -Path "$CurrentDir\CreateDefaultInstance" -Recurse -Force -ErrorAction Ignore
 
CreateDefaultInstance @DSCConfigurationParameters -Verbose

$ConfigurationName = "CreateDefaultInstance"
Remove-Item -Path "$CurrentDir\CreateDefaultInstance\$ConfigurationName.mof" -ErrorAction Ignore
Rename-Item -Path "$CurrentDir\CreateDefaultInstance\localhost.mof" -NewName "$ConfigurationName.mof"

$DscServiceModulesDirectory = "$env:ProgramFiles\WindowsPowerShell\DscService\Modules\"
$DscServiceConfigurationDirectory = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration\"
New-DscChecksum -Path "$CurrentDir\CreateDefaultInstance\$ConfigurationName.mof"
$Session = New-PSSession -ComputerName "PULL"
Copy-Item "$CurrentDir\CreateDefaultInstance\$ConfigurationName.mof*" -Destination $DscServiceConfigurationDirectory -ToSession $Session -Force


Invoke-Command -ScriptBlock {
    #region Prerequisites
    if (-not(Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed) {
        Install-WindowsFeature -Name RSAT-AD-PowerShell -Verbose
    }
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

    $null = Get-PackageProvider -Name NuGet -Force
    $RequiredModules = 'ActiveDirectoryDsc', 'ComputerManagementDsc', 'SqlServerDsc'
    $InstalledModule = Get-InstalledModule -Name $RequiredModules -ErrorAction Ignore
    if (-not([String]::IsNullOrEmpty($InstalledModule))) {
        $MissingModules = (Compare-Object -ReferenceObject $RequiredModules -DifferenceObject $InstalledModule.Name).InputObject
    }
    else {
        $MissingModules = $RequiredModules
    }
    if (-not([String]::IsNullOrEmpty($MissingModules))) {
        Install-Module -Name $MissingModules -Scope AllUsers -AllowClobber -Force
    }

    #Install-Module -Name ActiveDirectoryDsc, ComputerManagementDsc, SqlServerDsc -Force -AllowClobber
    #endregion 

    $ModuleToCompress = (Get-Module ActiveDirectoryDsc, ComputerManagementDsc, SqlServerDsc -ListAvailable)
    foreach ($CurrentModuleToCompress in $ModuleToCompress) {
        $CurrentModuleBase = $CurrentModuleToCompress.ModuleBase
        $ArchiveFileName = "{0}_{1}.zip" -f $CurrentModuleToCompress.Name, $CurrentModuleToCompress.Version
        $ArchiveDestinationPath = Join-Path $using:DscServiceModulesDirectory -ChildPath $ArchiveFileName
        Compress-Archive -Path $CurrentModuleBase -DestinationPath $ArchiveDestinationPath -Force -Verbose
        New-DscChecksum -Path $ArchiveDestinationPath
    }

    Get-ChildItem -Path $using:DscServiceConfigurationDirectory, $using:DscServiceModulesDirectory
} -Session $Session -Verbose

Update-DscConfiguration -ComputerName $TargetNodes -Wait -Verbose
#endregion
break

#region Testing the configuration
#For a 2-node cluster
$TargetNodes = 'SQLNODE01'#, 'SQLNODE02'
#Testing the configuration
$Result = Test-DscConfiguration -Detailed -ComputerName $TargetNodes -Verbose
$Result | Format-List * -Force

#Getting all DSC entries and sending them in a JSON file
#Getting the current directory (where this script file resides)
$OutputDir = $env:Temp
#For DSC event log filtering
$StartTime = [datetime]::Today.ToString('s')
$JSONFile = $TargetNodes | ForEach-Object -Process {
    $ComputerName = $_
    #eventvwr $ComputerName /c:Microsoft-Windows-Dsc/Operational #/f:"*[System[((EventID=4512) or (EventID=4513))]]"
    (Get-WinEvent -LogName "Microsoft-Windows-Dsc/Operational" -FilterXPath "*[System[((EventID=4512) or (EventID=4513)) and TimeCreated[@SystemTime>'$StartTime']]]" -ComputerName $ComputerName) | Sort-Object -Property TimeCreated | ForEach-Object {
        if ($_.Message -match "[to|for]\s+(?<JSONFile>.*)") {
            [PSCustomObject]@{"ComputerName" = $ComputerName; "FullName" = $Matches['JSONFile']; "UNCPath" = '\\' + $ComputerName + '\' + $Matches['JSONFile'] -replace ':', '$'; TimeCreated = $_.TimeCreated }
        }
    }
} | Sort-Object -Property TimeCreated, ComputerName

$ConfigurationStatusJSONFile = Join-Path -Path $OutputDir -ChildPath ConfigurationStatus-All.details.json
$ConfigurationStatusJSONFile
Get-ChildItem $JSONFile.UNCPath | Sort-Object -Property LastWriteTime | Get-Content -Encoding Unknown -ErrorAction Ignore | Out-File $ConfigurationStatusJSONFile
#Opening the JSON file
& $ConfigurationStatusJSONFile

#Start-DscConfiguration -UseExisting -ComputerName $TargetNodes -Wait -Force -Verbose 
#endregion 
