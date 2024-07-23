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
#requires -Version 5 -Modules ThreadJob -RunAsAdministrator

[CmdletBinding()]
param
(
    [switch] $Force
)

Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region function definitions
function Get-LatestModuleVersion {
    [CmdletBinding()]
    param (
        [object] $Module
    )
    Write-Verbose "[$($MyInvocation.MyCommand)] Processing '$($Module.Name)' PowerShell module"
    $FoundUpdates = Find-Module -Name $Module.Name -ErrorAction Ignore
    Write-Verbose -Message "[$($MyInvocation.MyCommand)] Found PowerShell Module Updates:`r`n$($FoundUpdates | Format-Table | Out-String)"
    $FoundUpdates
}

function Uninstall-OldModule {
    [CmdletBinding()]
    param (
        [object] $Module,
        [switch] $Force
    )
    #Removing all versions except the highest one (normally the lastest from the online repository). We have to parse the version to get the correct sorting. Without this "1.11.0" -gt "1.2.0" returns $false
    $ModulesToUninstall = Get-InstalledModule -Name $Module.Name -AllVersions | Select-Object -Property *, @{Name="ParsedVersion"; Expression={[version]::Parse($_.Version)}} | Sort-Object -Property ParsedVersion -Descending | Select-Object -Skip 1
    if (-not([string]::IsNullOrEmpty($ModulesToUninstall))) {
        Write-Host -Object "[$($MyInvocation.MyCommand)] The following modules will be uninstalled:`r`n$($ModulesToUninstall | Format-Table | Out-String)"
        foreach ($CurrentModuleToUninstall in $ModulesToUninstall) {
            Write-Host -Object "[$($MyInvocation.MyCommand)] Uninstalling the '$($CurrentModuleToUninstall.Name)' - version '$($CurrentModuleToUninstall.Version)' module"
            Uninstall-Module -Name $($CurrentModuleToUninstall.Name) -RequiredVersion $($CurrentModuleToUninstall.Version) -AllowPrerelease -Force:$Force -ErrorAction Ignore
        }
    }
    else {
        Write-Verbose -Message "[$($MyInvocation.MyCommand)] Nothing to uninstall for the '$($Module.Name)' PowerShell module" -Verbose
    }
}

$ExportedFunctions = [scriptblock]::Create(@"
    Function Get-LatestModuleVersion { ${Function:Get-LatestModuleVersion} }          
    Function Uninstall-OldModule { ${Function:Uninstall-OldModule} }
"@)
#endregion

#region Main Code
<#
#Picking up 10 random installed modules for testing
$Modules = Get-InstalledModule | Get-Random -Count 10 | Sort-Object -Property Name
$RandomInstalledModules = $Modules | ForEach-Object -Process {
    Write-Host -Object "Processing '$($_.Name)' PowerShell Module"
    #Picking up 1 random version module to install (except the highest one)
    Find-Module -Name $_.Name -AllVersions | Sort-Object -Property Version -Descending | Select-Object -Skip 1 | Get-Random
}
Write-Host -Object "Installing PowerShell Modules:`r`n$($RandomInstalledModules | Out-String)"
$RandomInstalledModules | Install-Module -PassThru -AllowClobber -SkipPublisherCheck -Force #-Verbose 
#$RandomInstalledModules | Uninstall-Module
#>

#Unloading all loaded modules
Get-Module | Remove-Module -Force

#region Evaluating Updates To Do
Write-Verbose -Message "Getting installed modules"
$LocalInstalledModulesBeforeUpdate = Get-InstalledModule
Write-Verbose -Message "Finding latest installed module versions on PowerShell Gallery (or any registered repository)"
$Jobs = foreach ($CurrentLocalInstalledModulesBeforeUpdate in $LocalInstalledModulesBeforeUpdate) {
    Write-Verbose -Message "Processing '$($CurrentLocalInstalledModulesBeforeUpdate.Name)' PowerShell Module" -Verbose
    Start-ThreadJob -ScriptBlock { Get-LatestModuleVersion -Module $using:CurrentLocalInstalledModulesBeforeUpdate } -InitializationScript $ExportedFunctions #-StreamingHost $Host
}
$RepositoryLatestModules = $Jobs | Receive-Job -Wait -AutoRemoveJob

#$RepositoryLatestModules = $LocalInstalledModulesBeforeUpdate | Find-Module -ErrorAction Ignore
Write-Verbose -Message "Comparing version Local vs. PowerShell Gallery (or any registered repository)"
#$RepositoryModuleUpdates = Compare-Object -ReferenceObject $LocalInstalledModulesBeforeUpdate -DifferenceObject $RepositoryLatestModules -Property Version, Name -PassThru | Where-Object -FilterScript { $_.SideIndicator -eq "=>"} 
#$RepositoryModuleUpdatesHT = $RepositoryModuleUpdates | Group-Object -Property Name -AsHashTable -AsString
$RepositoryModuleUpdatesHT = Compare-Object -ReferenceObject $LocalInstalledModulesBeforeUpdate -DifferenceObject $RepositoryLatestModules -Property Version, Name -PassThru | Where-Object -FilterScript { $_.SideIndicator -eq "=>"} | Group-Object -Property Name -AsHashTable -AsString
#endregion

#region Updating
if ($null -ne $RepositoryModuleUpdatesHT) {
    $LocalModulesToUpdate = $LocalInstalledModulesBeforeUpdate | Where-Object -FilterScript { $_.Name -in $RepositoryModuleUpdatesHT.Keys }
    $LocalModulesToUpdateHT = $LocalModulesToUpdate | Group-Object -Property Name -AsHashTable -AsString
    $ModulesToUpdate = $LocalModulesToUpdate | Select-Object -Property Name, @{Name="From (Local)"; Expression= {$_.Version}}, @{Name="To (Repository)"; Expression= {$RepositoryModuleUpdatesHT[$_.Name].Version}}, @{Name="PublishedDate (Local)"; Expression= {$LocalModulesToUpdateHT[$_.Name].PublishedDate}}, @{Name="PublishedDate (Repository)"; Expression= {$RepositoryModuleUpdatesHT[$_.Name].PublishedDate}}

    Write-Host -Object "Updating the modules:`r`n$($ModulesToUpdate | Format-Table | Out-String)"
    $UpdatedModules = Update-Module -Name $RepositoryModuleUpdatesHT.Keys -Force -PassThru
    Write-Host -Object "Updated Modules: $($UpdatedModules | Select-Object -Property Name, Version, PublishedDate | Sort-Object -Property Name | Out-String)"
    $Delta = Compare-Object -ReferenceObject ($ModulesToUpdate | Select-Object -Property Name, @{Name="Version"; Expression= {$_.'To (Repository)'}}) -DifferenceObject $UpdatedModules -Property Name, Version -IncludeEqual -PassThru
    $AdditionalUpdatedModules = $Delta | Where-Object -FilterScript { $_.SideIndicator -eq "=>" }
    if ($AdditionalUpdatedModules) {
        Write-Host -Object "Additional Updated Modules: $($AdditionalUpdatedModules | Select-Object -Property Name, Version, PublishedDate | Sort-Object -Property Name | Out-String)"
    }
    $NotUpdatedModules = $Delta | Where-Object -FilterScript { $_.SideIndicator -eq "<=" }
    if ($NotUpdatedModules) {
        Write-Warning -Message "Not Updated Modules: $($NotUpdatedModules | Select-Object -Property Name, Version | Sort-Object -Property Name | Out-String)"
    }
}
else {
    Write-Host -Object "No module updates available"
}
#endregion

#region Cleanup
$LocalInstalledModulesAfterUpdate = Get-InstalledModule
#$LocalInstalledModulesAfterUpdate = $RandomInstalledModules
$null = Start-ThreadJob -ScriptBlock { $null} -ThrottleLimit $([math]::Min(25, $LocalInstalledModulesAfterUpdate.Count))
$Jobs = foreach ($CurrentLocalInstalledModulesAfterUpdate in $LocalInstalledModulesAfterUpdate) {
    Write-Verbose -Message "Processing '$($CurrentLocalInstalledModulesAfterUpdate.Name)' PowerShell module (AsJob)" -Verbose
    #Uninstall-OldModule -Module $CurrentLocalInstalledModulesAfterUpdate -Verbose
    Start-ThreadJob -ScriptBlock { Uninstall-OldModule -Module $using:CurrentLocalInstalledModulesAfterUpdate } -InitializationScript $ExportedFunctions -StreamingHost $Host
}
$Jobs | Receive-Job -Wait -AutoRemoveJob

#endregion
#endregion