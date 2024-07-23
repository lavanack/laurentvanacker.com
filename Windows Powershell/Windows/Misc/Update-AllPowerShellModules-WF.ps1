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

#region Workflow definitions
workflow WF-Get-LatestModuleVersion {
    [CmdletBinding()]
    param (
        [object[]] $Module
    )
    ForEach -ThrottleLimit 10 -Parallel ($CurrentModule in $Module)
    {
        Write-Verbose "[$($MyInvocation.MyCommand)] Processing '$($CurrentModule.Name)' PowerShell module"
        $FoundUpdates = Find-Module -Name $CurrentModule.Name -ErrorAction Ignore
        Write-Verbose -Message "[$($MyInvocation.MyCommand)] Found PowerShell Module Updates:`r`n$($FoundUpdates | Format-Table | Out-String)"
        $FoundUpdates
    }
}


workflow WF-Uninstall-OldModule {
    [CmdletBinding()]
    param (
        [object[]] $Module,
        [switch] $Force
    )
    ForEach -ThrottleLimit 10 -Parallel ($CurrentModule in $Module)
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand)] Processing '$($CurrentModule.Name)' PowerShell module"
        #Removing all versions except the highest one (normally the lastest from the online repository). We have to parse the version to get the correct sorting. Without this "1.11.0" -gt "1.2.0" returns $false
        $ModulesToUninstall = Get-InstalledModule -Name $CurrentModule.Name -AllVersions | Select-Object -Property *, @{Name="ParsedVersion"; Expression={[version]::Parse($_.Version)}} | Sort-Object -Property ParsedVersion -Descending | Select-Object -Skip 1
        if (-not([string]::IsNullOrEmpty($ModulesToUninstall))) {
            <#
            InlineScript { 
                Write-Host -Object "[$($MyInvocation.MyCommand)] Uninstalling the modules:`r`n$($using:ModulesToUninstall | Format-Table | Out-String)" 
                Write-Host -Object "[$($MyInvocation.MyCommand)] Uninstall-Module -Name $($using:ModulesToUninstall.Name) -RequiredVersion $($using:ModulesToUninstall.Version) -ErrorAction Ignore" 
            }
            #>
            foreach ($CurrentModuleToUninstall in $ModulesToUninstall) {
                <#
                InlineScript { 
                    Write-Host -Object "[$($MyInvocation.MyCommand)] Uninstalling the '$($using:CurrentModuleToUninstall.Name)' - version '$($using:CurrentModuleToUninstall.Version)' module"
                }
                #>
                Uninstall-Module -Name $($CurrentModuleToUninstall.Name) -RequiredVersion $($CurrentModuleToUninstall.Version) -AllowPrerelease -Force:$Force -ErrorAction Ignore
            }
        }
        else {
            Write-Verbose -Message "[$($MyInvocation.MyCommand)] Nothing to uninstall for the '$($CurrentModule.Name)' PowerShell module"
        }
    }
}

#endregion

#region Main Code
#Picking up 10 random installed modules for testing
$Modules = Get-InstalledModule | Get-Random -Count 10 | Sort-Object -Property Name
$RandomInstalledModules = $Modules | ForEach-Object -Process {
    Write-Host -Object "Processing '$($_.Name)' PowerShell Module"
    #Picking up 1 random version module to install (except the highest one)
    Find-Module -Name $_.Name -AllVersions | Sort-Object -Property Version -Descending | Select-Object -Skip 1 | Get-Random
}
Write-Host -Object "Installing PowerShell Modules:`r`n$($RandomInstalledModules | Out-String)"
$RandomInstalledModules | Install-Module -PassThru -AllowClobber -SkipPublisherCheck -Force #-Verbose 
<#
#$RandomInstalledModules | Uninstall-Module
#>

#Unloading all loaded modules
Get-Module | Remove-Module -Force

#region Evaluating Updates To Do
Write-Verbose -Message "Getting installed modules"
$LocalInstalledModulesBeforeUpdate = Get-InstalledModule
Write-Verbose -Message "Finding latest installed module versions on PowerShell Gallery (or any registered repository)"
$RepositoryLatestModules = WF-Get-LatestModuleVersion -Module $LocalInstalledModulesBeforeUpdate #-Verbose
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
WF-Uninstall-OldModule -Module $LocalInstalledModulesAfterUpdate #-Verbose
#endregion
#endregion