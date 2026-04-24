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
#requires -Version 5

[CmdletBinding(PositionalBinding = $false)]
Param(
    [Parameter(Mandatory = $false)]
    [string] $OfficeVersion = "16.0",
    [Parameter(Mandatory = $false)]
    [string] $Lang = "fr-FR"
)

#region Main Code
Clear-Host
$Error.Clear()
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Variable Definitions
$OfficeLanguageConfiguredRegPath = "HKCU:\Software\Contoso"
$OfficeLanguageConfiguredRegName = "OfficeLanguageConfigured"
#endregion

# =========================
# CHECK idempotence
# =========================
if (Get-ItemProperty -Path $OfficeLanguageConfiguredRegPath -Name $OfficeLanguageConfiguredRegName -ErrorAction SilentlyContinue) {
    Write-Output "Office Language Already Configured. Exiting"
    #exit 0
}
else {
    $OfficeLanguageResourcesRegName = "HKCU:\Software\Microsoft\Office\$OfficeVersion\Common\LanguageResources"

    Write-Output "Setting Office Language to '$Lang'"

    # Creating the registry key if needed
    if (-not(Test-Path $OfficeLanguageResourcesRegName)) {
        $null = New-Item -Path $OfficeLanguageResourcesRegName -Force
    }

    # Change la langue d’affichage (UI)
    $Parameters = @{
        Path         = $OfficeLanguageResourcesRegName 
        Value        = $Lang 
        PropertyType = "String" 
        Force        = $true
    }
    $null = New-ItemProperty @Parameters -Name "UILanguageTag"
    $null = New-ItemProperty @Parameters -Name "HelpLanguageTag"

    # Tagging as completed
    $null = New-Item -Path $OfficeLanguageConfiguredRegPath -Force
    $null = New-ItemProperty -Path $OfficeLanguageConfiguredRegPath -Name $OfficeLanguageConfiguredRegName -Value "Done" -PropertyType String -Force

    Write-Output "Office Language Set to '$Lang"
}
#endregion