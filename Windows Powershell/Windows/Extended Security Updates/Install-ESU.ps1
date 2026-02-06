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

[CmdletBinding(PositionalBinding = $false)]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()] 
    [ValidatePattern("\w{5}-\w{5}-\w{5}-\w{5}-\w{5}")] 
    [string]$MAKKey,
    [Parameter(Mandatory = $true)]
    [ValidateSet(1,2,3)] 
    #To replace with the year associated to the MAK Key : 1, 2 or 3
    [int]$Year 
)

#region Function definitions
#Function to write to the log and to the screen
function Write-Log {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string] $Message,

        [ValidateScript({Test-Path -Path $(Split-Path -Path $_ -Parent) -PathType Container})] 
        [Parameter(Mandatory = $false)]
        $LogFile = $(Join-Path -Path $env:Temp -ChildPath "ESU_installation.log"),
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor] $Color = [System.ConsoleColor]::White
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "{0} - {1}" -f $Timestamp, $Message
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host -Object $Message -ForegroundColor $Color
}
 
#Function to install and activate ESU
function Install-ESU {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [ValidatePattern("\w{5}-\w{5}-\w{5}-\w{5}-\w{5}")] 
        [string]$MAKKey,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [string]$ActivationID,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(1,2,3)] 
        #To replace with the year associated to the MAK Key : 1, 2 or 3
        [int]$Year
    )

    $ExitCode = 0
    Write-Log -Message "Installing the MAK ESU Key..."
    $null = cscript.exe /b "$env:windir\system32\slmgr.vbs" /ipk $MAKKey 
 
    Write-Log -Message "Enabling ESU for the Year #$Year ..."
    $null = cscript.exe /b "$env:windir\system32\slmgr.vbs" /ato $ActivationID
 
    #Manual Troubleshoot 
    #$MAKKey = "<YOUR_MAKKEY_HERE>"
    #cscript.exe "$env:windir\system32\slmgr.vbs" /ipk $MAKKey
 
    Write-Log -Message "Checking Setup ..."
    $ActivationStatus = Get-CimInstance -Query "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL"
    $IsSucceeded = $ActivationStatus | Where-Object { $_.Name -like "*ESU*" } | Select-Object Name, LicenseStatus, Description, PartialProductKey
 
    if ($IsSucceeded) {
        Write-Log -Message "✅ ESU Installation succeeded " -Color Green
        $ExitCode = 0
    }
    else {
        Write-Log -Message "❌ Key not found after the Setup" -Color Red
        $ExitCode = 1
    }
    return $ExitCode

}
#endregion

#region Main Code
#region Variables
$ExpectedVersion = "19045"
$ActivationIDs = @{
    1 = "f520e45e-7413-4a34-a497-d2765967d094"
    2 = "1043add5-23b1-4afb-9a0f-64343c8f3f8d"
    3 = "83d49986-add3-41d7-ba33-87c7bfb5c0fb"
}
#endregion
 
Write-Log -Message "=== Start Of The Script ===" -Color Cyan
 
#region Checking Windows Version
$BuildNumber = (Get-ComputerInfo).OsBuildNumber
Write-Log -Message "Version détectée : $BuildNumber"
#endregion

#region Setup
if ($BuildNumber -eq $ExpectedVersion) {
    Write-Log -Message "✅ ESU-Compliant Windows Version" -Color Green
 
    $KBVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    if ($KBVersion -gt 5198) {
 
        # --- Vérification ESU ---
        Write-Log -Message "Checking ESU Activation Status ..."
        $ActivationStatus = Get-CimInstance -Query "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL"
        $IsSucceeded = $ActivationStatus | Where-Object { $_.Name -like "*ESU*" } | Select-Object Name, LicenseStatus, Description, PartialProductKey
        $Condition = "Client-ESU-Year{0}" -f $Year
 
        if ($IsSucceeded) {
            Write-Log -Message "✅ ESU already installed" -Color Green
            # Extraire les numéros
            $IsSucceededYear = [int]([regex]::Match($IsSucceeded.Name, 'Year(\d+)').Groups[1].Value)
            $ConditionYear = [int]([regex]::Match($Condition, 'Year(\d+)').Groups[1].Value)
            if ($ConditionYear -gt $IsSucceededYear) {
                Write-Log -Message "⚠️ The Installed ESU Covers A Shorter Period (Year $IsSucceededYear < $ConditionYear). Action required." -Color Yellow
                Install-ESU -MAKKey $MAKKey -ActivationID $ActivationIDs[$Year] -Year $Year
            }
            elseif ($ConditionYear -eq $IsSucceededYear) {
                Write-Log -Message "✅ Right ESU  (Year $IsSucceededYear)" -Color Green
            }
            else {
                Write-Log -Message "ℹ️ The Installed ESU Covers A Longer Period (Year $IsSucceededYear > $ConditionYear). No Action required." -Color Cyan
            }
        }
        else {
            Write-Log -Message "❌ ESU Not Set, Installation in Progress ..." -Color Cyan
            Install-ESU -MAKKey $MAKKey -ActivationID $ActivationIDs[$Year] -Year $Year
        }
    }
    else {
        Write-Log -Message "❌ Level of Cumulative update required is not reach to install ESU required at least November 2024 (Current : $KBVersion)" -Color Red
    }
}
else {
    Write-Log -Message "❌ Version Windows incompatible ESU (actuelle : $BuildNumber)" -Color Red
}
#endregion

Write-Log -Message "=== End Of The Script ===" -Color Cyan

#endregion