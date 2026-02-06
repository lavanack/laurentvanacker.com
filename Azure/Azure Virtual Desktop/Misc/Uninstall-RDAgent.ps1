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
Param(
)

#region Function Definitions
function Uninstall-RDAgent {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    $IsRemoved = $false
    $RDSApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Services*"}
    if ($RDSApp) {
        Write-Verbose -Message "Uninstalling 'Remote Desktop Services' applications"
        $null = $RDSApp.Uninstall()
        $RDSApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Services*"}
        if (-not($RDSApp)) {
            Write-Host -Object "✅ 'Remote Desktop Services' applications were successfully removed !" -ForegroundColor Green
            $IsRemoved = $true
        }
        else {
            Write-Host -Object "❌ 'Remote Desktop Services' applications  were NOT successfully removed !" -ForegroundColor Red
        }
    }
    else {
        Write-Warning -Message "No 'Remote Desktop Services' applications found"
    }

    $RDAApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Agent*"}
    if ($RDAApp) {
        Write-Verbose -Message "Uninstalling 'Remote Desktop Agent' applications"
        $null = $RDAApp.Uninstall()
        $RDAApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Services*"}
        if (-not($RDAApp)) {
            Write-Host -Object "✅ 'Remote Desktop Agent' applications were successfully removed !" -ForegroundColor Green
            $IsRemoved = $true
        }
        else {
            Write-Host -Object "❌ 'Remote Desktop Agent' applications were NOT successfully removed !" -ForegroundColor Red
        }
    }
    else {
        Write-Warning -Message "No 'Remote Desktop Agent' applications found"
    }

    if ($IsRemoved) {
        Write-Verbose -Message "Rebooting ..."
        Restart-Computer -Force
    }
}
#endregion

#region Main Code
Clear-Host
$Error.Clear()

# Set working directory to script location for relative path operations
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

Uninstall-RDAgent -Verbose
#endregion
