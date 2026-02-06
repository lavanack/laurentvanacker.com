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
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$RegistrationInfoToken,
    [Switch]$Restart
)

#region Function Definitions
function Repair-RDAgent {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$RegistrationInfoToken,
        [Switch]$Restart
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

    <#
    if ($IsRemoved) {
        Write-Verbose -Message "Rebooting ..."
        Restart-Computer -Force
    }
    #>

    $null = Get-ChildItem -Path $(Join-Path -Path $env:ProgramFiles -ChildPath "Microsoft RDInfra") -Filter *.msi | Remove-Item -Force

    $WVDAgentInstaller = Join-Path -Path $env:TEMP -ChildPath "WVD-Agent.msi"
    $WVDBootLoaderInstaller = Join-Path -Path $env:TEMP -ChildPath "WVD-BootLoader.msi"

    $Files = @(
        @{URL = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv"; Path = $WVDAgentInstaller}
        @{URL = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH"; Path = $WVDBootLoaderInstaller}
    )

<#
    #Alternate URIs
    $Files = @(
        @{URL = "https://go.microsoft.com/fwlink/?linkid=2310011"; Path = $WVDAgentInstaller}
        @{URL = "https://go.microsoft.com/fwlink/?linkid=2311028"; Path = $WVDBootLoaderInstaller}
    )
#>


    Start-BitsTransfer -Source $Files.URL -Destination $Files.Path

    Write-Verbose -Message "Installing '$WVDAgentInstaller' ..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $WVDAgentInstaller", "/quiet", "REGISTRATIONTOKEN=$RegistrationInfoToken", "/l* $env:Temp\AgentInstall.txt" -Wait
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30

    Write-Verbose -Message "Installing '$WVDBootLoaderInstaller' ..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $WVDBootLoaderInstaller", "/quiet", "/l* $env:Temp\AgentBootLoaderInstall.txt" -Wait
    Write-Verbose -Message "Sleeping 30 seconds ..."
    Start-Sleep -Seconds 30

    $RDSApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Services Infrastructure Agent*"}
    if ($RDSApp) {
        Write-Host -Object "✅ $($RDSApp.Name) was successfully installed !" -ForegroundColor Green
    }
    else {
        Write-Host -Object "❌ $($RDSApp.Name) was NOT installed !" -ForegroundColor Red
    }

    $RDAApp = Get-WmiObject -Class Win32_Product | Where-Object -FilterScript {$_.Name -like "*Remote Desktop Agent Boot Loader*"}
    if ($RDAApp) {
        Write-Host -Object "✅ $($RDAApp.Name) was successfully installed !" -ForegroundColor Green
    }
    else {
        Write-Host -Object "❌ $($RDAApp.Name) was NOT installed !" -ForegroundColor Red
    }

    Write-Verbose -Message "Removing '$WVDAgentInstaller', '$WVDBootLoaderInstaller' files ..."
    $null = Remove-Item -Path $WVDAgentInstaller, $WVDBootLoaderInstaller -Force -ErrorAction Ignore

    if ($Restart) {
        Write-Verbose -Message "Rebooting ..."
        $null = Restart-Computer -Force
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

Repair-RDAgent -RegistrationInfoToken $RegistrationInfoToken -Restart:$Restart.IsPresent -Verbose
#endregion
