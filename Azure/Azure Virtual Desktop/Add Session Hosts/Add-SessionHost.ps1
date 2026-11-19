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
#Requires -Version 5.1 -Modules Az.Accounts, Az.Compute, Az.DesktopVirtualization, Microsoft.PowerShell.ThreadJob

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
)

#region Function Definitions
function Remove-RemoteDesktopAgentTools {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        $ScriptString = @'
$apps = @(
    "Remote Desktop Services Infrastructure Agent",
    "Remote Desktop Agent Boot Loader"
)

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($app in $apps) {
    $installed = Get-ItemProperty -Path $registryPaths | Where-Object { $_.DisplayName -like "*$app*" }
    foreach ($item in $installed) {
        Write-Output "Uninstalling $($item.DisplayName)"
        $productCode = $item.PSChildName
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru
        Write-Output "Exit code: $($process.ExitCode)"
        if ($process.ExitCode -notin @(0, 3010)) {
            throw "Uninstallation failed: $($item.DisplayName)"
        }
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "IsRegistered" -Value 0 -Force
'@
        $VMs = @()
        $Jobs = @()
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVM: `r`n$($CurrentVM | Out-String)"
            #region Uninstalling AVD Tools
            $Jobs += Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString $ScriptString -Verbose -AsJob
            $VMs += $VM
            #endregion
        }
    }
    end {
        $Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Results: `r`n$($Results | Out-String)"
        $Jobs = foreach ($CurrentVM in $VMs) {
            $CurrentVM | Restart-AzVM -AsJob
        }
        $Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Results: `r`n$($Results | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}

function Add-SessionHost {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.PowerShell.Cmdlets.DesktopVirtualization.Models.HostPool]$HostPool,

        [switch] $EntraIDJoin
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$HostPool: `r`n$($HostPool | Out-String)"

        $RegistrationInfoExpirationTime = (Get-Date).ToUniversalTime().AddDays(1)
        $RegistrationInfoToken = New-AzWvdRegistrationInfo -ResourceGroupName $HostPool.ResourceGroupName -HostPoolName $HostPool.Name -ExpirationTime $RegistrationInfoExpirationTime -ErrorAction SilentlyContinue
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$RegistrationInfoToken: `r`n$($RegistrationInfoToken | Out-String)"

        #URI updated on : 07/22/2026
        #To Get the latest version of the zip by looking in the Resource Group Deployement
        #$avdModuleLocation = Get-AzWvdHostPool | ForEach-Object -Process { (Get-AzWvdSessionHost -ResourceGroupName $_.ResourceGroupName -HostPoolName $_.Name) | ForEach-Object -Process { $AzResource = Get-AzResource -ResourceId $_.ResourceId; ((Get-AzVMExtension -ResourceGroupName $AzResource.ResourceGroupName -VMName $AzResource.Name -ErrorAction Ignore | Where-Object -FilterScript { $_.ExtensionType -eq "DSC"}).PublicSettings | ConvertFrom-Json -ErrorAction Ignore).ModulesUrl } }
        $avdModuleLocation = "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.03448.1358.zip"
        $avdExtensionName = "DSC"
        $avdExtensionPublisher = "Microsoft.Powershell"
        $avdExtensionVersion = "2.73"
        $avdExtensionSetting = @{
            modulesUrl            = $avdModuleLocation
            ConfigurationFunction = "Configuration.ps1\AddSessionHost"
            Properties            = @{
                hostPoolName             = $HostPool.Name
                RegistrationInfoToken    = $RegistrationInfoToken.Token
                aadJoin                  = $EntraIDJoin.IsPresent
                UseAgentDownloadEndpoint = $true
            }
        }
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$avdExtensionSetting: `r`n$($avdExtensionSetting | Out-String)"
        $Results = @()
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVM: `r`n$($CurrentVM | Out-String)"

            $Parameters = @{
                VMName            = $CurrentVM.Name 
                ResourceGroupName = $CurrentVM.ResourceGroupName 
                Name              = $avdExtensionName
            }

            if (Get-AzVMExtension @Parameters -ErrorAction Ignore) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing '$avdExtensionName' extension from the '$($CurrentVM.Name)'"
                $Result = Remove-AzVMExtension @Parameters -Force
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($Result | Out-String)"
                $ScriptString = @'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "IsRegistered" -Value 0 -Force
Restart-Service RDAgentBootLoader
'@
                $Result = Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString $ScriptString -Verbose
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($Result | Out-String)"
            }

            if ($EntraIDJoin.IsPresent) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Registering '$($CurrentVM.Name)' VM to EntraID"
                try {
                    $Result = Set-AzVMExtension -Publisher Microsoft.Azure.ActiveDirectory -Name AADLoginForWindows -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -ExtensionType AADLoginForWindows -TypeHandlerVersion 2.0
                    $Succeeded = $Result.IsSuccessStatusCode
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($Result | Out-String)"
                }
                catch {
                    Write-Warning -Message "Unable to register the '$($CurrentVM.Name)' VM to EntraID"
                    Write-Warning -Message "Exception Message: $($_.Exception.Message)"
                    $Succeeded = $false
                }
            }
            else {
                $Succeeded = $true
            }
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Succeeded: $Succeeded"
            
            if ($Succeeded) {
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Adding '$($CurrentVM.Name)' VM to '$($HostPool.Name)' Host Pool"
                try {
                    $Result = Set-AzVMExtension @Parameters -Location $CurrentVM.Location -TypeHandlerVersion $avdExtensionVersion -Publisher $avdExtensionPublisher -ExtensionType $avdExtensionName -Settings $avdExtensionSetting -ErrorAction Stop
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Result: `r`n$($Result | Out-String)"
                    $Succeeded = $Result.IsSuccessStatusCode
                }
                catch {
                    Write-Warning -Message "Exception Message: $($_.Exception.Message)"
                    $Succeeded = $false
                }
                Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Succeeded: $Succeeded"

                if ($Succeeded) {
                    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] The '$($CurrentVM.Name)' VM was added to the '$($HostPool.Name)' Host Pool"
                }
                else {
                    Write-Warning -Message "Unable to add the '$($CurrentVM.Name)' VM to the '$($HostPool.Name)' Host Pool"
                }
                $Results += [PSCustomObject] @{VM = $CurrentVM.Id; Succeeded = $Succeeded}
            }
        }
    }
    end {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Results: `r`n$($Results | Out-String)"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $Results
    }
}

function Set-WindowsOptimization {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )

    begin {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"
        $ScriptString = @'
$Uri = "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/WindowsOptimization.ps1"
$OutFile = Join-Path -Path $env:Temp -ChildPath $(Split-Path -Path $Uri -Leaf)
Invoke-RestMethod -Uri $Uri -OutFile $OutFile
& $OutFile -Optimizations All
$null = Remove-Item -Path $OutFile -Force -ErrorAction Ignore
'@
        $VMs = @()
        $Jobs = @()
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$CurrentVM: `r`n$($CurrentVM | Out-String)"
            #region AVD Windows Optimization
            $Jobs += Invoke-AzVMRunCommand -ResourceGroupName $CurrentVM.ResourceGroupName -VMName $CurrentVM.Name -CommandId 'RunPowerShellScript' -ScriptString $ScriptString -Verbose -AsJob
            $VMs += $VM
            #endregion
        }
    }
    end {
        $Results = $Jobs | Receive-Job -Wait -AutoRemoveJob
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$Results: `r`n$($Results | Out-String)"
        $Jobs = foreach ($CurrentVM in $VMs) {
            $CurrentVM | Restart-AzVM -AsJob
        }
        $Jobs | Receive-Job -Wait -AutoRemoveJob
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
    }
}
#endregion

#region Main Code
#region Script Initialization
Clear-Host

# Clear any existing errors for clean execution
$Error.Clear()

# Set script location context
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

Write-Verbose "Script executing from: $CurrentDir"
Write-Verbose "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Verbose "Execution Policy: $(Get-ExecutionPolicy)"
#endregion

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}
#endregion

$EmptyDemoHostPoolResourceGroups = Get-AzResourceGroup -ResourceGroupName "rg-avdhp-np-ei-empty-demo-*"
Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$EmptyDemoHostPoolResourceGroups: `r`n$($EmptyDemoHostPoolResourceGroups | Out-String)"
$HostPool = foreach ($EmptyDemoHostPoolResourceGroup in $EmptyDemoHostPoolResourceGroups) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$EmptyDemoHostPoolResourceGroup: `r`n$($EmptyDemoHostPoolResourceGroup | Out-String)"
    $EmptyDemoHostPools = Get-AzWvdHostPool -ResourceGroupName $EmptyDemoHostPoolResourceGroup.ResourceGroupName
    foreach ($EmptyDemoHostPool in $EmptyDemoHostPools) {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$EmptyDemoHostPool: `r`n$($EmptyDemoHostPool | Out-String)"
        $ExistingSessionHostId = (Get-AzWvdSessionHost -ResourceGroupName $EmptyDemoHostPoolResourceGroup.ResourceGroupName -HostPoolName $EmptyDemoHostPool.Name).ResourceId
        if ([string]::IsNullOrEmpty($ExistingSessionHostId)) {
            $EmptyDemoHostPool
            break
        }
    }
}

$VMResourceGroupName= (Get-AzResourceGroup -ResourceGroupName "rg-vm-rnd-*" | Get-Random).ResourceGroupName
$VMs = Get-AzVM -ResourceGroupName $VMResourceGroupName

<#
#region Sequential Processing
$Results = $VMs | Add-SessionHost -HostPool $HostPool -EntraIDJoin -Verbose
$Results
#endregion
#>

#region Parallel Processing
$Jobs = foreach ($VM in $VMs) {
    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] `$VM: $($VM.Id)"         
    $PercentComplete = 1/$VMs.Count
    Write-Progress -Id 0 -Activity "[$($_)/$($VMs.Count)] Adding VMs ..." -CurrentOperation "Adding '$($VM.Name)' VM ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete

    $Params = @{
        VM          = $VM
        HostPool    = $HostPool
        EntraIDJoin = $true
        Verbose     = $true
    }

    $ExportedFunctions = [scriptblock]::Create(@"
        Function Add-SessionHost { ${Function:Add-SessionHost} }
"@)

    Start-ThreadJob -ScriptBlock { param() Add-SessionHost @using:Params } -InitializationScript $ExportedFunctions -StreamingHost $Host
}
Write-Progress -Id 0 -Activity "Completed !" -Completed

# Wait for provisioning jobs and discard their output; VM start requests remain asynchronous.
Write-Host -Object "Waiting for the addition of the virtual machines to complete ..." 
$null = $Jobs | Receive-Job -Wait -AutoRemoveJob
Write-Host -Object "Virtual machines added successfully!" -ForegroundColor Green
#endregion

break

$Results = $VM | Set-WindowsOptimization -Verbose
$Results
#endregion