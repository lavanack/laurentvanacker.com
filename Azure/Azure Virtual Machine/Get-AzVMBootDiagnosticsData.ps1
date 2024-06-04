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
attorneys' fees, th
at arise or result from the use or distribution
of the Sample Code.
#>

#requires -Version 5 -Modules Az.Accounts, Az.Compute

#region Function definitions
function Get-AzVMBootDiagnosticsDataSetting {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )
    begin {}
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "Processing '$($CurrentVM.Name)' Azure VM"
            $CurrentVM.DiagnosticsProfile.BootDiagnostics | Select-Object -Property @{Name="VMName"; Expression={$CurrentVM.Name}}, *
            if (-not($CurrentVM.DiagnosticsProfile.BootDiagnostics)) {
                Write-Verbose -Message "Boot Diagnostics is NOT enabled for the '$($CurrentVM.Name)' Azure VM"
            }
        }
    }
    end {}
}

function Get-AzVMBootDiagnosticsDataItem {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM,
        [string] $LocalPath = $(Join-Path -Path $env:TEMP -ChildPath "BootDiagnostics"),
        [switch] $Open
    )
    begin {
        $null = New-Item -Path $LocalPath -ItemType Directory -Force
        Write-Verbose "`$LocalPath: $LocalPath"
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "Processing '$($CurrentVM.Name)' Azure VM"
            if (-not($CurrentVM.DiagnosticsProfile.BootDiagnostics)) {
                Write-Verbose -Message "Boot Diagnostics is NOT enabled for the '$($CurrentVM.Name)' Azure VM"
            }
            else {
                $CurrentVM | Get-AzVMBootDiagnosticsData -Windows -LocalPath $LocalPath
            }
        }
    }
    end {
        if ($Open) {
            start $LocalPath
        }
    }
}

function Get-AzVMBootDiagnosticsDataBlobUri {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachineList[]] $VM
    )

    begin {
        #region Azure Context
        # Log in first with Connect-AzAccount if not using Cloud Shell

        $azContext = Get-AzContext
        $SubcriptionID = $azContext.Subscription.Id
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
        $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = 'Bearer ' + $token.AccessToken
        }
        #endregion
    }
    process {
        foreach ($CurrentVM in $VM) {
            Write-Verbose -Message "Processing '$($CurrentVM.Name)' Azure VM"
            if (-not($CurrentVM.DiagnosticsProfile.BootDiagnostics)) {
                    Write-Verbose -Message "Boot Diagnostics is NOT enabled for the '$($CurrentVM.Name)' Azure VM"
                    continue
                }
            else {
                    $URI = "https://management.azure.com/subscriptions/$SubcriptionID/resourceGroups/$($CurrentVM.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($CurrentVM.Name)/retrieveBootDiagnosticsData?api-version=2024-03-01"
                    Write-Verbose -Message "`$URI: $URI"
                    try {
                        # Invoke the REST API
                        $Response = Invoke-RestMethod -Method POST -Headers $authHeader -ContentType "application/json" -Uri $URI -ErrorVariable ResponseError
                    }
                    catch [System.Net.WebException] {   
                        # Dig into the exception to get the Response details.
                        # Note that value__ is not a typo.
                        Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__ )"
                        Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
                        $respStream = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($respStream)
                        $Response = $reader.ReadToEnd() | ConvertFrom-Json
                        if (-not([string]::IsNullOrEmpty($Response.message))) {
                            Write-Warning -Message $Response.message
                        }
                    }
                    finally {
                    }
                    $Response | Select-Object -Property @{Name="VMName"; Expression = {$CurrentVM.Name} }, *
                }  
        }
    }
    end {
    }
}
#endregion

Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
$AzVMBootDiagnosticsDataBlobUriCSVFile = Join-Path -Path $CurrentDir -ChildPath $("AzVMBootDiagnosticsDataBlobUri_{0}.csv" -f (Get-Date -Format 'yyyyMMddHHmmss'))
$LocalPath = "C:\Temp\AzVMBootDiagnosticsDataItem"

Remove-Item -Path (Join-Path -Path $LocalPath -ChildPath "*") -Force -Recurse -ErrorAction Ignore

Get-AzVM | Get-AzVMBootDiagnosticsDataSetting -Verbose
$AzVMBootDiagnosticsDataBlobUri = Get-AzVM | Get-AzVMBootDiagnosticsDataBlobUri -Verbose 
$AzVMBootDiagnosticsDataBlobUri | Format-List -Property * -Force
$AzVMBootDiagnosticsDataBlobUri | Export-Csv -Path $AzVMBootDiagnosticsDataBlobUriCSVFile -NoTypeInformation
& $AzVMBootDiagnosticsDataBlobUriCSVFile
Get-AzVM | Get-AzVMBootDiagnosticsDataItem -LocalPath $LocalPath -Open -Verbose