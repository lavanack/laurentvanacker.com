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
#Requires -Version 5.1 -Modules Az.Automation, Az.Resources, Az.Accounts

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
    [Parameter(Mandatory = $true)]
    [string] $AutomationAccountName,
    [Parameter(Mandatory = $true)]
    [string] $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\.webhook\.\w+\.azure-automation\.net/webhooks\?token=.*$')]
    [string] $WebhookURI,
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^TRN\d{4}$")]
    [string]$VNET = "TRN{0:D4}" -f $(Get-Random -Minimum 1 -Maximum 1000),
    [ValidateScript({$_ -in 1..9 })]
    [Parameter(Mandatory = $false)]
    [uint16]$VMNumb = $(Get-Random -Minimum 1 -Maximum 10)
)

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$HostPoolData =  [PSCustomObject]@{VNET = $VNET; VMNumb=$VMNumb}

$Body = $HostPoolData | ConvertTo-Json -Compress
Write-Verbose "Payload: $Body"

try {
    $Response = Invoke-WebRequest -Method Post -Uri $WebhookURI -Body $Body -UseBasicParsing -ErrorAction Stop

    if ($Response.StatusCode -eq 202) {
        Write-Host -Object "Webhook test successful! Status Code: $($Response.StatusCode)" -ForegroundColor Green
        $JobIds = ($Response.Content | ConvertFrom-Json).JobIds

        # Monitor job execution
        Write-Host -Object "Monitoring job execution..."
        # 30 minutes timeout
        $timeout = 1800 
        $elapsed = 0
        $Step = 30
        Do {
            Start-Sleep -Seconds $Step
            Write-Host -Object "Sleeping $Step seconds ..."
            $elapsed += $Step
            $JobCompleted  = $true
            foreach ($JobId in $JobIds) {
                try {
                    $Job = Get-AzAutomationJob -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Id $JobId -ErrorAction Stop
                    Write-Host -Object "JobId : '$JobId' - Status $($Job.Status)"
                    if ($Job.Status -notin @("Completed", "Failed", "Stopped", "Suspended")) {
                        $JobCompleted  = $false
                        #break
                    }
                }
                catch {
                    Write-Warning "Failed to retrieve job status: $($_.Exception.Message)"
                    break
                }
            }
        } While (($elapsed -lt $timeout) -and (-not($JobCompleted)))

        # Get job output
        try {
            $JobOutput = foreach ($JobId in $JobIds) {
                Get-AzAutomationJobOutput -AutomationAccountName $AutomationAccountName -Id $JobId -ResourceGroupName $ResourceGroupName -Stream Any -ErrorAction Stop
            }
            $Summary = $JobOutput.Summary -join "`r`n"
            $Summary 
        }
        catch {
            Write-Warning "Failed to retrieve job output: $($_.Exception.Message)"
        }

        if (-not($JobCompleted)) {
            Write-Warning "Job execution timeout reached ($timeout seconds)"
        }
    }
    else {
        Write-Warning "Webhook test failed with status code: $($Response.StatusCode)"
    }
}
catch {
        Write-Error "Testing failed: $($_.Exception.Message)"
}
#endregion
