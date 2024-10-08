﻿<#
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

function Remove-AzVMStaleCredential {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param
    (
    )
    #region Login to your Azure subscription.
    try { 
        $null = Get-AzAccessToken -ErrorAction Stop
    }
    catch {
        Connect-AzAccount
        #Get-AzSubscription | Out-GridView -OutputMode Single -Title "Select your Azure Subscription" | Select-AzSubscription
    }
    #endregion
    Clear-Host
    $AzureCredentials = cmdkey /list | Select-String -Pattern "=(?<termsrv>TERMSRV/)?(?<dnsname>(?<vmname>.*)\.(?<location>.*)\.cloudapp\.azure\.com)" -AllMatches
    if ($AzureCredentials.Matches) {
        $Index = 0
        $AzureCredentials.Matches | ForEach-Object -Process { 
            $TERMSRV = $($_.Groups['termsrv'].Value)
            $DNSName = $_.Groups['dnsname'].Value
            $VMName = $_.Groups['vmname'].Value
            $Location = $_.Groups['location'].Value
            $AzVM = Get-AzVM -Name $VMName 
            $Index++
            $PercentComplete = $Index / $AzureCredentials.Matches.Count * 100
            Write-Progress -Activity "[$($Index)/$($AzureCredentials.Matches.Count)] Cleaning VM credentials ..." -CurrentOperation "Processing '$VMName' Credentials ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete
            if (($AzVM) -and ($AzVM.Location -eq $Location)) {
                Write-Verbose -Message "$VMName ($DNSName) Azure VM exists. The related credentials will stay into the Windows Credential Manager"
            }
            else {
                If ($pscmdlet.ShouldProcess($DNSName, 'Removing Credentials from the Windows Credential Manager')) {
                    Write-Warning -Message "$VMName ($DNSName) Azure VM doesn't exist. The related credentials will be removed from the Windows Credential Manager"
                    Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$TERMSRV$DNSName" -NoNewWindow #-Wait
                    #Certificate: Registry cleaning
                    $HKCUPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers\$DNSName"
                    if (Test-Path -Path $HKCUPath) {
                        Write-Verbose -Message "Removing '$HKCUPath' ..."
                        Remove-Item -Path $HKCUPath -Force
                    }
                }
            }
        }
        Write-Progress -Completed -Activity "Completed"
    }
}

Get-ChildItem -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -Include *.cloudapp.azure.com -Recurse | Remove-Item -Force -WhatIf
Remove-AzVMStaleCredential -Verbose -Confirm:$false #-WhatIf