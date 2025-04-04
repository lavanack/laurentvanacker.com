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

#region function definition
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

    $SourceSubscription = (Get-AzContext).Subscription
    Write-Verbose -Message "Currently Selected Subscription: '$($SourceSubscription.Name)'"
    $AzureCredentials = cmdkey /list | Select-String -Pattern "=(?<termsrv>TERMSRV/)?(?<dnsname>(?<vmname>.*)\.(?<location>.*)\.cloudapp\.azure\.com)" -AllMatches
    $VMs = foreach ($CurrentSubscription in Get-AzSubscription) {
        $null = Select-AzSubscription -SubscriptionObject $CurrentSubscription
        Write-Verbose -Message "Switching to '$($CurrentSubscription.Name)' Subscription"
        Get-AzVM | Where-Object -FilterScript { $_.Name -in $(($AzureCredentials.Matches.Groups | Where-Object -FilterScript { $_.Name -eq "vmname" }).Value) } | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value $((Get-AzContext).Subscription.Name) -PassThru
    }
    $null = Select-AzSubscription -SubscriptionObject $SourceSubscription
    Write-Verbose -Message "Switching Back to '$($SourceSubscription.Name)' Subscription"
    
    $VMHT = $VMs | Group-Object -Property Name -AsHashTable -AsString

    if ($AzureCredentials.Matches) {
        $Index = 0
        $AzureCredentials.Matches | ForEach-Object -Process { 
            $TERMSRV = $($_.Groups['termsrv'].Value)
            $DNSName = $_.Groups['dnsname'].Value
            $VMName = $_.Groups['vmname'].Value
            $Location = $_.Groups['location'].Value
            $AzVM = $VMHT[$VMName]
            $Index++
            $PercentComplete = $Index / $AzureCredentials.Matches.Count * 100
            Write-Progress -Activity "[$($Index)/$($AzureCredentials.Matches.Count)] Cleaning VM credentials ..." -CurrentOperation "Processing '$VMName' Credentials ..." -Status $('{0:N0}%' -f $PercentComplete) -PercentComplete $PercentComplete
            if (($AzVM) -and ($AzVM.Location -eq $Location)) {
                Write-Verbose -Message "$VMName ($DNSName) Azure VM exists in the '$($AzVM.SubscriptionName)' Subscription. The related credentials will stay into the Windows Credential Manager"
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
#endregion 

#region Main Code
Clear-Host
$Error.Clear()
$SourceSubscription = (Get-AzContext).Subscription

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

#Get-ChildItem -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -Include *.cloudapp.azure.com -Recurse | Remove-Item -Force -WhatIf
Remove-AzVMStaleCredential -Verbose -Confirm:$false #-WhatIf
#endregion 