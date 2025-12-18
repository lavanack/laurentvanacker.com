<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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

##requires -Module Az.Accounts, Az.Security

Clear-Host

#region Function Definition(s)
function Get-AzVMJITAccess {
    [CmdletBinding(PositionalBinding = $false)]
    param
    (
    )

    $Requests = (Get-AzJitNetworkAccessPolicy).Requests | Where-Object -FilterScript {$_.VirtualMachines.Ports.EndTimeUtc -gt [datetime]::UtcNow }

    foreach ($CurrentRequest in $Requests) {
       $EndTimeUtc = $CurrentRequest.VirtualMachines.Ports.EndTimeUtc
       if ($EndTimeUtc -ge $UtcNow) {
           $Requestor = $CurrentRequest.Requestor
           $StartTimeUtc = $CurrentRequest.StartTimeUtc
           $VirtualMachines = $CurrentRequest.VirtualMachines
           $Ports = $CurrentRequest.VirtualMachines.Ports.Number

           [PSCustomObject] @{
                Requestor = $Requestor
                StartTimeUtc = $StartTimeUtc
                StartTimeLocalTime = $StartTimeUtc.ToLocalTime()
                VirtualMachines = $VirtualMachines
                Ports = $Ports
                EndTimeUtc = $EndTimeUtc
                EndTimeLocalTime = $EndTimeUtc.ToLocalTime()
           }
       }
    }
}
#endregion

#region Main code
Clear-Host
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent

# Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Connect-AzAccount
}


$AzVMJITAccess = Get-AzVMJITAccess -Verbose | Format-List -Property * -Force 
$AzVMJITAccess | Sort-Object -Property EndTimeUtc
#endregion