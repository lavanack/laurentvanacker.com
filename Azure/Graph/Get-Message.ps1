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
#requires -Version 5 -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Mail

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$Global:MaximumFunctionCount = 32768
#Connect to the graph API
if ((-not(Get-MgContext) -or ("Mail.Read" -notin $((Get-MgContext).Scopes)))) {
    Connect-MgGraph -Scopes "Mail.Read" -ContextScope Process -NoWelcome
}
# Get the signed-in user's emails
$Me = (Get-AzContext).Account.Id
$Top100Messages = Get-MgUserMessage -UserId $Me -Top 100 | Select-Object Subject, From, ReceivedDateTime
$Top100Messages

$OneWeekAgo = (Get-Date).AddDays(-7)
$FilteredMessages = Get-MgUserMessage -UserId $Me -Top 50 | Where-Object { $($_.Subject -like "Sev2") -or ($_.ReceivedDateTime -lt $OneWeekAgo) }

Write-Host "Found $($FilteredMessages.Count) messages to delete." -ForegroundColor Green

# Loop through and delete
foreach ($Message in $FilteredMessages) {
    Write-Host "Deleting message: $($Message.Subject) - ID: $($Message.Id)"
    Remove-MgUserMessage -UserId $Me -MessageId $Message.Id -Verbose -WhatIf
}

Write-Host "Deletion complete." -ForegroundColor Green
#endregion