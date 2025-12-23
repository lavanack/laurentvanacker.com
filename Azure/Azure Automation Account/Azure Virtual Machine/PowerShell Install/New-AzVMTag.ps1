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
#requires -Version 5 -Modules Az.Accounts, Az.Compute

Clear-Host
$Error.Clear()
$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

$Pattern = "vm{0:yyMMdd}*" -f (Get-date)

Get-AzVM -Name $Pattern | ForEach-Object -Process { 
    $Tag = @{"Hardening"=$("2019", "2022", "2025" | Get-Random) }
    ForEach($TagName in $Tag.Keys) {
        $TagValue = $Tag[$TagName]
        Write-Host -Object "[$($_.Name)] Adding '$($TagName)' = '$($TagValue)' Tag "
    }
    $_ | Update-AzVM -Tag $Tag -Verbose -AsJob 
} | Receive-Job -Wait -AutoRemoveJob
