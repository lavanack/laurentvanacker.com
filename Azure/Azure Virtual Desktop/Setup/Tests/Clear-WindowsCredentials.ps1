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

[CmdletBinding()]
Param (
)

Clear-Host
$Pattern = "(fsl|msix|apat).*"
$StorageAccountCredentials = cmdkey /list | Select-string -Pattern "(?<Target>Target: (?<Domain>Domain:target=(?<FQDN>(?<Pattern>$Pattern)\.file\.core\.windows\.net)))" -AllMatches
if ($StorageAccountCredentials.Matches) {
    Write-Verbose -Message "Processing $Matches"
    $StorageAccountCredentials.Matches | ForEach-Object -Process { 
        $Target = $_.Groups['Target']
        $Domain = $_.Groups['Domain']
        $FQDN = $_.Groups['FQDN']
        $Pattern = $_.Groups['Pattern']
        Write-Verbose -Message "`$Target: $Target"
        Write-Verbose -Message "`$Domain: $Domain"
        Write-Verbose -Message "`$FQDN: $FQDN"
        Write-Verbose -Message "`$Pattern: $Pattern"
        Write-Host -Object "Removing cmdkey credentials for $Domain"
        Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$Domain" -NoNewWindow
    }
}
else {
    Write-Verbose -Message "No Windows Credentials"
}
 
