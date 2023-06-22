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
Function Get-RDCManCredential
{
    [CmdletBinding()]
    param
    (
		[Parameter(Mandatory = $True, HelpMessage = 'Please specify the path of a valid .rdg document', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateScript( {
				(Test-Path -Path $_ -PathType Leaf) -and ($_ -match '\.rdg$')
			})]
		[string[]]$FullName
    )


   begin
    {
        $null = Add-Type -AssemblyName System.Security
    }
    process
    {
        Foreach ($CurrentFullName in $FullName)
	    {
            Write-Verbose "Processing $FullName ..."
            #Remove-Item -Path $FullName -Force 
            If (Test-Path -Path $CurrentFullName -PathType Leaf) {
                $RDGFileContent = [xml](Get-Content -Path $CurrentFullName)
                $logonCredentials = $RDGFileContent.SelectNodes("//logonCredentials")
                foreach($currentLogonCredential in $logonCredentials)
                {
                    $serverName = $currentLogonCredential.ParentNode.properties.name
                    $userName = $currentLogonCredential.userName
                    $domainName = $currentLogonCredential.Domain
                    $SecurePasswordStr = $currentLogonCredential.password
                    $SecurePassword = [System.Convert]::FromBase64String($SecurePasswordStr)
                    if (-not([string]::IsNullOrEmpty($SecurePassword)))
                    {
                        $PasswordBytes = [Security.Cryptography.ProtectedData]::Unprotect($SecurePassword, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                        $ClearTextPassword = [System.Text.Encoding]::Unicode.GetString($PasswordBytes)
                        [PSCustomObject]@{FullName=$CurrentFullName; ServerName=$serverName; DomainName=$domainName; UserName=$userName; Password=$ClearTextPassword}
                    }
                }
            }
        }
    }
    end
    {
    }
}

Clear-Host
<#
$FullName = $(Join-Path -Path $([Environment]::GetFolderPath("MyDocuments")) -ChildPath "RDCMan.rdg")
Get-RDCManCredential -FullName $FullName
#>
$RDCManCredential = Get-ChildItem -Path $([Environment]::GetFolderPath("MyDocuments")) -Filter *.rdg -File | Get-RDCManCredential -Verbose 
$RDCManCredential | Format-Table -AutoSize
