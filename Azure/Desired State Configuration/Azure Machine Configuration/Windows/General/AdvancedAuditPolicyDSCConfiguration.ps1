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

#From https://raw.githubusercontent.com/NVISOsecurity/posh-dsc-windows-hardening/refs/heads/master/AuditPolicy_WindowsServer2016.ps1

Configuration AdvancedAuditPolicyDSCConfiguration {
	Param ( 
	)
    Import-DscResource -ModuleName 'PSDscResources', 'AuditPolicyDSC'

    node $AllNodes.NodeName
	{
        #region Account Logon
        AuditPolicySubcategory "Audit Credential Validation (Success)"
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure)'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory "Audit Kerberos Authentication Service (Success)"
        {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Kerberos Authentication Service (Failure)'
        {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory "Audit Kerberos Service Ticket Operations (Success)"
        {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Failure)'
        {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        #endregion

        #region Account Management
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Success)' 
        {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Success)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Failure)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        #endregion

        #region Detailed Tracking
        AuditPolicySubcategory 'Audit Process Creation (Success)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }    

        AuditPolicySubcategory 'Audit Process Creation (Failure)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        #endregion    

        #region Logon/Logoff
        AuditPolicySubcategory 'Audit Logon (Success)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        #endregion
    }
}
#endregion

#region Main Code
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            #PSDscAllowPlainTextPassword = $true
        }
    )
}


<#
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 
#>

AdvancedAuditPolicyDSCConfiguration -ConfigurationData $ConfigurationData
<#
Start-DscConfiguration -Path .\AdvancedAuditPolicyDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>
#endregion