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

Configuration CreateAdminUserDSCConfiguration
{
    param (
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName 'PSDscResources'

    node $AllNodes.NodeName
    {
        User AdminUser {
            Ensure   = 'Present'
            UserName = $Credential.UserName
            Password = $Credential
        }


        Group AddUserToAdminGroup {
            GroupName        = 'Administrators'
            Ensure           = 'Present'
            MembersToInclude = @( $Credential.UserName )
            DependsOn        = '[User]AdminUser'
        }
    }
}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            PSDscAllowPlainTextPassword = $true
        }
    )
}


$Username = 'MyEvilAdminUser'
$ClearTextPassword = 'P@ssw0rd'
$SecurePassword = ConvertTo-SecureString -String $ClearTextPassword -AsPlainText -Force

$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($Username, $SecurePassword)
CreateAdminUserDSCConfiguration -Credential $Credential -ConfigurationData $ConfigurationData
