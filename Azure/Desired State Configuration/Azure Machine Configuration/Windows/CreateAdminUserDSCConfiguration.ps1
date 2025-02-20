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
