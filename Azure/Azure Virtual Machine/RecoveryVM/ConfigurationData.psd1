@{
    AllNodes = @(
        @{
            NodeName= 'localhost'
            <#
                NOTE! THIS IS NOT RECOMMENDED IN PRODUCTION.
                This is added so that AppVeyor automatic tests can pass, otherwise the tests will fail on
                passwords being in plain text and not being encrypted. Because there is not possible to have
                a certificate in AppVeyor to encrypt the passwords we need to add parameter
                'PSDscAllowPlainTextPassword'.
                NOTE! THIS IS NOT RECOMMENDED IN PRODUCTION.
            #>
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
         }
    )
}