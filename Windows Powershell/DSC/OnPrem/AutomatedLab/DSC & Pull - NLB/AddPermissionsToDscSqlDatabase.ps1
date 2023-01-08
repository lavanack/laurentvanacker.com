param (
    [Parameter(Mandatory)]
    [string[]]$DomainAndComputerName
)

$addPermissionsQuery = @'
-- Adding Permissions
USE [master]
GO

CREATE LOGIN [{0}\{1}] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
GO

USE [DSC]

CREATE USER [{1}] FOR LOGIN [{0}\{1}] WITH DEFAULT_SCHEMA=[db_datareader]
GO

ALTER ROLE [db_datareader] ADD MEMBER [{1}]
GO

ALTER ROLE [db_datawriter] ADD MEMBER [{1}]
GO
'@

foreach ($CurrentDomainAndComputerName in $DomainAndComputerName)
{
    Write-Host "Adding permissions to DSC database for $CurrentDomainAndComputerName..." -NoNewline

    $domain = ($CurrentDomainAndComputerName -split '\\')[0]
    $name = ($CurrentDomainAndComputerName -split '\\')[1]

    if ($ComputerName -eq $env:COMPUTERNAME -and $DomainName -eq $env:USERDOMAIN)
    {
        $domain = 'NT AUTHORITY'
        $name = 'SYSTEM'
    }
    #$name = $name + '$'

    $account = New-Object System.Security.Principal.NTAccount($domain, $name)
    try
    {
        $account.Translate([System.Security.Principal.SecurityIdentifier]) | Out-Null
    }
    catch
    {
        Write-Error "The account '$domain\$name' could not be found"
        continue
    }

    $query = $addPermissionsQuery -f $domain, $name

    Invoke-Sqlcmd -Query $query -ServerInstance localhost
}

Write-Host 'finished'
