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

#From https://github.com/dsccommunity/ComputerManagementDsc/wiki/Computer#example-1

Configuration DomainJoinDSCConfiguration {
	Param ( 
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $DomainName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
	)
    Import-DscResource -ModuleName 'PSDscResources', 'ComputerManagementDsc'

    node $AllNodes.NodeName
	{
        
        <#
        Script DomainJoinStorage {
            # TestScript runs first and if it returns false, then SetScript runs
            GetScript  = {
                [string] $DomainName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    DomainName = $DomainName
                }
            }
     
            SetScript            = {
                #Add-Computer -DomainName $using:DomainName -Credential $using:Credential -Restart
                Restart-Computer -Force

            }
            TestScript           = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ($state.DomainName -eq $using:DomainName)
            }
        }
        #>
        #Not optimal solution because the server name has to be explicitly specified (so this DSC configuration is tied to a specific machine)
        Computer JoinDomain
        {
            Name       = $Name
            DomainName = $DomainName
            Credential = $Credential # Credential to join to domain
        }


        PendingReboot RebootAfterDomainJoin
        {
            Name = 'DomainJoin'
        }
    }
}
#endregion

#region Main Code
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
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

<#
$DNSServer = (Get-DnsClientServerAddress -InterfaceAlias Ethernet).ServerAddresses | Select-Object -First 1
#Alterntive but PS Remoting has to be enabled
$DomainName = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem -ComputerName $DNSServer -Credential $Credential).Domain
#>
$DomainName = "contoso.com"
#$Name = $Env:COMPUTERNAME
$Name = "localhost"
$AdJoinUserName = 'adjoin@{0}' -f $DomainName
$AdJoinUserClearTextPassword = 'My5trongP@ssw0rd'
$AdJoinUserPassword = ConvertTo-SecureString -String $AdJoinUserClearTextPassword -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($AdJoinUserName, $AdJoinUserPassword)
#$Credential = Get-Credential -Message "AD Domain Join Credential"

DomainJoinDSCConfiguration -ConfigurationData $ConfigurationData -DomainName $DomainName -Name $Name -Credential $Credential
<#
Start-DscConfiguration -Path .\DomainJoinDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>
#endregion
