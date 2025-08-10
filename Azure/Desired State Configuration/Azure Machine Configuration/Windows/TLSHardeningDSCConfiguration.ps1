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

Configuration TLSHardeningDSCConfiguration {
	Param ( 
	)
    Import-DscResource -ModuleName 'PSDscResources'

    node $AllNodes.NodeName
	{
		
        foreach ($DisabledProtocol in "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1") {
            $Name = $DisabledProtocol -replace "\W"
		    #region Client
            Registry $("DisableClient{0}" -f $Name) {
			    Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Client"
			    ValueName = 'Enabled'
			    ValueData = '0'
			    ValueType = 'DWORD'
			    Ensure = 'Present'
		    }

            Registry $("DisableByDefaultClient{0}" -f $Name) {
			    Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Client"
			    ValueName = 'DisabledByDefault'
			    ValueData = '1'
			    ValueType = 'DWORD'
			    Ensure = 'Present'
		    }
            #endregion 

		    #region Server
            Registry $("DisableServer{0}" -f $Name) {
			    Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Server"
			    ValueName = 'Enabled'
			    ValueData = '0'
			    ValueType = 'DWORD'
			    Ensure = 'Present'
		    }

            Registry $("DisableByDefaultServer{0}" -f $Name) {
			    Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$DisabledProtocol\Server"
			    ValueName = 'DisabledByDefault'
			    ValueData = '1'
			    ValueType = 'DWORD'
			    Ensure = 'Present'
		    }
            #endregion 

        }
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

TLSHardeningDSCConfiguration -ConfigurationData $ConfigurationData
<#
Start-DscConfiguration -Path .\TLSHardeningDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>
#endregion