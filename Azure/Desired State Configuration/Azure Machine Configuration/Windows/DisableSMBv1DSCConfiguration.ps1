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

<#
#region Alternative
Configuration DisableSMBv1DSCConfiguration {
	Param ( 
	)
    Import-DscResource -ModuleName 'PSDscResources'

    node $AllNodes.NodeName
	{
        Script DisableSMBv1 {
            GetScript  = {
                $State = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
                @{
                    GetScript  = $GetScript
                    SetScript  = $SetScript
                    TestScript = $TestScript
                    Result     = $State
                }
            }
     
            SetScript  = {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
            }
     
            TestScript = {
                # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ($state.Result -eq "DisabledWithPayloadRemoved")
            }
        }

	}
}
#endregion
#>
Configuration DisableSMBv1DSCConfiguration {
	Param ( 
	)
    Import-DscResource -ModuleName 'PSDscResources'

    node $AllNodes.NodeName
	{
        Registry DisableSMBv1 {
			Key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
			ValueName = 'SMB1'
			ValueData = '0'
			ValueType = 'DWORD'
			Ensure = 'Present'
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

DisableSMBv1DSCConfiguration -ConfigurationData $ConfigurationData

<#
Start-DscConfiguration -Path .\DisableSMBv1RegistryDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>
#endregion