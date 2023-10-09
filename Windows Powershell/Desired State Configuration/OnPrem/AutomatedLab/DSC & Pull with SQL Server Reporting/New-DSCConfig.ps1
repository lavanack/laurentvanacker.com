configuration PullTestConfig
{
	param(
        [string[]] $ComputerName = 'localhost'
    )
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration' 
    
	node $ComputerName
	{
		File TempDir
		{
			Ensure          = 'Present'
			DestinationPath = 'C:\MyTemp'
			Type            = 'Directory'
		}       
	}
}

PullTestConfig
$ConfigurationName = "PullTestConfig"

#Copy-Item -Path .\PullTestConfig\localhost.mof -Destination "C:\Program Files\WindowsPowerShell\DscService\Configuration\$ConfigurationName.mof"
#New-DscChecksum "C:\Program Files\WindowsPowerShell\DscService\Configuration\$ConfigurationName.mof" -Force
Rename-Item -Path .\PullTestConfig\localhost.mof -NewName "$ConfigurationName.mof"
Import-Module xPSDesiredStateConfiguration
Publish-DSCModuleAndMof -Source .\PullTestConfig -Force

Get-ChildItem -Path 'C:\Program Files\WindowsPowerShell\DscService\Configuration\', 'C:\Program Files\WindowsPowerShell\DscService\Modules\'
