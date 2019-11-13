#requires -version 3 -RunAsAdministrator 
#requires -Modules WebAdministration

Import-Module -Name WebAdministration

#region function definitions
#For getting machine keys
function Get-MachineKey
{
	Import-Module -Name WebAdministration
	Write-Verbose -Message "Getting machine key configuration from $($env:COMPUTERNAME)"
	$MachineKey = Get-WebConfiguration -Filter 'system.web/machinekey' -Recurse |
	Select-Object -Property decryptionKey, decryption, validationKey, validation, PSPath, @{
		Name       = 'ComputerName'
		Expression = {
			$env:COMPUTERNAME
		}
	}
	return $MachineKey
}

#For setting machine keys
function Set-MachineKey
{
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
		[ValidateNotNullOrEmpty()]
		[array]$InputObject
	)
	begin
	{
		Import-Module -Name WebAdministration
	}
	process
	{
		foreach($CurrentInputObject in $InputObject)
		{
			$IISPath = $CurrentInputObject.PSPath -replace 'MACHINE/WEBROOT/APPHOST/', 'IIS:\sites\'
			if (Test-Path -Path $IISPath)
			{
				#Risk Mitigation : support of -whatif and -confirm
				If (($pscmdlet -eq $null) -or ($pscmdlet.ShouldProcess($CurrentInputObject.PSPath, 'Setting Machine Keys')))
				{
					Write-Host -Object "[$env:Computername] Setting the decryptionKey to $($CurrentInputObject.decryptionKey) for $($CurrentInputObject.PSPath)"
					Set-WebConfigurationProperty -Filter 'system.web/machinekey' -PSPath "$($CurrentInputObject.PSPath)" -name 'decryptionKey' -value $($CurrentInputObject.decryptionKey)
					Write-Host -Object "[$env:Computername] Setting the Decryption Algorithm to $($CurrentInputObject.Decryption) for $($CurrentInputObject.PSPath)"
					Set-WebConfigurationProperty -Filter 'system.web/machinekey' -PSPath "$($CurrentInputObject.PSPath)"  -name 'Decryption' -value $($CurrentInputObject.Decryption)
					Write-Host -Object "[$env:Computername] Setting the validationKey to $($CurrentInputObject.validationKey) for $($CurrentInputObject.PSPath)"
					Set-WebConfigurationProperty -Filter 'system.web/machinekey' -PSPath "$($CurrentInputObject.PSPath)" -name 'validationKey' -value $($CurrentInputObject.validationKey)
					Write-Host -Object "[$env:Computername] Setting the validation Algorithm to $($CurrentInputObject.validation) for $($CurrentInputObject.PSPath)"
					Set-WebConfigurationProperty -Filter 'system.web/machinekey' -PSPath "$($CurrentInputObject.PSPath)" -name 'validation' -value $($CurrentInputObject.validation)
				}
			}
			else
			{
				Write-Warning -Message "$IISPath doesn't exist on $($env:COMPUTERNAME)"
			}
		}
	}
	end
	{
	}
}

Function Push-MachineKey
{
	[CmdletBinding(PositionalBinding = $False, SupportsShouldProcess = $True)]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateNotNullOrEmpty()]
		[String[]]$ComputerName
	)
	begin
	{
		$LocalKeys = Get-MachineKey
	}
	process
	{
		Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Set-MachineKey}  -ArgumentList (,$LocalKeys)
	}
	end
	{
	}
}


Function Show-MachineKey
{
	[CmdletBinding(PositionalBinding = $False, SupportsShouldProcess = $True)]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateNotNullOrEmpty()]
		[String[]]$ComputerName,

		[parameter(Mandatory=$false)]
		[switch]$PassThru
	)
	begin
	{
		$AllKeys = @()
	}
	process
	{
		$AllKeys+=Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Get-MachineKey} | Select-Object -Property * -ExcludeProperty PSComputerName, RunSpaceId
	}
	end
	{
		if ($PassThru)
		{
			$AllKeys | Sort-Object PSPath, ComputerName | Out-GridView -Title 'Machine Keys across Web Servers' -PassThru
		}
		else
		{
			$AllKeys | Sort-Object PSPath, ComputerName | Out-GridView -Title 'Machine Keys across Web Servers'
		}
	}
}


function Export-MachineKey
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
					Test-Path -Path (Split-Path -Path $_ -Parent) -PathType Container
		})]
		#CSV file full name
		
		[Alias('FilePath', 'Path')]
		[String]$FullName
	)
	Write-Verbose -Message "Exporting machine key configuration from $($env:COMPUTERNAME) to $CSVFile"
	Get-MachineKey | Export-Csv -Path $FullName -NoTypeInformation
}

#For importing machine keys
function Import-MachineKey
{
	[CmdletBinding(PositionalBinding = $True, SupportsShouldProcess = $True)]
	Param(
		[Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
					Test-Path -Path $_ -PathType Leaf
		})]
		#CSV file full name
		[Alias('FilePath', 'Path')]
		[String]$FullName
	)
	$LocalKeys = Import-Csv -Path $FullName
	Write-Verbose -Message "Importing machine key configuration from $(($LocalKeys | Select-Object -ExpandProperty ComputerName -Unique).ComputerName)"
	Set-MachineKey -InputObject $LocalKeys
}
#endregion

Clear-Host
# Getting the this script path
$CurrentScript = $MyInvocation.MyCommand.Path
# Getting the directory of this script
$CurrentDir = Split-Path -Path $CurrentScript -Parent
#CSV file for exporting/importing machine keys
$CSVFile = $CurrentScript.replace((Get-Item -Path $CurrentScript).Extension, '.csv')

#Exporting/Backing up local machine keys to a CSV file
#Export-MachineKey -Path $CSVFile -Verbose

#Importing and setting machine keys from a CSVFile to the local computer 
#Get-Item -Path $CSVFile | Import-MachineKey -Verbose #-WhatIf 

#Getting local machine keys
#$LocalKeys = Get-MachineKey
#Exporting/Backing up local machine keys to a CSV file
#$LocalKeys | Export-Csv -Path $CSVFile -NoTypeInformation

#Importing machine keys from a CSVFile
#$LocalKeys = Import-Csv -Path $CSVFile
#Setting machine keys the local computer 
#Set-MachineKey -InputObject $LocalKeys -whatif
#$LocalKeys | Set-MachineKey -whatif

$TargetIISServers="IIS002","DC001"
#Pushing/Duplicating local machine keys (after a manual setting on the source server) on the targeted computers
Push-MachineKey Push-MachineKey -ComputerName $TargetIISServers -Verbose


#Checking all machine keys across the web servers
$KeysAcrossWebFarm=Show-MachineKey -ComputerName $TargetIISServers -PassThru -Verbose
$KeysAcrossWebFarm