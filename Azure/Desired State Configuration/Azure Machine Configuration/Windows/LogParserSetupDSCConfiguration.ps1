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

#region function definitions
function Get-AzVMCompute {
    [CmdletBinding(PositionalBinding = $false)]
    Param(
    )

    Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Entering function '$($MyInvocation.MyCommand)'"

    $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Metadata" = "true" } -Method GET -TimeoutSec 5
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] VM Compute Object:`r`n$($response.compute | Out-String)"
        return $response.compute
    }
    catch {
        Write-Verbose -Message "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Leaving function '$($MyInvocation.MyCommand)'"
        return $null
    }
}
#endregion

#region DSC Configuration
Configuration LogParserSetupDSCConfiguration {
	Param ( 
	)
    Import-DscResource -ModuleName 'PSDscResources'

    node $AllNodes.NodeName
	{
        
        foreach ($CurrentSoftware in $Node.Softwares) {
            $SASURI = $CurrentSoftware.SASURI
            $FileName = Split-Path -Path $($SASURI -replace "\?.*") -Leaf
            $DestinationPath = Join-Path -Path $env:Temp -ChildPath $FileName

            Script "$($FileName) - CopyFromBlobWithSAS" {
                GetScript  = {
                    @{
                        GetScript  = $GetScript
                        SetScript  = $SetScript
                        TestScript = $TestScript
                    }
                }
     
                SetScript  = {
                        Invoke-RestMethod -Uri $using:SASURI -OutFile $using:DestinationPath
                }
     
                TestScript = {
                    # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                    return Test-Path -Path $using:DestinationPath -PathType Leaf
                }
            }

		    MsiPackage InstallLogParser {
			    Ensure          = 'Present'
			    Path            = $DestinationPath
			    ProductId       = '4AC23178-EEBC-4BAF-8CC0-AB15C8897AC9'
                DependsOn       = "[Script]$($FileName) - CopyFromBlobWithSAS"
		    }
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

$AzVMCompute = Get-AzVMCompute
#Adding a 7-day expiration time from now for the SAS Token
$StartTime = Get-Date
$ExpiryTime = $StartTime.AddDays(7)

#Getting all certificate data from the container.
$StorageSoftwareContainerName = "softwares"
$SoftwareStorageBlobSASToken = Get-AzResourceGroup -Name $AzVMCompute.resourceGroupName | Get-AzStorageAccount | Get-AzStorageContainer -Name $StorageSoftwareContainerName -ErrorAction Ignore | Get-AzStorageBlob | New-AzStorageBlobSASToken -FullUri -Permission r -StartTime $StartTime -ExpiryTime $ExpiryTime      

#Region Building an hashtable with required certificate data for building the DSC configuration 
$CertificateConfigurationData = foreach ($CurrentSoftwareStorageBlobSASToken in $SoftwareStorageBlobSASToken) {
    $SASURI = $CurrentSoftwareStorageBlobSASToken
    @{SASURI = $SASURI}
}
#Adding the hashtable as configuration data
($ConfigurationData.AllNodes | Where-Object -FilterScript {$_.NodeName -eq 'localhost'})['Softwares']=$CertificateConfigurationData

LogParserSetupDSCConfiguration -ConfigurationData $ConfigurationData -Verbose
<#
Start-DscConfiguration -Path .\CertificateImportDSCConfiguration -Force -Wait -Verbose
Test-DscConfiguration -Detailed
#>

#endregion