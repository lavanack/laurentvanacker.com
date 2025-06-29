<#
This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment.  THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
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
#requires -Version 5 -Modules Az.Accounts, Az.Resources, Az.Storage
#From https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-custom-image-templates
#From https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#customization-log

#region Function definitions
function Get-AzureVMImageBuilderCustomizationLog {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $false)]
        #Destination Folder for the downloaded files
		[string]$Destination = '.',
		[Parameter(Mandatory = $false)]
        #Destination Folder for the downloaded files
        [ValidatePattern("^IT_.*$")]
		[string]$ResourceGroupName = "IT_*",
		[switch]$TimeStamp
	)
    #Getting all Image Builder Template ResourceGroup
    $AzImageBuilderTemplateResourceGroup =  Get-AzResourceGroup -Name $ResourceGroupName 
    foreach ($CurrentAzImageBuilderTemplateResourceGroup in $AzImageBuilderTemplateResourceGroup) {
        Write-Verbose -Message "Processing '$($CurrentAzImageBuilderTemplateResourceGroup.ResourceGroupName)' Resource Group (Image Template: $($CurrentAzImageBuilderTemplateResourceGroup.Tags.imageTemplateName) / Resource Group: $($CurrentAzImageBuilderTemplateResourceGroup.Tags.imageTemplateResourceGroupName))..."
        #Creating a dedicated directory per Image Builder Template ResourceGroup
        $CurrentDestination = New-Item -Path $Destination -Name $CurrentAzImageBuilderTemplateResourceGroup.ResourceGroupName -ItemType Directory -Force
        #Getting the customization.log (only this file exists in the packerlogs directory)
        try
        {
            $AzStorageBlobContent = $CurrentAzImageBuilderTemplateResourceGroup | Get-AzStorageAccount | Get-AzStorageContainer -Name packerlogs | Get-AzStorageBlob | Get-AzStorageBlobContent -Destination $CurrentDestination -Force -Verbose 
            if ($null -ne $AzStorageBlobContent)
            {
                Write-Verbose -Message "Getting $($AzStorageBlobContent | Out-String)"
                #Getting the local path of the downloaded customization.log 
                $DestinationFile = Join-Path -Path $CurrentDestination -ChildPath $AzStorageBlobContent.Name
                #If the TimeStamp switch has been specified we add a timetamp to the log file name (so we can compare the log file between to runs and follow the template build process evolution)
                if ($TimeStamp)
                {
                    $Extension = (Get-Item -Path $DestinationFile).Extension
                    #$TimeStampDestinationFile = $DestinationFile -replace "\$($Extension)$", "_$("{0:yyyyMMddHHmmss}" -f (Get-Date))$Extension"
                    $TimeStampDestinationFile = $DestinationFile -replace "\$($Extension)$", $("_{0:yyyyMMddHHmmss}{1}" -f $(Get-Date), $Extension)
                    Rename-Item -Path $DestinationFile -NewName $TimeStampDestinationFile
                    Write-Verbose -Message "Destination File: '$TimeStampDestinationFile' ..."
                    $TimeStampDestinationFile
                }
                #Else the file will be overwritten at each run
                else
                {
                    Write-Verbose -Message "Destination File: '$DestinationFile' ..."
                    $DestinationFile
                }
            } else {
                Write-Verbose -Message "Removing '$CurrentDestination' (No customization.log file found/processed) ..."
                $CurrentDestination | Remove-Item -Force
            }
        }
        catch {}
    }
}
#endregion

#region Main code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir

#region Login to your Azure subscription.
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
	Connect-AzAccount
}
#endregion


$CustomizationLog = Get-AzureVMImageBuilderCustomizationLog -Destination $CurrentDir -TimeStamp -Verbose
if ($null -ne $CustomizationLog)
{
    $CustomizationLog
    #Open them via the default action
    $CustomizationLog | ForEach-Object -Process { & $_ }
    #Looking for customization phase(s)
    Select-String -Pattern "Starting provisioner|Starting AVD AIB Customization|AVD AIB CUSTOMIZER PHASE" -Path $CustomizationLog -Context 1
}
else
{
    Write-Warning "No customization.log file found/processed ..."
}
#endregion