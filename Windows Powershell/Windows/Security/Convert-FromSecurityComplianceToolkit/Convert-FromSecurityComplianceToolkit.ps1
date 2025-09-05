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
#Requires -PSEdition Core -Modules GPRegistryPolicyParser, BaselineManagement, GPRegistryPolicyDsc, SecurityPolicyDsc, AuditPolicyDsc, PSDesiredStateConfiguration, GuestConfiguration

#From https://doitpshway.com/convert-ms-security-baselines-to-azure-arc-guest-configuration-packages
#From https://learn.microsoft.com/en-us/powershell/dsc/quickstarts/gpo-quickstart
#From https://github.com/microsoft/BaselineManagement/blob/main/src/BaselineManagement.psm1#L21-L636

<#
#Pre-requisites: Installing requied modules if not locally available
Install-Module -Name 'GPRegistryPolicyParser', 'BaselineManagement', 'GPRegistryPolicyDsc', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'PSDesiredStateConfiguration', 'GuestConfiguration' -Scope AllUsers -Force
Install-Module -Name 'PSDesiredStateConfiguration' -Scope AllUsers -Force
#>

[CmdletBinding()]
param
(
)

#region Function Definition
Function Convert-FromSecurityComplianceToolkit {
    [CmdletBinding()]
    param
    (
    )

    #region Variable Defintion
    $BaselineURI = [ordered]@{
        "Windows Server 2016" = "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
        "Windows Server 2019" = "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
        "Windows Server 2022" = "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    }

    $DSCRootDirectory = Join-Path -Path $PSScriptRoot -ChildPath "ConvertedBaselineGPOs"
    $ExtractedBaselineDirectory = Join-Path -Path $PSScriptRoot -ChildPath "ExtractedBaselines"
    $BaselineDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Baselines"
    Remove-Item -Path $DSCRootDirectory, $ExtractedBaselineDirectory, $BaselineDirectory -Recurse -Force -ErrorAction Ignore
    $null = New-Item -Path $DSCRootDirectory, $ExtractedBaselineDirectory, $BaselineDirectory -ItemType Directory -Force

    foreach ($OS in $BaselineURI.Keys) {
        Write-Verbose -Message "Processing '$OS' Operating System ..."
        $Destination = Join-Path -Path $BaselineDirectory -ChildPath $((Split-Path -Path $BaselineURI[$OS] -Leaf) -replace "%20", "_")
        Write-Verbose -Message "`$Destination: $Destination"
        Start-BitsTransfer -Source $BaselineURI[$OS] -Destination $Destination
        $DestinationPath = Join-Path -Path $ExtractedBaselineDirectory -ChildPath $OS
        Remove-Item -Path $DestinationPath -Recurse -Force -ErrorAction Ignore
        Write-Verbose -Message "`$DestinationPath: $DestinationPath"
        Expand-Archive -Path $Destination -DestinationPath $DestinationPath
        $GPODir = (Get-ChildItem -Path $DestinationPath -Filter "GPOs" -Recurse -Directory).FullName
        Write-Verbose -Message "`$GPODir: $GPODir"
        $ConfigName = $OS -replace "\s"
        Write-Verbose -Message "`$ConfigName: $ConfigName"
        $DSCOSDirectory = Join-Path -Path $DSCRootDirectory -ChildPath $OS
        Write-Verbose -Message "`$DSCOSDirectory: $DSCOSDirectory"
        
        foreach ($CurrentGPODir in (Get-ChildItem -Path $GPODir -Directory)) {
            Write-Verbose -Message "`$CurrentGPODir: $CurrentGPODir"
            if ((Get-Content -Path "$($CurrentGPODir)\bkupInfo.xml" -Raw) -match "<GPODisplayName><!\[CDATA\[(.+)\]\]></GPODisplayName>") {
                $GPOName = $Matches[1] -replace '\W', '_'
                Write-Verbose -Message "`$GPOName: $GPOName"
            }
            else {
                Write-Warning -Message "Cannot find GPO name in '$($CurrentGPODir)\bkupInfo.xml'."
            }
            Write-Verbose -Message "`tProcessing '$GPOName' GPO ..."
            <#
            $GPOName = ([regex]"<GPODisplayName><!\[CDATA\[(.+)\]\]></GPODisplayName>").Matches((Get-Content -Path "$($CurrentGPODir)\bkupInfo.xml" -Raw)).captures.groups[1].value
            Write-Verbose -Message "`$GPOName: $GPOName"
            #>
            # !BEWARE! creating of some localhost.mof can (probably will) end with an error https://github.com/microsoft/BaselineManagement?tab=readme-ov-file#known-gaps-in-capability
            # problematic ps1 parts have to be commented otherwise you will not be able to create DSC from it!
            #Note: 
            # For Windows Server 2016 and 2019, the Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM: has to be commented (with <# ...#> tags) in the generated ps1 file. 
            # After you have to run the .ps1 file to generate the localhost.mof file. This occurs after running the ConvertFrom-GPO
            # For Windows Server 2022, We have to comment (with ;) the line that contains the property 'LdapEnforceChannelBinding' in the related GptTmpl.inf file before running the ConvertFrom-GPO cmdlet. This occurs before running the ConvertFrom-GPO
            $DSCGPODirectory = Join-Path -Path $DSCOSDirectory -ChildPath $GPOName
            Write-Verbose -Message "`$DSCGPODirectory: $DSCGPODirectory"

            try {
                $ConvertedGpo = ConvertFrom-GPO -Path $CurrentGPODir -OutputConfigurationScript -OutputPath $DSCGPODirectory -ConfigName $GPOName -ShowPesterOutput -ErrorAction Stop
            }
            catch {
                if ($_ -like "Invalid MOF definition*") {
                    Write-Warning "In '$($ConvertedGpo.ConfigurationScript)' comment setting that contains property mentioned in this error '$_'.`n`nOtherwise you will not be able to generate guest configuration from it!"
                }
                else {
                    Write-Error $_
                }
            }
            <#
        # Disabling MOF compilation part (last line) I will compile it by myself later
        $ConfigurationScript = Join-Path -Path $DSCOSDirectory -ChildPath "$ConfigName.ps1"
        (Get-Content -Path $ConfigurationScript) -replace "($ConfigName -OutputPath)", '#$1' | Set-Content -Path $ConfigurationScript
        #>
        }
    }
    #endregion
}
#endregion



#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

Convert-FromSecurityComplianceToolkit -Verbose
#endregion
