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
#Pre-requisites: Installing required modules if not locally available
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

    #region Downloading the Microsoft Security Compliance Toolkit webpage content and extracting download links from it
    $MicrosoftSecurityComplianceToolkitDownloadURI = "https://www.microsoft.com/en-us/download/details.aspx?id=55319"
    $Content = Invoke-RestMethod -Uri $MicrosoftSecurityComplianceToolkitDownloadURI
    if ($Content -match '"downloadFile":(?<JSON>\[[^]]+\])') {
        $SCTFileData = ($Matches['JSON'] | ConvertFrom-Json) | Select-Object -Property @{Name = "SKU"; Expression = { $_.Name -replace "\..*" } }, * | Group-Object -Property SKU -AsHashtable -AsString
        Write-Verbose -Message "`$SCTFileData: $($SCTFileData | Out-String)"
    }
    else {
        Write-Error -Message "Cannot find download links on '$MicrosoftSecurityComplianceToolkitDownloadURI' webpage." -ErrorAction Stop
    }

    #Filtering only Windows Server baselines
    $SCTFileData = $SCTFileData.Values | Where-Object -FilterScript { $_.SKU -match "Server \d{4}" } | ForEach-Object -Process { $_ }  | Group-Object -Property SKU -AsHashtable -AsString
    #endregion
    
    #region Variable Definition
    #Creating required directories: The root directory for every iteration will be a timestamped directory in the same directory where this script resides
    $TimeStampedDirectory = Join-Path -Path $PSScriptRoot -ChildPath $(Get-Date -Format "yyyyMMddHHmmss")
    $DSCRootDirectory = Join-Path -Path $TimeStampedDirectory -ChildPath "ConvertedBaselines"
    $ExtractedBaselineDirectory = Join-Path -Path $TimeStampedDirectory -ChildPath "ExtractedBaselines"
    $BaselineDirectory = Join-Path -Path $TimeStampedDirectory -ChildPath "Baselines"
    #endregion

    $null = New-Item -Path $TimeStampedDirectory, $DSCRootDirectory, $ExtractedBaselineDirectory, $BaselineDirectory -ItemType Directory -Force

    $BaselineIndex = 0
    foreach ($Baseline in $SCTFileData.Keys) {
        $BaselineIndex++
        $PercentComplete = ($BaselineIndex / $SCTFileData.Keys.Count * 100)
        Write-Verbose -Message "`$PercentComplete: $PercentComplete"
        Write-Progress -Id 1 -Activity "[$BaselineIndex/$($SCTFileData.Keys.Count)] Processing '$Baseline' Baseline ..." -Status $("{0:N0} %" -f $PercentComplete) -PercentComplete $PercentComplete
        Write-Host -Object "`r`nProcessing '$Baseline' Baseline ..."
        $ConfigurationScript = Join-Path -Path $BaselineDirectory -ChildPath $((Split-Path -Path $SCTFileData[$Baseline].url -Leaf) -replace "%20", "_")
        Write-Verbose -Message "`$ConfigurationScript: $ConfigurationScript"
        $Source = $SCTFileData[$Baseline].url
        Write-Verbose -Message "`$Source: $Source"
        Start-BitsTransfer -Source $Source -Destination $ConfigurationScript
        $ConfigurationScriptPath = Join-Path -Path $ExtractedBaselineDirectory -ChildPath $Baseline
        Remove-Item -Path $ConfigurationScriptPath -Recurse -Force -ErrorAction Ignore
        Write-Verbose -Message "`$ConfigurationScriptPath: $ConfigurationScriptPath"
        Expand-Archive -Path $ConfigurationScript -DestinationPath $ConfigurationScriptPath
        $GPODir = (Get-ChildItem -Path $ConfigurationScriptPath -Filter "GPOs" -Recurse -Directory).FullName
        Write-Verbose -Message "`$GPODir: $GPODir"
        $ConfigName = $Baseline -replace "\s"
        Write-Verbose -Message "`$ConfigName: $ConfigName"
        $DSCOSDirectory = Join-Path -Path $DSCRootDirectory -ChildPath $Baseline
        Write-Verbose -Message "`$DSCOSDirectory: $DSCOSDirectory"
        

        $GPOIndex = 0
        $GPODirs = (Get-ChildItem -Path $GPODir -Directory)
        foreach ($CurrentGPODir in $GPODirs) {
            $GPOIndex++
            $PercentComplete = ($GPOIndex / $GPODirs.Count * 100)
            Write-Verbose -Message "`$PercentComplete: $PercentComplete"
            Write-Progress -Id 2 -Activity "[$GPOIndex/$($GPODirs.Count)] Processing '$GPOName' GPO ..." -Status $("{0:N0} %" -f $PercentComplete) -PercentComplete $PercentComplete

            Write-Verbose -Message "`$CurrentGPODir: $CurrentGPODir"
            if ((Get-Content -Path "$($CurrentGPODir)\bkupInfo.xml" -Raw) -match "<GPODisplayName><!\[CDATA\[(.+)\]\]></GPODisplayName>") {
                $GPOName = $Matches[1] -replace '\W', '_'
                Write-Verbose -Message "`$GPOName: $GPOName"
            }
            else {
                Write-Warning -Message "Cannot find GPO name in '$($CurrentGPODir)\bkupInfo.xml'."
            }
            Write-Host -Object "- Processing '$GPOName' GPO ..."
            <#
            $GPOName = ([regex]"<GPODisplayName><!\[CDATA\[(.+)\]\]></GPODisplayName>").Matches((Get-Content -Path "$($CurrentGPODir)\bkupInfo.xml" -Raw)).captures.groups[1].value
            Write-Verbose -Message "`$GPOName: $GPOName"
            #>
            # !BEWARE! creating of some localhost.mof can (probably will) end with an error https://github.com/microsoft/BaselineManagement?tab=readme-ov-file#known-gaps-in-capability
            # problematic ps1 parts have to be commented otherwise you will not be able to create DSC from it! This script will try to do it for you
            # you will have to manually check the created configuration script and uncomment the commented parts if you want to use them
            # you can also try to fix the generated configuration script (if any) and re-run the script
            $DSCGPODirectory = Join-Path -Path $DSCOSDirectory -ChildPath $GPOName
            Write-Verbose -Message "`$DSCGPODirectory: $DSCGPODirectory"

            try {
                #$ConvertedGpo = ConvertFrom-GPO -Path $CurrentGPODir -OutputConfigurationScript -OutputPath $DSCGPODirectory -ConfigName $GPOName -ShowPesterOutput -ErrorAction Stop
                $ConvertedGpo = ConvertFrom-GPO -Path $CurrentGPODir -OutputConfigurationScript -OutputPath $DSCGPODirectory -ConfigName $GPOName -ErrorAction Stop
                Write-Host -Object " - Successfully converted '$GPOName' GPO to DSC."
                Write-Verbose -Message "`$ConvertedGpo: $($ConvertedGpo | Out-String)"
            }
            catch {
                if ($Error[1].ErrorDetails.Message -match "Invalid MOF definition") {
                    $ConfigurationScript = Join-Path -Path $DSCGPODirectory -ChildPath "$GPOName.ps1"
                    Write-Warning -Message "- In '$ConfigurationScript' comment setting that contains property mentioned in this error:`r`n'$($Error[1].ErrorDetails.Message)'.`r`nOtherwise you will not be able to generate guest configuration from it!"
                    if ($Error[1].ErrorDetails.Message -match "property\s+'(\w*)'\s") {
                        $Property = $Matches[1]
                        Write-Verbose -Message "`$Property: $Property"
                        # Define the regex pattern to match everything until the next }, including new lines
                        $Pattern = "([^\r\n]+$Property[^\}]+\})"
                        
                        # Use regex to find all matches
                        $FileContent = Get-Content -Path $ConfigurationScript -Raw
                        $MyMatches = [regex]::Matches($FileContent, $Pattern)
                        if ($MyMatches) {
                            [regex]::Replace($FileContent, $Pattern, "<# Fixed by '$($MyInvocation.MyCommand)'`r`n`$1`r`n#>") | Set-Content -Path $ConfigurationScript
                            Write-Verbose -Message "Commenting setting that contains property '$Property' in '$ConfigurationScript'."
                            #Removing the faulty localhost.mof.error file if exists
                            $null = Get-ChildItem -Path $DSCGPODirectory -Filter localhost.mof.error |  Remove-Item -ErrorAction Ignore -Force
                            #Recalling the Configuration Script after fixing it (for generating a valid localhost.mof file)
                            & $ConfigurationScript | Out-Null
                            if (Test-Path -Path $(Join-Path -Path $DSCGPODirectory -ChildPath localhost.mof) -PathType Leaf) {
                                Write-Host -Message " - Repair successful!" -ForegroundColor Green
                            }
                            else {
                                Write-Warning -Message " - Repair failed!"
                            }
                        }
                    }
                    else {
                        Write-Warning "Cannot find property name in error message: '$($Error[1].ErrorDetails.Message)'."
                    }
                }
                else {
                    Write-Error $_.Exception.Message
                    if ($_.Exception.Message -match "^.*\s(?<file>\S*)\sfile.*'(?<entry>.*)'.*unknown value.*$") {
                        $File = $Matches['file']
                        $Entry = $Matches['entry']
                        Write-Verbose -Message "`$File: $File"
                        Write-Verbose -Message "`$Entry: $Entry"
                        Get-ChildItem -Path $CurrentGPODir -Filter $File -File -Recurse | ForEach-Object {
                            Write-Verbose -Message "`Fixing error by removing the problematic '$Entry' entry in the '$($_.FullName)' file"
                            $Pattern = "(^{0}.*$)" -f ($Entry -replace "(\W)", "\\$1")
                            #(Get-Content -Path $_.FullName) -replace $Pattern, '#$1' | Set-Content -Path $_.FullName
                            (Get-Content -Path $_.FullName) -replace $Pattern | Set-Content -Path $_.FullName
                            Write-Verbose -Message "Commenting entry '$Entry' in '$($_.FullName)'."
                            try {
                                $ConvertedGpo = ConvertFrom-GPO -Path $CurrentGPODir -OutputConfigurationScript -OutputPath $DSCGPODirectory -ConfigName $GPOName -ShowPesterOutput -ErrorAction Stop
                                Write-Host -Message " - Repair successful!" -ForegroundColor Green
                                Write-Verbose -Message "`$ConvertedGpo: $($ConvertedGpo | Out-String)"
                            }
                            catch {
                                Write-Error $_.Exception.Message
                            }
                        }   
                    }
                }
            }
        }
        Write-Progress -Id 2 -Completed -Activity 'GPO processing completed.'
        <#
            # Disabling MOF compilation part (last line) I will compile it by myself later
            $ConfigurationScript = Join-Path -Path $DSCGPODirectory -ChildPath "$GPOName.ps1"
            (Get-Content -Path $ConfigurationScript) -replace "($ConfigName -OutputPath)", '#$1' | Set-Content -Path $ConfigurationScript
            #>
    }
    Write-Progress -Id 1 -Completed -Activity 'Baseline processing completed.'
    Get-ChildItem -Path $TimeStampedDirectory -Recurse -Filter localhost.mof.error
}

#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

Convert-FromSecurityComplianceToolkit #-Verbose
#endregion
