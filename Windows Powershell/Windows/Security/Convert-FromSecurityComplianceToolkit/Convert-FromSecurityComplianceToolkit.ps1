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
    <#
    .SYNOPSIS
      Function that converts the Microsoft Security Compliance Toolkit baslines to DSC configuration scripts
    .DESCRIPTION
      Function that converts the Microsoft Security Compliance Toolkit baslines to DSC configuration scripts
    .PARAMETER  Output
      The root Output directory where the baselines and DSC configuration scripts will be stored
    .EXAMPLE
      PS C:\> Convert-FromSecurityComplianceToolkit 
    .EXAMPLE
      PS C:\> Convert-FromSecurityComplianceToolkit -Output "C:\Temp\SCT" -Verbose
   #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string] $Output = $(Join-Path -Path "." -ChildPath $(Get-Date -Format "yyyyMMddHHmmss"))
    )

    #region Downloading the Microsoft Security Compliance Toolkit webpage content and extracting all download links from it
    $MicrosoftSecurityComplianceToolkitDownloadURI = "https://www.microsoft.com/en-us/download/details.aspx?id=55319"
    $Content = Invoke-RestMethod -Uri $MicrosoftSecurityComplianceToolkitDownloadURI
    if ($Content -match '"downloadFile":(?<JSON>\[[^]]+\])') {
        #Extracting JSON part from the webpage content and converting it to a PowerShell object
        $SCTFileData = ($Matches['JSON'] | ConvertFrom-Json) | Select-Object -Property @{Name = "SKU"; Expression = { $_.Name -replace "\..*" } }, * | Group-Object -Property SKU -AsHashtable -AsString
        Write-Verbose -Message "`$SCTFileData: $($SCTFileData | Out-String)"
    }
    else {
        Write-Error -Message "Cannot find download links on '$MicrosoftSecurityComplianceToolkitDownloadURI' webpage." -ErrorAction Stop
    }

    #Filtering only Windows Server baselines: For testing purposes
    #$SCTFileData = $SCTFileData.Values | Where-Object -FilterScript { $_.SKU -match "Server \d{4}" } | ForEach-Object -Process { $_ }  | Group-Object -Property SKU -AsHashtable -AsString
    #endregion
    
    #region Variable Definition
    #Creating subdirectories under the Output root directory
    $DSCRootDirectory = Join-Path -Path $Output -ChildPath "DSCConfigurations"
    $ExtractedBaselineDirectory = Join-Path -Path $Output -ChildPath "SCTFiles"
    $BaselineDirectory = Join-Path -Path $Output -ChildPath "SCTFiles"
    #endregion

    #Creating required directories
    $null = New-Item -Path $Output, $DSCRootDirectory, $ExtractedBaselineDirectory, $BaselineDirectory -ItemType Directory -Force

    $BaselineIndex = 0
    $RepairStatuses = @()
    foreach ($Baseline in $SCTFileData.Keys) {
        $BaselineIndex++
        $PercentComplete = ($BaselineIndex / $SCTFileData.Keys.Count * 100)
        Write-Verbose -Message "`$PercentComplete: $PercentComplete"
        Write-Progress -Id 1 -Activity "[$BaselineIndex/$($SCTFileData.Keys.Count)] Processing '$Baseline' Baseline ..." -Status $("{0:N0} %" -f $PercentComplete) -PercentComplete $PercentComplete
        Write-Host -Object "`r`nProcessing '$Baseline' Baseline ..."
        #Replacing %20 in the filename with _ to avoid issues
        $ConfigurationScript = Join-Path -Path $BaselineDirectory -ChildPath $((Split-Path -Path $SCTFileData[$Baseline].url -Leaf) -replace "%20", "_")
        Write-Verbose -Message "`$ConfigurationScript: $ConfigurationScript"
        #Geeting the download link for the current baseline
        $Source = $SCTFileData[$Baseline].url
        Write-Verbose -Message "`$Source: $Source"
        #Downloading the baseline file (zip file)
        Start-BitsTransfer -Source $Source -Destination $ConfigurationScript
        #Folder where we will extract the baseline 
        $ConfigurationScriptPath = Join-Path -Path $ExtractedBaselineDirectory -ChildPath $Baseline
        Write-Verbose -Message "`$ConfigurationScriptPath: $ConfigurationScriptPath"
        #Extracting the baseline zip file
        Expand-Archive -Path $ConfigurationScript -DestinationPath $ConfigurationScriptPath
        #Getting the GPOs folder path
        $GPODir = (Get-ChildItem -Path $ConfigurationScriptPath -Filter "GPOs" -Recurse -Directory).FullName
        Write-Verbose -Message "`$GPODir: $GPODir"

        if ($GPODir) {

            #Directory where the converted DSC configuration scripts will be stored
            $DSCOSDirectory = Join-Path -Path $DSCRootDirectory -ChildPath $Baseline
            Write-Verbose -Message "`$DSCOSDirectory: $DSCOSDirectory"
        
            $GPOIndex = 0
            $GPODirs = (Get-ChildItem -Path $GPODir -Directory)
            foreach ($CurrentGPODir in $GPODirs) {
                $GPOIndex++

                Write-Verbose -Message "`$CurrentGPODir: $CurrentGPODir"
                #Extracting GPO name from the bkupInfo.xml file
                if ((Get-Content -Path "$($CurrentGPODir)\bkupInfo.xml" -Raw) -match "<GPODisplayName><!\[CDATA\[(.+)\]\]></GPODisplayName>") {
                    $GPOName = $Matches[1] -replace '\W+', '_'
                    Write-Verbose -Message "`$GPOName: $GPOName"
                }
                else {
                    Write-Warning -Message "Cannot find GPO name in '$($CurrentGPODir)\bkupInfo.xml'. Skipping this GPO Directory."
                    continue
                }
                Write-Host -Object "- Processing '$GPOName' GPO ..."
                $PercentComplete = ($GPOIndex / $GPODirs.Count * 100)
                Write-Verbose -Message "`$PercentComplete: $PercentComplete"
                Write-Progress -Id 2 -Activity "[$GPOIndex/$($GPODirs.Count)] Processing '$GPOName' GPO ..." -Status $("{0:N0} %" -f $PercentComplete) -PercentComplete $PercentComplete
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
                $Attempts = 0
                $AttemptLimit = 5
                $Success = $false
                Do {
                    $Attempts++
                    try {
                        #Conversion of the GPO to DSC configuration script
                        $ConvertedGpo = ConvertFrom-GPO -Path $CurrentGPODir -OutputConfigurationScript -OutputPath $DSCGPODirectory -ConfigName $GPOName -ErrorAction Stop 2>$null
                        Write-Host -Object " - Successfully converted '$GPOName' GPO to DSC."
                        Write-Verbose -Message "`$ConvertedGpo: $($ConvertedGpo | Out-String)"
                        $Success = $true
                    }
                    catch {
                        $Success = $false
                        #Handling errors during conversion
                        if ($Error[1].ErrorDetails.Message -match "Invalid MOF definition") {
                            $ConfigurationScript = Join-Path -Path $DSCGPODirectory -ChildPath "$GPOName.ps1"
                            Write-Warning -Message "- In '$ConfigurationScript' comment setting that contains property mentioned in this error:`r`n'$($Error[1].ErrorDetails.Message)'.`r`nOtherwise you will not be able to generate guest configuration from it!"
                            #Trying to extract the property name from the error message
                            if ($Error[1].ErrorDetails.Message -match "property\s+'(\w*)'\s") {
                                $Property = $Matches[1]
                                Write-Verbose -Message "`$Property: $Property"
                                # Define the regex pattern to match everything until the next }, including new lines for the faulty property
                                $Pattern = "([^\r\n]+$Property[^\}]+\})"
                        
                                # Use regex to find all matches
                                $FileContent = Get-Content -Path $ConfigurationScript -Raw
                                $MyMatches = [regex]::Matches($FileContent, $Pattern)
                                if ($MyMatches) {
                                    #Fixing the configuration script by commenting the faulty setting
                                    [regex]::Replace($FileContent, $Pattern, "<# Fixed by '$($MyInvocation.MyCommand)'`r`n`$1`r`n#>") | Set-Content -Path $ConfigurationScript
                                    $Message = "Commenting setting that contains property '$Property' in '$ConfigurationScript'."
                                    Write-Warning -Message $Message
                                    #Removing the faulty localhost.mof.error file if exists
                                    $null = Get-ChildItem -Path $DSCGPODirectory -Filter localhost.mof.error |  Remove-Item -ErrorAction Ignore -Force
                                    #Recalling the Configuration Script after fixing it (for generating a valid localhost.mof file)
                                    & $ConfigurationScript | Out-Null
                                    #Testing if the localhost.mof file has been successfully created
                                    if (Test-Path -Path $(Join-Path -Path $DSCGPODirectory -ChildPath localhost.mof) -PathType Leaf) {
                                        Write-Host -Message " - Repair successful!" -ForegroundColor Green
                                        $RepairStatuses += [PSCustomObject]@{FullName = $ConfigurationScript; Tye = "Success"; Message = "Commented setting that contains property '$Property'" }
                                        $Success = $true
                                    }
                                    else {
                                        Write-Warning -Message " - Repair failed!"
                                        $RepairStatuses += [PSCustomObject]@{FullName = $ConfigurationScript; Tye = "Failure"; Message = $Error[1].ErrorDetails.Message }
                                    }
                                }
                            }
                            else {
                                Write-Warning "Cannot find property name in error message: '$($Error[1].ErrorDetails.Message)'."
                            }
                        }
                        else {
                            $Message = $_.Exception.Message
                            #Trying to extract the problematic file and entry from the error message
                            if ($Message -match "^.*\s(?<file>\S*)\sfile.*'(?<entry>.*)'.*unknown value.*$") {
                                $File = $Matches['file']
                                $Entry = $Matches['entry']
                                Write-Verbose -Message "`$File: $File"
                                Write-Verbose -Message "`$Entry: $Entry"
                                Get-ChildItem -Path $CurrentGPODir -Filter $File -File -Recurse | ForEach-Object {
                                    Write-Verbose -Message "`Fixing error by removing the problematic '$Entry' entry in the '$($_.FullName)' file"
                                    $Pattern = "(^{0}.*$)" -f ($Entry -replace "(\W)", "\\$1")
                                    #(Get-Content -Path $_.FullName) -replace $Pattern, '#$1' | Set-Content -Path $_.FullName
                                    #Removing the problematic entry by replacing it with an empty string
                                    (Get-Content -Path $_.FullName) -replace $Pattern | Set-Content -Path $_.FullName
                                    $Message = "Removing entry '$Entry' in '$($_.FullName)'."
                                    Write-Verbose -Message $Message
                                }   
                            }
                            else {
                                Write-Warning -Message "Cannot find problematic file and entry in error message: '$Message'."
                            }
                        }
                    }
                } While ((-not($Success)) -and ($Attempts -lt $AttemptLimit))
                if ((-not($Success)) -or ($Attempts -gt $AttemptLimit)) {
                    Write-Error -Message "'$GPOName' GPO could not be converted properly after $AttemptLimit attempts"
                    $RepairStatuses += [PSCustomObject]@{FullName = $ConfigurationScript; Tye = "Failure"; Message = "'$GPOName' GPO could not be converted properly after $AttemptLimit attempts" }
                }
            }
            Write-Progress -Id 2 -Completed -Activity 'GPO processing completed.'
        }
        else {
            Write-Warning -Message "Cannot find GPOs folder in '$ConfigurationScriptPath'. Skipping this Baseline."
        }
    }
    Write-Progress -Id 1 -Completed -Activity 'Baseline processing completed.'
    if (Get-ChildItem -Path $Output -Recurse -Filter localhost.mof.error -File) {
        Write-Warning -Message "Some localhost.mof.error files have been found (despite auto-repair process). Please check them and fix the corresponding configuration scripts."
    }
    return $RepairStatuses
}

#endregion

#region Main Code
Clear-Host
$Error.Clear()

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir 

#$RepairStatuses = Convert-FromSecurityComplianceToolkit -Output "C:\Temp\SCT" -Verbose
$RepairStatuses = Convert-FromSecurityComplianceToolkit #-Verbose
$RepairStatuses | Format-List -Property *
#endregion
