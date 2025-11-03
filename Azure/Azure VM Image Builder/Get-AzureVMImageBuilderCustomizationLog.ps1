<#
.SYNOPSIS
    Downloads and analyzes Azure VM Image Builder customization logs for troubleshooting purposes.

.DESCRIPTION
    This script retrieves customization logs from Azure VM Image Builder template staging resource groups.
    It automatically discovers all Image Builder templates in the current subscription, downloads their
    customization.log files from the associated storage accounts, and optionally opens them for analysis.
    
    The script is particularly useful for troubleshooting Azure Virtual Desktop (AVD) custom image 
    templates and understanding the customization phase execution.

.PARAMETER Destination
    Specifies the destination folder where downloaded log files will be saved.
    Default value is the current directory ('.').

.PARAMETER TimeStamp
    When specified, adds a timestamp to the downloaded log file names to prevent overwriting
    and allow comparison between multiple runs. Format: yyyyMMddHHmmss

.EXAMPLE
    .\Get-AzureVMImageBuilderCustomizationLog.ps1
    
    Downloads all customization logs to the current directory, overwriting existing files.

.EXAMPLE
    .\Get-AzureVMImageBuilderCustomizationLog.ps1 -Destination "C:\Logs" -TimeStamp
    
    Downloads all customization logs to C:\Logs with timestamps in filenames.

.EXAMPLE
    .\Get-AzureVMImageBuilderCustomizationLog.ps1 -Destination ".\AIB-Logs" -TimeStamp -Verbose
    
    Downloads logs to AIB-Logs subfolder with detailed verbose output and timestamps.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String[]
    Returns an array of file paths for successfully downloaded customization log files.

.NOTES
    File Name      : Get-AzureVMImageBuilderCustomizationLog.ps1
    Author         : Laurent Vanacker
    Prerequisite   : PowerShell 5.0+, Az.Accounts, Az.Resources, Az.Storage modules
    
    This script requires:
    - Active Azure authentication (will prompt if not authenticated)
    - Reader access to Image Builder template resource groups
    - Reader access to staging resource groups and storage accounts
    
    The script will:
    1. Discover all Image Builder templates in the current subscription
    2. Identify staging resource groups for each template
    3. Download customization.log files from packerlogs containers
    4. Optionally timestamp files to prevent overwriting
    5. Open downloaded files with default application
    6. Search for key customization phases in the logs

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-custom-image-templates

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#customization-log

.COMPONENT
    Azure VM Image Builder

.FUNCTIONALITY
    Log Analysis, Troubleshooting, Azure Virtual Desktop

#>

<#
DISCLAIMER: This Sample Code is provided for the purpose of illustration only
and is not intended to be used in a production environment. THIS
SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free
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
    <#
    .SYNOPSIS
        Downloads Azure VM Image Builder customization logs from staging resource group storage accounts.

    .DESCRIPTION
        This function discovers all Azure VM Image Builder templates in the current subscription,
        identifies their associated staging resource groups, and downloads customization.log files
        from the packerlogs storage containers. Each template's logs are saved to separate folders
        for organization.

    .PARAMETER Destination
        The destination folder where log files will be downloaded. Creates subdirectories for each
        Image Builder template resource group. Default is current directory.

    .PARAMETER TimeStamp
        When specified, appends a timestamp (yyyyMMddHHmmss) to downloaded log filenames to prevent
        overwriting and enable comparison between different runs.

    .EXAMPLE
        Get-AzureVMImageBuilderCustomizationLog

        Downloads all customization logs to the current directory.

    .EXAMPLE
        Get-AzureVMImageBuilderCustomizationLog -Destination "C:\AIB-Logs" -TimeStamp

        Downloads logs to C:\AIB-Logs with timestamps in filenames.

    .OUTPUTS
        System.String[]
        Array of file paths for successfully downloaded customization log files.

    .NOTES
        - Requires active Azure authentication
        - Creates subdirectories named after staging resource groups
        - Removes empty directories if no logs are found
        - Uses verbose output to show processing details
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, HelpMessage = "Destination folder for downloaded log files")]
        [ValidateScript({
                if (Test-Path -Path $_ -PathType Container) { $true }
                elseif (Test-Path -Path (Split-Path -Path $_ -Parent)) { $true }
                else { throw "Parent directory '$_' does not exist" }
            })]
        [string]$Destination = '.',
        
        [Parameter(Mandatory = $false, HelpMessage = "Add timestamp to log filenames")]
        [switch]$TimeStamp
    )
    # Step 1: Discover all Image Builder templates and their staging resource groups
    Write-Verbose -Message "Discovering Azure VM Image Builder templates in current subscription..."
    $AzImageBuilderTemplateResourceGroup = Get-AzImageBuilderTemplate | ForEach-Object -Process { 
        Write-Verbose -Message "Getting Staging ResourceGroup for '$($_.Name)' Image Template ..."
        # Each Image Builder template has an associated staging resource group where logs are stored
        Get-AzResourceGroup -Id $_.StagingResourceGroup -ErrorAction Ignore
    }
    
    # Step 2: Process each staging resource group to download customization logs
    foreach ($CurrentAzImageBuilderTemplateResourceGroup in $AzImageBuilderTemplateResourceGroup) {
        Write-Verbose -Message "Processing '$($CurrentAzImageBuilderTemplateResourceGroup.ResourceGroupName)' Resource Group (Image Template: $($CurrentAzImageBuilderTemplateResourceGroup.Tags.imageTemplateName) / Resource Group: $($CurrentAzImageBuilderTemplateResourceGroup.Tags.imageTemplateResourceGroupName)) ..."
        
        # Step 3: Create a dedicated directory for each Image Builder template's logs
        $CurrentDestination = New-Item -Path $Destination -Name $CurrentAzImageBuilderTemplateResourceGroup.ResourceGroupName -ItemType Directory -Force
        
        # Step 4: Download customization.log from the packerlogs container
        # The staging resource group contains a storage account with a 'packerlogs' container
        try {
            Write-Verbose -Message "Attempting to download customization logs from storage account..."
            $AzStorageBlobContent = $CurrentAzImageBuilderTemplateResourceGroup | 
            Get-AzStorageAccount | 
            Get-AzStorageContainer -Name packerlogs | 
            Get-AzStorageBlob | 
            Get-AzStorageBlobContent -Destination $CurrentDestination -Force -Verbose 
            
            if ($null -ne $AzStorageBlobContent) {
                Write-Verbose -Message "Successfully downloaded: $($AzStorageBlobContent | Out-String)"
                
                # Step 5: Get the local path of the downloaded customization.log 
                $DestinationFile = Join-Path -Path $CurrentDestination -ChildPath $AzStorageBlobContent.Name
                
                # Step 6: Handle timestamping if requested
                if ($TimeStamp) {
                    # Add timestamp to filename to prevent overwriting and enable comparison
                    $Extension = (Get-Item -Path $DestinationFile).Extension
                    $TimeStampDestinationFile = $DestinationFile -replace "\$($Extension)$", $("_{0:yyyyMMddHHmmss}{1}" -f $(Get-Date), $Extension)
                    Rename-Item -Path $DestinationFile -NewName $TimeStampDestinationFile
                    Write-Verbose -Message "Timestamped file created: '$TimeStampDestinationFile'"
                    $TimeStampDestinationFile
                }
                else {
                    # Return the original file path (will be overwritten on subsequent runs)
                    Write-Verbose -Message "Log file saved to: '$DestinationFile'"
                    $DestinationFile
                }
            }
            else {
                # Step 7: Clean up empty directories if no logs were found
                Write-Verbose -Message "No customization.log file found - removing empty directory '$CurrentDestination'"
                $CurrentDestination | Remove-Item -Force
            }
        }
        catch {
            # Handle errors gracefully (e.g., storage account not accessible, container doesn't exist)
            Write-Warning -Message "Failed to download logs for '$($CurrentAzImageBuilderTemplateResourceGroup.ResourceGroupName)': $($_.Exception.Message)"
            # Clean up empty directory on error
            if (Test-Path -Path $CurrentDestination) {
                $CurrentDestination | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
#endregion

#region Main Script Execution
<#
    Main script logic:
    1. Initialize environment and ensure Azure authentication
    2. Download all available Image Builder customization logs
    3. Open logs for analysis and search for key customization phases
#>

# Initialize script environment
Clear-Host
$Error.Clear()

# Set working directory to script location for relative path operations
$CurrentScript = $MyInvocation.MyCommand.Path
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
Write-Verbose -Message "Script location: $CurrentDir"

#region Azure Authentication
# Ensure user is authenticated to Azure
# Loop until valid Azure access token is obtained
Write-Host "Checking Azure authentication..." -ForegroundColor Cyan
While (-not(Get-AzAccessToken -ErrorAction Ignore)) {
    Write-Host "Azure authentication required. Please sign in..." -ForegroundColor Yellow
    Connect-AzAccount
}
Write-Host "✓ Azure authentication confirmed" -ForegroundColor Green

# Display current Azure context for verification
$AzContext = Get-AzContext
Write-Host "Connected to subscription: $($AzContext.Subscription.Name) ($($AzContext.Subscription.Id))" -ForegroundColor Green
#endregion

#region Download and Process Logs
Write-Host "`nDownloading Azure VM Image Builder customization logs..." -ForegroundColor Cyan

try {
    # Download all available customization logs with timestamps enabled
    $CustomizationLog = Get-AzureVMImageBuilderCustomizationLog -Destination $CurrentDir -TimeStamp -Verbose
    
    if ($null -ne $CustomizationLog -and $CustomizationLog.Count -gt 0) {
        Write-Host "✓ Successfully downloaded $($CustomizationLog.Count) log file(s)" -ForegroundColor Green
        
        # Display downloaded log files
        Write-Host "`nDownloaded log files:" -ForegroundColor Cyan
        $CustomizationLog | ForEach-Object { Write-Host "  • $_" -ForegroundColor White }
        
        # Open log files with default application for immediate analysis
        Write-Host "`nOpening log files for analysis..." -ForegroundColor Cyan
        $CustomizationLog | ForEach-Object -Process { 
            try {
                & $_
                Write-Verbose -Message "Opened: $_"
            }
            catch {
                Write-Warning -Message "Could not open file: $_ ($($_.Exception.Message))"
            }
        }
        
        # Search for key customization phases in the logs
        Write-Host "`nSearching for customization phases..." -ForegroundColor Cyan
        $CustomizationPhases = Select-String -Pattern "Starting provisioner|Starting AVD AIB Customization|AVD AIB CUSTOMIZER PHASE" -Path $CustomizationLog -Context 1
        
        if ($CustomizationPhases) {
            Write-Host "✓ Found $($CustomizationPhases.Count) customization phase marker(s)" -ForegroundColor Green
            Write-Host "`nCustomization phases found:" -ForegroundColor Yellow
            $CustomizationPhases | ForEach-Object {
                Write-Host "  File: $($_.Filename)" -ForegroundColor Cyan
                Write-Host "  Line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor White
                if ($_.Context.PreContext) {
                    $_.Context.PreContext | ForEach-Object { Write-Host "    Context: $_" -ForegroundColor Gray }
                }
                Write-Host ""
            }
        }
        else {
            Write-Warning "No customization phase markers found in the log files"
        }
    }
    else {
        Write-Warning "No customization.log files found or processed"
        Write-Host "This could mean:" -ForegroundColor Yellow
        Write-Host "  • No Image Builder templates exist in the current subscription" -ForegroundColor Yellow
        Write-Host "  • Templates haven't been run yet" -ForegroundColor Yellow
        Write-Host "  • Staging resource groups or storage accounts are not accessible" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to process Image Builder logs: $($_.Exception.Message)"
    Write-Host "Please ensure you have:" -ForegroundColor Yellow
    Write-Host "  • Appropriate permissions to access Image Builder resources" -ForegroundColor Yellow
    Write-Host "  • Az.Accounts, Az.Resources, and Az.Storage modules installed" -ForegroundColor Yellow
}
#endregion

Write-Host "`nScript execution completed." -ForegroundColor Green
#endregion