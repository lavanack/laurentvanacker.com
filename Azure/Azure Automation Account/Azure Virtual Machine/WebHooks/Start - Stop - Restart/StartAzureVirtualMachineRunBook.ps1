<#
.SYNOPSIS
    Azure Automation runbook to start Azure Virtual Machines via webhook

.DESCRIPTION
    This runbook starts one or more Azure Virtual Machines based on data received from a webhook.
    The runbook uses the system-assigned managed identity of the Azure Automation Account to
    authenticate with Azure and perform VM operations.

.PARAMETER WebhookData
    The webhook data object containing the request body with VM information.
    Expected JSON format in RequestBody:
    [
        {
            "ResourceGroupName": "rg-name",
            "Name": "vm-name"
            "Action": "start|stop|restart"
        }
    ]

.INPUTS
    Webhook data with JSON payload containing VM resource group and name information

.OUTPUTS
    Status messages and job information for VM start operations

.EXAMPLE
    # Webhook payload example:
    [
        {
            "ResourceGroupName": "rg-production",
            "Name": "vm-webserver-01"
            "Action": "stop"
        },
        {
            "ResourceGroupName": "rg-production", 
            "Name": "vm-database-01"
            "Action": "restart"
        }
        {
            "ResourceGroupName": "rg-production", 
            "Name": "vm-middle-01"
            "Action": "start"
        }
    ]

.NOTES
    Author: Laurent Vanacker
    Version: 2.0
    Created: 2025-10-13
    
    Requirements:
    - Azure Automation Account with system-assigned managed identity enabled
    - Managed identity must have "Virtual Machine Contributor" role on target VMs/Resource Groups
    - Az.Accounts and Az.Compute PowerShell modules must be available in the Automation Account
    
    Security Considerations:
    - Uses managed identity authentication (no stored credentials)
    - Webhook should be secured and access controlled
    - Consider implementing IP restrictions on webhook endpoint

.LINK
    https://docs.microsoft.com/en-us/azure/automation/automation-webhooks
    https://docs.microsoft.com/en-us/azure/automation/automation-security-overview
#>


#requires -Version 5.1 -Modules Az.Accounts, Az.Compute

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, HelpMessage = "Webhook data object containing VM information")]
    [ValidateNotNull()]
    [object] $WebhookData
)

#region Initialization and Input Validation

# Initialize error handling
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'
$VerbosePreference = 'Continue'

try {
    Write-Output "=== Azure VM Start Runbook Initiated ==="
    Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    Write-Output "Runbook: $($MyInvocation.MyCommand.Name)"
    
    # Log webhook data for debugging
    Write-Verbose "Object Type: $($WebhookData.GetType().FullName)"
    Write-Verbose "Webhook Data received: $($WebhookData | ConvertTo-Json -Depth 3 -Compress)"
    
    if (-not $WebhookData) {
        throw "No webhook data received. This runbook must be triggered via webhook."
    }

    Write-Output "Webhook Name: $($WebhookData.WebhookName)"
    Write-Verbose "Request Headers: $($WebhookData.RequestHeader | ConvertTo-Json -Compress)"
    
    # Handle test pane execution (when RequestBody is not present)
    if (-not $WebhookData.RequestBody) {
        Write-Warning "No RequestBody found. Assuming test pane execution - treating WebhookData as direct JSON input."
        $WebhookData = ConvertFrom-Json -InputObject $WebhookData
        Write-Verbose "Test pane data: $($WebhookData | ConvertTo-Json -Compress)"
    }
    
    #endregion

    #region Request Body Validation and Processing
    
    if ($WebhookData.RequestBody) {
        Write-Output "Processing webhook request body..."
        
        try {
            # Parse and validate VM data from request body
            $VMsToManage = ConvertFrom-Json -InputObject $WebhookData.RequestBody -ErrorAction Stop
            
            if (-not $VMsToManage -or $VMsToManage.Count -eq 0) {
                throw "Request body contains no VM data or is empty."
            }
            
            Write-Output "Found $($VMsToManage.Count) VM(s) to manage"
            
            # Validate required properties for each VM
            foreach ($vm in $VMsToManage) {
                if (-not $vm.ResourceGroupName -or -not $vm.Name -or -not $vm.Action) {
                    throw "Invalid VM data: Each VM must have 'ResourceGroupName', 'Name' and 'Action' properties. Received: $($vm | ConvertTo-Json -Compress)"
                }
                Write-Verbose "Validated VM: $($vm.Name) in resource group: $($vm.ResourceGroupName) with action: $($vm.action)"
            }
            
        }
        catch {
            Write-Error "Failed to parse or validate request body: $($_.Exception.Message)"
            throw
        }
        
        #region Azure Authentication and Context Setup
        
        Write-Output "Authenticating to Azure using managed identity..."
        
        try {
            # Disable context autosave to avoid conflicts
            $null = Disable-AzContextAutosave -Scope Process
            Write-Verbose "Disabled Az context autosave"
            
            # Connect using system-assigned managed identity
            $connectionResult = Connect-AzAccount -Identity -ErrorAction Stop
            Write-Output "Successfully authenticated using managed identity"
            Write-Verbose "Connection details: Account=$($connectionResult.Context.Account.Id), Subscription=$($connectionResult.Context.Subscription.Name)"
            
            # Set the Azure context
            $azureContext = Set-AzContext -Subscription $connectionResult.Context.Subscription -ErrorAction Stop
            Write-Output "Azure context set to subscription: $($azureContext.Subscription.Name) ($($azureContext.Subscription.Id))"
            
        }
        catch {
            Write-Error "Failed to authenticate to Azure: $($_.Exception.Message)"
            throw
        }
        
        #endregion
        
        #region VM Start Operations
        
        Write-Output "Initiating VM operations..."
        $startTime = Get-Date
        $jobs = @()
        $failedOperations = @()
        
        try {
            # Manage each VM asynchronously using background jobs
            foreach ($vm in $VMsToManage) {
                Write-Output "Queuing $($vm.Action) operation for VM: $($vm.Name) in resource group: $($vm.ResourceGroupName)"
                
                try {
                    # Verify VM exists before attempting to start
                    $azureVM = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -ErrorAction Stop
                    Write-Verbose "Found VM: $($azureVM.Name) (Status will be checked after start operation)"
                    
                    switch ($vm.Action) {
                        'start' {
                            # Start VM as background job                    
                            $job = $azureVM | Start-AzVM -AsJob -ErrorAction Stop
                            $jobs += $job
                            Write-Verbose "Stopped background job for VM: $($vm.Name) (Job ID: $($job.Id))"
                        }
                        'stop' {
                            # Stop VM as background job                    
                            $job = $azureVM | Stop-AzVM -AsJob -Force -ErrorAction Stop
                            $jobs += $job
                            Write-Verbose "Started background job for VM: $($vm.Name) (Job ID: $($job.Id))"
                        }
                        'restart' {
                            # Restart VM as background job                    
                            $job = $azureVM | Restart-AzVM -AsJob -ErrorAction Stop
                            $jobs += $job
                            Write-Verbose "Restarted background job for VM: $($vm.Name) (Job ID: $($job.Id))"
                        }
                        default {
                            Write-Warning -Message "Unknown $($vm.Action) action for VM: $($vm.Name) in resource group: $($vm.ResourceGroupName)"
                        }
                    }
                }
                catch {
                    $errorMsg = "Failed to '$($vm.Action)' VM '$($vm.Name)' in resource group '$($vm.ResourceGroupName)': $($_.Exception.Message)"
                    Write-Error $errorMsg
                    $failedOperations += @{
                        VM        = $vm
                        Error     = $_.Exception.Message
                        Timestamp = Get-Date
                    }
                }
            }
            
            if ($jobs.Count -eq 0) {
                throw "No VM operations were initiated successfully."
            }
            
            Write-Output "Started $($jobs.Count) background job(s). Waiting for completion..."
            
            # Display job status
            $jobSummary = $jobs | Select-Object Id, Name, State, PSBeginTime | Format-Table -AutoSize | Out-String
            Write-Verbose "Job Summary:`n$jobSummary"
            
            # Wait for all jobs to complete and collect results
            $jobResults = @()
            foreach ($job in $jobs) {
                try {
                    Write-Verbose "Waiting for job completion: $($job.Name) (ID: $($job.Id))"
                    $result = Receive-Job -Job $job -Wait -ErrorAction Stop
                    $jobResults += @{
                        JobName  = $job.Name
                        Status   = "Success"
                        Result   = $result
                        Duration = (Get-Date) - $job.PSBeginTime
                    }
                    Write-Output "✓ Successfully managed VM: $($job.Name.Split('_')[-1])"
                    
                }
                catch {
                    $jobResults += @{
                        JobName  = $job.Name
                        Status   = "Failed" 
                        Error    = $_.Exception.Message
                        Duration = (Get-Date) - $job.PSBeginTime
                    }
                    Write-Error "✗ Failed to manage VM via job '$($job.Name)': $($_.Exception.Message)"
                }
            }
            
            # Clean up jobs
            $jobs | Remove-Job -Force
            
        }
        catch {
            Write-Error "Critical error during VM manage operations: $($_.Exception.Message)"
            throw
        }
        
        #endregion
        
        #region Results Summary
        
        $endTime = Get-Date
        $totalDuration = $endTime - $startTime
        
        $successfulStarts = $jobResults | Where-Object { $_.Status -eq "Success" }
        $failedStarts = $jobResults | Where-Object { $_.Status -eq "Failed" }
        
        Write-Output "`n=== VM Start Operation Summary ==="
        Write-Output "Total VMs requested: $($VMsToManage.Count)"
        Write-Output "Successful starts: $($successfulStarts.Count)"
        Write-Output "Failed operations: $($failedStarts.Count + $failedOperations.Count)"
        Write-Output "Total duration: $($totalDuration.ToString('hh\:mm\:ss'))"
        Write-Output "Completion time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
        
        if ($successfulStarts.Count -gt 0) {
            $successfulVMNames = $successfulStarts | ForEach-Object { $_.JobName.Split('_')[-1] }
            Write-Output "Successfully started VMs: $($successfulVMNames -join ', ')"
        }
        
        if ($failedStarts.Count -gt 0 -or $failedOperations.Count -gt 0) {
            Write-Warning "Some VM start operations failed:"
            foreach ($failure in $failedStarts) {
                Write-Warning "  - Job $($failure.JobName): $($failure.Error)"
            }
            foreach ($failure in $failedOperations) {
                Write-Warning "  - VM $($failure.VM.Name): $($failure.Error)"
            }
        }
        
        #endregion
        
    }
    else {
        throw "Request body is empty or missing. Cannot process VM start request."
    }

}
catch {
    Write-Error "Runbook execution failed: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    throw
}
finally {
    Write-Output "=== Runbook Execution Completed ==="
    Write-Output "End time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
}