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

#requires -Version 5.1 -Modules Az.Accounts, Az.Compute

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true, HelpMessage = "Webhook data object containing VM information")]
    [ValidateNotNull()]
    [object] $WebhookData
)

#region Initialization and Input Validation
$LogAnalyticsWorkspaceId = Get-AutomationVariable -Name LogAnalyticsWorkspaceId

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

    
    if ($WebhookData.RequestBody) {
        throw "Request body is empty or missing. Cannot process VM request."
    }
    else {
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
        
        #region User Check
        Write-Output "Processing webhook request body..."
        
        try {
            # Parse and validate VM data from request body
            $Users = ConvertFrom-Json -InputObject $WebhookData.RequestBody -ErrorAction Stop
            
            if (-not $Users -or $Users.Count -eq 0) {
                throw "Request body contains no User data or is empty."
            }
            
            Write-Output "Found $($Users.Count) User(s) to manage"
            
            # Validate required properties for each VM
            foreach ($User in $Users) {
                
                $AzADUser = Get-AzADUser -UserPrincipalName $User -ErrorAction SilentlyContinue
                if (-not $AzADUser) {
                    throw "Invalid User data: '$User' not found in EntraID. Received: $($User | ConvertTo-Json -Compress)"
                }
                Write-Verbose "Validated User: $User"
            }
            
        }
        catch {
            Write-Error "Failed to parse or validate request body: $($_.Exception.Message)"
            throw
        }
        #endregion

        #region LAW 
        $VMs = foreach ($User in $Users) {
            Write-Output -InputObject "`$LogAnalyticsWorkspaceId: $LogAnalyticsWorkspaceId"
            #Last Connected AVD Session Host
            $Query = @"
WVDConnections
| extend Localtime = datetime_utc_to_local(TimeGenerated, "Europe/Paris")
| where UserName contains "$User" and State contains "Started"
| sort by TimeGenerated desc
| take 1
| project SessionHostName
"@

            Write-Output -InputObject "`$Query: $Query"
            # Run the query
            $Result = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspaceId -Query $Query
            #Keeping only the Netbios name (vm.contoso.com ==> vm)
            $VMName = $Result.Results.SessionHostName -replace "\..*"
            Write-Output -InputObject "`$VMName: $VMName)"                
            $VM = Get-AzVM -Name $VMName -Status
            if ($VM) {
                Write-Verbose "Found VM: $($VM.Name) in resource group: $($VM.ResourceGroupName)"
                $VM
            }
            else {
                Write-Warning "No VM found for '$User' User."
            }
        }
        #endregion

        #region VM Operations
        
        Write-Output "Initiating VM restarts..."
        $startTime = Get-Date
        $jobs = @()
        $failedOperations = @()
        

        try {
            # Manage each VM asynchronously using background jobs
            $jobs = foreach ($VM in $VMs) {
                Write-Output "Queuing restart/start operation for VM: $($VM.Name) in resource group: $($VM.ResourceGroupName)"
                
                try {
                    Write-Verbose "VM Power State: $($VM.PowerState))"
                    if ($VM.PowerState -match "running") {
                            $VM | Restart-AzVM -AsJob -ErrorAction Stop
                            Write-Verbose "Started background job for VM: $($VM.Name) (Action: Restart) (Job ID: $($job.Id))"
                    }
                    else {
                            $VM | Start-AzVM -AsJob -ErrorAction Stop
                            Write-Verbose "Started background job for VM: $($VM.Name) (Action: Start) (Job ID: $($job.Id))"
                    }
                }
                catch {
                    $errorMsg = "Failed to start/restart VM '$($VM.Name)' in resource group '$($VM.ResourceGroupName)': $($_.Exception.Message)"
                    Write-Error $errorMsg
                    $failedOperations += [PSCustomObject]@{
                        VM        = $VM
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
                    $jobResults += [PSCustomObject]@{
                        JobName  = $job.Name
                        Status   = "Success"
                        Result   = $result
                        Duration = (Get-Date) - $job.PSBeginTime
                    }
                    Write-Output "✓ Successfully managed VM: $($job.Name.Split('_')[-1])"
                    
                }
                catch {
                    $jobResults += [PSCustomObject]@{
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
        
        $successfulJobs = $jobResults | Where-Object { $_.Status -eq "Success" }
        $failedJobs = $jobResults | Where-Object { $_.Status -eq "Failed" }
        
        Write-Output "`n=== VM Start Operation Summary ==="
        Write-Output "Total VMs requested: $($Users.Count)"
        Write-Output "Successful operations: $($successfulJobs.Count)"
        Write-Output "Failed operations: $($failedJobs.Count + $failedOperations.Count)"
        Write-Output "Total duration: $($totalDuration.ToString('hh\:mm\:ss'))"
        Write-Output "Completion time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
        
        if ($successfulJobs.Count -gt 0) {
            $successfulVMNames = $successfulJobs | ForEach-Object { $_.JobName.Split('_')[-1] }
            Write-Output "Successfully started VMs: $($successfulVMNames -join ', ')"
        }
        
        if ($failedJobs.Count -gt 0 -or $failedOperations.Count -gt 0) {
            Write-Warning "Some VM start operations failed:"
            foreach ($failure in $failedJobs) {
                Write-Warning "  - Job $($failure.JobName): $($failure.Error)"
            }
            foreach ($failure in $failedOperations) {
                Write-Warning "  - VM $($failure.VM.Name): $($failure.Error)"
            }
        }
        
        #endregion
        
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