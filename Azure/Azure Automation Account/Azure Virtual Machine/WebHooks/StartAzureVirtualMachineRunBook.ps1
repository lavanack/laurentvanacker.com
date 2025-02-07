#requires -Version 3.0 -Modules Az.Accounts, Az.Resources

Param(
    [Parameter(Mandatory = $true)]
    [object] $WebhookData
)

Write-Output -InputObject "Object Type : $($WebhookData.GetType())"
Write-Output -InputObject "Webhook Data: $WebhookData" 

if ($WebhookData) { 

    Write-Output -InputObject "Webhook Name  : $($WebhookData.WebhookName)" 
    Write-Output -InputObject "Request Body  : $($WebhookData.RequestBody)"
    Write-Output -InputObject "Request Header: $($WebhookData.RequestHeader)"

    #Logic to allow for testing in Test Pane
    if (-not($WebhookData.RequestBody) ) {
        $WebhookData = (ConvertFrom-Json -InputObject $WebhookData)
        Write-Output -InputObject "Testing Pane: $WebhookData"
    }

    if ($WebhookData.RequestBody) { 
        $VMs = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

        $Jobs = foreach ($CurrentVM in $VMs)
        {
            Get-AzVM -ResourceGroupName $CurrentVM.ResourceGroupName -Name $CurrentVM.Name | Start-AzVM -AsJob
        }
        $Jobs | Receive-Job -Wait #-AutoRemoveJob
        Write-Output -InputObject "Jobs: $($Jobs | Select-Object -Property Name, State | Out-String)"
        Write-Output -InputObject " All VMs have been started: $($VMs.Name -join ', ')"
    }
    else {
        Write-Output -InputObject "Hello World!"
    }
}