az login --use-device-code
$ResourceGroupName = "rg-avd-hp-np-ei-poc-mp-use2-356"
$ResourceGroup = Get-AzResourceGroup -ResourceGroupName $ResourceGroupName
$WorkspaceName = "loghpnpeipocmpuse2356"
$SubscriptionId = (Get-AzContext).Subscription.Id
$SendFromEmail = (Get-AzContext).Account.Id 
$SendToEmails = "lavanack@microsoft.com"
#region https://github.com/AzaryaShaulov/AVD/tree/main/AVD-AzAlerts
.\AVD-RBAC-Precheck.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -WorkspaceResourceGroupName $ResourceGroupName -RequireRoleAssignmentWrite
.\AVD-AzAlerts-Deploy-Alert-LogicApp.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -LogicAppName "AVD-alert-details" -Location $ResourceGroup.Location -WorkspaceName $WorkspaceName -WorkspaceResourceGroupName $ResourceGroupName -SendFromEmail $SendFromEmail -SendToEmails $SendToEmail -Office365ConnectionName "avd-alerts-office365"
.\AVD-Webhook-TestAlert.ps1 -ResourceGroup $ResourceGroupName -LogicAppName "AVD-alert-details"
#endregion

#region https://github.com/AzaryaShaulov/AVD/tree/main/AVD-SessionHost-Insights-Alerts
.\AVD-Insights-Alerts-Precheck.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
.\AVD-Insights-Alerts-Deploy-LogicApp.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -LogicAppName "AVD-Insights-Alert-Email" -Location $ResourceGroup.Location -WorkspaceName $WorkspaceName -WorkspaceResourceGroupName $ResourceGroupName -SendFromEmail $SendFromEmail -SendToEmail $SendToEmail
#endregion
