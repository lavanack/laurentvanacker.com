#requires -Version 3.0 -Modules Az.Accounts, Az.Resources
 #Modified version from https://luke.geek.nz/azure/turn-on-a-azure-virtual-machine-using-azure-automation/

Param(
  [Parameter(Mandatory = $true)]
  [String]
  $TagName,
  [Parameter(Mandatory = $true)]
  [String]
  $TagValue,
  [Parameter(Mandatory = $true)]
  [Boolean]
  $Shutdown
)

$CountryCode = 'FR'

$tDate =(Get-Date).ToUniversalTime()
$tz = [System.TimeZoneInfo]::FindSystemTimeZoneById("Romance Standard Time")
$Date  = [System.TimeZoneInfo]::ConvertTimeFromUtc($tDate, $tz)


$API = Get-AutomationVariable -Name AbstractApiKey
$Holiday = Invoke-WebRequest -Uri ('https://holidays.abstractapi.com/v1/?api_key={0}&country={1}&year={2}&month={3}&day={4}' -f $API, $CountryCode, $Date.Year, $Date.Month, $Date.Day) -UseBasicParsing

$Holidays = $Holiday.Content
$Holidays = $Holidays | ConvertFrom-Json

IF ($null -ne $Holidays.name) 
{
  Write-Output -InputObject ("Today is a holiday. The Holiday today is: {0}. The Azure Virtual Machine(s) won't be started." -f $Holidays.name)
}
ELSE 
{
  Write-Output -InputObject 'No holiday today. The Virtual Machine(s) will be started.'

  # Ensures you do not inherit an AzContext in your runbook
  Disable-AzContextAutosave -Scope Process
  # Connect to Azure with system-assigned managed identity (Azure Automation account, which has been given VM Start permissions)
  $AzureContext = (Connect-AzAccount -Identity).context
  Write-Output -InputObject $AzureContext
  # set and store context
  $AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext
  Write-Output -InputObject $AzureContext

  $vms = Get-AzResource -TagName $TagName -TagValue $TagValue -ResourceType 'Microsoft.Compute/virtualMachines' 

  Foreach ($vm in $vms) 
  {
    if ($Shutdown) 
    {
      Write-Output -InputObject "Stopping $($vm.Name)"        
      Stop-AzVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName -Force -AsJob
    }
    else 
    {
      Write-Output -InputObject "Starting $($vm.Name)"        
      Start-AzVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName -AsJob
    }
  }
}
