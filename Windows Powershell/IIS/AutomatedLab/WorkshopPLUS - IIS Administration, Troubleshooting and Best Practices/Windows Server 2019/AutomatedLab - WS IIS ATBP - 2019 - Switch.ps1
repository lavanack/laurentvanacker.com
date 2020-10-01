$LabName = 'IISWSPlus2019'
Get-VMSwitch -Name $LabName | Remove-VMSwitch -Force
New-VMSwitch -SwitchName $LabName -SwitchType Internal
$NetAdapter = Get-NetAdapter -Name "*$LabName*"
New-NetIPAddress -IPAddress 10.0.0.2 -PrefixLength 16 -InterfaceIndex $NetAdapter.ifIndex
