$Now = Get-Date
$TimeStamp = "{0:yyyyMMddHHmmss}.txt" -f $Now
New-Item -Path $env:SystemRoot -Name $TimeStamp -ItemType File -Force -Value "This file has been generated via Ansible Tower at $Now"