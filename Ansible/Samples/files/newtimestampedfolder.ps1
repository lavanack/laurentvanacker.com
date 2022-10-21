$TimeStamp = "{0:yyyyMMddHHmmss}" -f (Get-Date)
New-Item -Path $env:TEMP -Name $TimeStamp -ItemType Directory -Force