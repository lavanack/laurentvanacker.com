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

#From https://learn.microsoft.com/en-us/azure/virtual-machines/disks-benchmarks

#region Main code
Clear-Host
$Error.Clear()
$StartTime = Get-Date

$CurrentScript = $MyInvocation.MyCommand.Path
#Getting the current directory (where this script file resides)
$CurrentDir = Split-Path -Path $CurrentScript -Parent
Set-Location -Path $CurrentDir
$TimeStamp = Get-Date -Format 'yyyyMMddHHmmss'
#$DiskSPDUri = "https://aka.ms/getdiskspd"
$DiskSPDUri = "https://github.com/Microsoft/diskspd/releases/latest/download/DiskSpd.zip"
$DiskSPDZipDir = Join-Path -Path $env:Temp -ChildPath $TimeStamp
$DiskSPDZipFile = Join-Path -Path $DiskSPDZipDir -ChildPath (Split-Path -Path $DiskSPDUri -Leaf)

$null = New-Item -Path $DiskSPDZipDir -ItemType Directory -Force
Invoke-RestMethod -Uri $DiskSPDUri -OutFile $DiskSPDZipFile
Expand-Archive -Path $DiskSPDZipFile -Force -DestinationPath $DiskSPDZipDir

$DiskSPDZipExe = Get-ChildItem -Path $DiskSPDZipDir -Filter "diskspd.exe" -Recurse -File | Where-Object -FilterScript { $_.DirectoryName -match "amd64" }
#$DiskPerformance = "StandardSSD"
$DiskPerformance = "PremiumSSD"
$PerformanceCounters = @(
    '\Cache\*'
    '\Distributed Transaction Coordinator\*'
    '\LogicalDisk(*)\*' 
    '\Memory\*'
    '\Network Inspection System\*'
    '\Network Interface(*)\*'
    '\Paging File(*)\*'
    '\PhysicalDisk(*)\*'
    '\Process(*)\*'
    '\Processor Information(*)\*'
    '\Processor(*)\*' 
    '\Server\*'
    '\System\*'
    '\TCP\*'
    '\TCPv4\*'
    '\TCPv6\*'
)

$FixedDrives = (Get-Volume | Where-Object -FilterScript { $_.DriveLetter -ne $null -and $_.DriveType -eq 'Fixed'}) | Sort-Object -Property DriveLetter
#region Data Collection Setup
$Operation = "MixVDI"
#$DataCollectorSetName = "{0}-{1}-{2}-{3}" -f $env:COMPUTERNAME, $DiskPerformance, $Operation, $TimeStamp
$DataCollectorSetName = "{0}-{1}-{2}" -f $env:COMPUTERNAME, $DiskPerformance, $Operation
$BLGFile = Join-Path -Path $CurrentDir -ChildPath $("{0}_{1}_{2}_DiskPerformanceCounters" -f $env:COMPUTERNAME, $DiskPerformance, $Operation)
Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Creating '$DataCollectorSetName' Performance Data Collection ..."
$PerformanceCounterNames = "`"{0}`"" -f $($PerformanceCounters -join '" "')
#region Removing previoulsy existing Data Collector Set (if anay) 
logman stop $DataCollectorSetName | Out-Null
logman delete $DataCollectorSetName | Out-Null 
#endregion
#We run from a cmd session due to the $PerformanceCounterNames variable
Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "logman create counter $DataCollectorSetName -v mmddhhmm -o $BLGFile -f bin -rf 24:00:00 -si 00:00:15 -c $PerformanceCounterNames" -NoNewWindow -Wait
#endregion

#region Data Collection Start
Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting '$DataCollectorSetName' Performance Data Collection ..."
logman start $DataCollectorSetName 
#endregion

foreach ($CurrentFixedDriveLetter in $FixedDrives.DriveLetter) {

    #region Benchmarks
    #region TestFile
    $PerfTestsDir = "{0}:\PerfTests" -f $CurrentFixedDriveLetter
    $null = New-Item -Path $PerfTestsDir -ItemType Directory -Force
    $TestFile = Join-Path -Path $PerfTestsDir -ChildPath "testfile.dat"
    Write-Host -Object "Processing '$TestFile' ..."
    Remove-Item -Path $TestFile -Force -ErrorAction Ignore
    #endregion

    #region Disk Benchmark
    Push-Location -Path $DiskSPDZipExe.PSParentPath
    Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Starting '$Operation' Operation Disk Benchmark ..."
    $LogFile = Join-Path -Path $CurrentDir -ChildPath $("{0}_{1}_{2}_{3}.log" -f $env:COMPUTERNAME, $CurrentFixedDriveLetter, $DiskPerformance, $Operation)
    .\diskspd.exe -c20G -b4K -r -w20 -o8 -t4 -d120 -W30 -Sh -L $TestFile | Out-File $LogFile
    Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] '$Operation' Operation Disk Benchmark Stopped ..."
    Pop-Location
    Remove-Item -Path $TestFile -Force
    #endregion

    #endregion
}

#region Data Collection Stop and Delete
Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Stopping '$DataCollectorSetName' Performance Data Collection ..."
logman stop $DataCollectorSetName 
Write-Host "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")][$($MyInvocation.MyCommand)] Removing '$DataCollectorSetName' Performance Data Collection ..."
logman delete $DataCollectorSetName 
#endregion

#endregion

