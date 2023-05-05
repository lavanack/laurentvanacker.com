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
#requires -version 3
Clear-Host
$CurrentDir=Split-Path $MyInvocation.MyCommand.Path
$OutputCSVFile = Join-Path -Path $CurrentDir -ChildPath $("ArrayVsArrayList.csv")

$Results = New-Object -TypeName 'System.Collections.ArrayList';
$Limit = 100000
for($index=0; $index -le $Limit; $index+=100)
{
    Write-Progress -Activity "Processing $Index" -Status "Progress: $($index/$Limit*100) %" -PercentComplete ($index/$Limit*100)
    $ArrayList = New-Object -TypeName 'System.Collections.ArrayList';
    $Array = @();
    $ArrayListTime = Measure-Command {
         for($i = 0; $i -lt $index; $i++)
         {
            $null = $ArrayList.Add("Adding $i")
         }
    };


    $ArrayTime = Measure-Command {
        for($i = 0; $i -lt $index; $i++)
        {
            $Array += "Adding $i"
        }
     };
     $Time = [pscustomobject][ordered] @{ Index = $Index; ArrayListTime = $ArrayListTime.Ticks; ArrayTime = $ArrayTime.Ticks; Delta = "{0:p}" -f (($ArrayTime.Ticks-$ArrayListTime.Ticks)/($ArrayListTime.Ticks))}
     $null = $Results.Add($Time)
     #$Time
}
$Results| Export-Csv -Path $OutputCSVFile -NoTypeInformation
Write-Host -Object "[INFO] Data have been exported to '$OutputCSVFile'"
