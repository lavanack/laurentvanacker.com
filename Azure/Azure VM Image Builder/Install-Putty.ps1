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
product in which the Sample Code is embedded; (ii) to include a valid<
copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and
Our suppliers from and against any claims or lawsuits, including
attorneys' fees, that arise or result from the use or distribution
of the Sample Code.
#>
#Installing Putty

#region Downloading Putty 
$DestinationFolderPath = "C:\Tools"
$DestinationFolder = New-Item -Path $DestinationFolderPath -ItemType Directory -Force
$PuttyUri = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"
$Outfile = Join-Path -Path $DestinationFolder -ChildPath $(Split-Path -Path $PuttyUri -Leaf)
If (-not(Test-Path -Path $Outfile)) {
    Write-Verbose -Message "Downloading Putty ..."
    Invoke-WebRequest -Uri $PuttyUri -UseBasicParsing -OutFile $Outfile -Verbose
}
#endregion 
