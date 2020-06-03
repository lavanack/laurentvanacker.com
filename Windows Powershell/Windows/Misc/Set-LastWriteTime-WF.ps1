#requires -version 3

workflow Set-LastWriteTime-WF {
    [CmdletBinding()]
    Param(
        [String[]]$Computers,
        [String]$FullName,
        [Datetime]$LastWriteTime
    )

    foreach -parallel($Computer in $Computers) {
        Set-ItemProperty -Path $FullName -Name LastWriteTime -Value $LastWriteTime -PSComputerName $Computer
    }
} 

Clear-Host
$Computers = '2012R2-MS', '2012R2-DC', 'WIN8-WS'
Set-LastWriteTime-WF -Computers $Computers -FullName 'C:\Windows\WindowsUpdate.log' -LastWriteTime $(Get-Date) -Verbose