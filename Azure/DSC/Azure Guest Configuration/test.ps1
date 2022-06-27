$VMSuffix                           = "ws2019"
$ResourcePrefixStart                     = "dscagc"
[string]$LatestVMName = (Get-AzVM).Name | Where-Object -FilterScript {$_ -match "^$ResourcePrefixStart(\d{3})$VMSuffix$" } | Sort-Object -Descending | Select-Object -First 1
if ($Matches)
{
    $index = "{0:D3}" -f (([int]($Matches[1])+1))
}
else
{
    #$index="{0:D3}" -f 1
    $index="001"
}
$ResourcePrefix 	= "{0}{1}" -f $ResourcePrefixStart, $index
$VMName 	        = "{0}{1}" -f $ResourcePrefix, $VMSuffix
$VMName 	       

=========================================
$VMSuffix                           = "ws2019"
$ResourcePrefixStart                     = "dscagc"

$env:COMPUTERNAME -match '\D+(\d{3})\D+'; 
$index=$Matches[1]
$ResourcePrefix 	= "{0}{1}" -f $ResourcePrefixStart, $index
$VMName 	        = "{0}{1}" -f $ResourcePrefix, $VMSuffix
$VMName 	       
