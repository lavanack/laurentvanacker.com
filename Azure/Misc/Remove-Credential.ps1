Clear-Host
$AzureCredentials = cmdkey /list | Select-string -Pattern "=(TERMSRV/)?((.*)\.(.*)\.cloudapp\.azure\.com)" -AllMatches
if ($AzureCredentials.Matches)
{
    $AzureCredentials.Matches | ForEach-Object -Process { 
        $DNSName = $_.Groups[2].Value
        $VMName = $_.Groups[3].Value
        $Location = $_.Groups[4].Value
        $AzVM = Get-AzVM -Name $VMName 
        if (($AzVM) -and ($AzVM.Location -eq $Location))
        {
            Write-Host -Object "$VMName Azure VM exists" -ForegroundColor Green
        }
        else
        {
            Write-Warning -Message "$VMName Azure VM doesn't exist. The related credentials will be removed from the Windows Credential Manager"
            Start-Process -FilePath "$env:comspec" -ArgumentList "/c", "cmdkey /delete:$DNSName" -Wait
        }
    }
}
