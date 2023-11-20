# Azure Active Directory Hybrid Lab - PowerShell version

The [New-AAD-Hybrid-BCDR-Lab.ps1](https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell/New-AAD-Hybrid-BCDR-Lab.ps1) has the same functionality same that lab one available on [https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab) but in a full Powershell version  instead of using ARM templates.
The default values remain the same as the original version (ARM-based). Feel free to customize the values to your needs.

The [New-AAD-Hybrid-BCDR-Lab.ps1](https://github.com/lavanack/laurentvanacker.com/blob/master/Azure/Azure%20Virtual%20Desktop/AAD-Hybrid-Lab%20-%20PowerShell/New-AAD-Hybrid-BCDR-Lab.ps1) is for BCDR strategy for the domain controller(s) (an additional DC will deployed in an another Azure region - eastus2 by default. You just will have to confgure the AzureAD Connect in staging Mode) 
