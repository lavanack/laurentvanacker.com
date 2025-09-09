# Convert Microsoft Security Compliance baselines to Azure Machine Configuration packages

- [Convert Microsoft Security Compliance baselines to Azure Machine Configuration packages](#convert-microsoft-security-compliance-baselines-to-azure-machine-configuration-packages)
  - [Introduction](#introduction)
  - [Convert-FromSecurityComplianceToolkit.ps1](#convert-fromsecuritycompliancetoolkitps1)
  - [Next Steps](#next-steps)
  

## Introduction

When teaching about [Azure Machine Configuration](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/) to a customer of mine (in a security hardening context). I discovered this helpful [article](https://doitpshway.com/convert-ms-security-baselines-to-azure-arc-guest-configuration-packages) (Convert MS security baselines to Azure ARC Guest Configuration packages). I use it as a starting point to develop the [Convert-FromSecurityComplianceToolkit.ps1](Convert-FromSecurityComplianceToolkit.ps1) script.

## Convert-FromSecurityComplianceToolkit.ps1
This script download all the tools from the [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319) page and convert every GPO into a dedicated DSC configuration script. A dedicated timestamped (yyyyMMddHHmmss) output folder will be created in the script folder if the Output parameter is not specified.  

> [!Note]
> As explained in the [article](https://doitpshway.com/convert-ms-security-baselines-to-azure-arc-guest-configuration-packages):
> 
> !BEWARE! creating of some localhost.mof can (probably will) end with an error https://github.com/microsoft/BaselineManagement?tab=readme-ov-file#known-gaps-in-capability
> problematic ps1 parts have to be commented otherwise you will not be able to create DSC from it!
> 
> **I solved this by using some regular expressions to solve this problme by removing or commenting the faulty parts. At the end of the script a list of these modifications are displayed as shown below**
>
> ![Auto Fixes](docs/autofixes.jpg)
>
> I also attached a [zip](20250909083044.zip) file with a sample run.

## Next Steps
If you want to learn more about [Azure Machine Configuration](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/),  transform the generated DSC Configurations scripts into [Azure Machine Configuration](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/) scripts or run some proposed demos you can take a look to my dedicated [folder](https://github.com/lavanack/laurentvanacker.com/tree/master/Azure/Desired%20State%20Configuration/Azure%20Machine%20Configuration)
