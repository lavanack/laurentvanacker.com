# MSIX

Table of content:

- [MSIX](#msix)
  - [Context](#context)
  - [Setup](#setup)
    - [Prerequisites](#prerequisites)
  - [Other Option](#other-option)

## Context

[MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) is a Windows app package format that provides a modern packaging experience to all Windows apps. The [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) package format preserves the functionality of existing app packages and/or install files in addition to enabling new, modern packaging and deployment features to Win32, WPF, and Windows Forms apps.

[MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) enables enterprises to stay current and ensure their applications are always up to date. It allows IT Pros and developers to deliver a user centric solution while still reducing the cost of ownership of application by reducing the need to repackage.

## Setup

[AutomatedLab](https://automatedlab.org) ([GitHub](https://github.com/AutomatedLab/AutomatedLab)) is a project that allows to set up lab and test environments on **Hyper-V** or **[Azure](https://portal.azure.com/)** with multiple products.

### Prerequisites

Run the [AutomatedLab - MSIX.ps1](AutomatedLab%20-%20MSIX.ps1) script (PowerShell 5.1 needed) wait for completion (~30 minutes).
After completion you'll have:

- a Domain Controller for the contoso.com domain: DC01.
- a Windows server for creating a MSIX package via the installed 'MSIX Packaging Tool': MSIX.

All Windows Servers are running 'Windows Server 2022 Datacenter (Desktop Experience)'. Credentials will be displayed at the end of the deployment process. Just connect via RDP to the MSIX server.

## Other Option

The [Azure Virtual Desktop (AVD) Landing Zone Accelerator](https://github.com/Azure/avdaccelerator) offers an alternative to deploy Azure VM with MSIX App Attach Tools **[here](https://github.com/Azure/avdaccelerator/blob/main/workload/bicep/brownfield/appAttachToolsVM)**
