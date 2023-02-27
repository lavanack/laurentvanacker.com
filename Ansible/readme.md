# AutomatedLab and Red Hat Ansible Automation Platform
[AutomatedLab](https://automatedlab.org) ([GitHub](https://github.com/AutomatedLab/AutomatedLab)) is a project that allows to set up lab and test environments on **Hyper-V** or **[Azure](https://portal.azure.com/)** with multiple products


Table of content:
- [AutomatedLab and Red Hat Ansible Automation Platform](#automatedlab-and-red-hat-ansible-automation-platform)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  


## Prerequisites 

  * An [AutomatedLab](https://automatedlab.org) environment 
  * A trial subscription for Ansible Automation Platform: https://www.redhat.com/en/technologies/management/ansible/trial

## Setup

Run the [Ansible Tower.ps1](./AutomatedLab/AutomatedLab%20-%20Ansible%20Tower.ps1) script (PowerShell 5.1 needed) and enter your credentials for your  trial subscription for Ansible Automation Platform when needed and wait for completion (~2 hours).
After completion you'll have:
* a Domain controller: DC01
* a Git server: GIT01
* an IIS server for testing purpose: IIS01
* a Windows Server for testing purpose: WS01
* a Red Hat Enterprise Linux 8.6: RHEL01

All Windows Servers are running 'Windows Server 2022 Datacenter (Desktop Experience)' and credentials will be displayed a the end of the deployment process.