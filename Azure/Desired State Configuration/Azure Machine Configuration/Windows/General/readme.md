# Azure Machine Configuration

[![Azure](https://img.shields.io/badge/Azure-Machine%20Configuration-0078d4?logo=microsoft-azure&logoColor=white)](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207.X-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![DSC](https://img.shields.io/badge/DSC-Desired%20State%20Configuration-00BCF2?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/dsc/)

> **Automated Azure VM deployment with comprehensive DSC configurations for security and compliance management**

## 📋 Overview

This project provides a comprehensive solution for deploying and configuring Azure Virtual Machines with Azure Machine Configuration (formerly Guest Configuration). The solution includes automated VM deployment, prerequisite installation, and multiple DSC configurations for security hardening and compliance management.

### 🚀 Quick Start

1. **Deploy Azure VM**: Run [`1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1`](1%20-%20AzureVMWithAzureAutomanageMachineConfiguration.ps1)
2. **Install Prerequisites**: Execute [`2 - Prerequisites.ps1`](2%20-%20Prerequisites.ps1) on the VM
3. **Apply Configurations**: Run [`3 - AzureAutomanageMachineConfigurationWithSASToken.ps1`](3%20-%AzureAutomanageMachineConfigurationWithSASToken.ps1) or [`3 - AzureAutomanageMachineConfigurationWithSystemAssignedIdentity.ps1`](3%20-%AzureAutomanageMachineConfigurationWithSystemAssignedIdentity.ps1). The difference is the way to access to the Storage Account (Storage Account Key vs. System Assigned Identity : More details [here](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition))

## 🔧 DSC Configurations

The following Desired State Configuration scripts are included for comprehensive system hardening:

### Security Configurations

- **[Rogue Administrator Creation](CreateAdminUserDSCConfiguration.ps1)** - Creates an administrative account for testing

![Rogue Admin](docs/rogueadmin.jpg)

- **[Audit Policy Configuration](AdvancedAuditPolicyDSCConfiguration.ps1)** - Configures advanced audit policies

![Audit Policy Configuration](docs/auditpol.jpg)

### Additional Configurations

- **[Certificate Import](CertificateImportDSCConfiguration.ps1)** - Manages certificate deployment
- **[SMBv1 Disabling](DisableSMBv1DSCConfiguration.ps1)** - Disables legacy SMBv1 protocol
- **[SMB Signing](EnableSMBSigningDSCConfiguration.ps1)** - Enables SMB signing for security
- **[Log Parser Setup](LogParserSetupDSCConfiguration.ps1)** - Configures log parsing tools
- **[TLS Hardening](TLSHardeningDSCConfiguration.ps1)** - Implements TLS security hardening

## 📋 Table of Contents

- [Overview](#-overview)
- [DSC Configurations](#-dsc-configurations)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration Options](#-configuration-options)
- [Security Features](#-security-features)
- [Troubleshooting](#-troubleshooting)

## 🔧 Prerequisites

### Required Resources

- **Azure Subscription** - Active [Azure subscription](https://portal.azure.com) with appropriate permissions
- **PowerShell 5.1+** - Required for initial deployment script
- **Azure PowerShell Module** - For Azure resource management

### Permissions Required

- **Contributor** access to the target Azure subscription
- **User Access Administrator** (for role assignments)
- **Resource Group** creation permissions

## 🚀 Installation & Setup

### Step 1: Deploy Azure VM

Run the deployment script from your local machine:

```powershell
.\1 - AzureVMWithAzureAutomanageMachineConfiguration.ps1
```

**Duration**: ~10 minutes  
**Requirements**: PowerShell 5.1, Azure connection

### Step 2: Install Prerequisites on VM

1. Copy the 'Azure Machine Configuration' folder to the Azure VM
2. Navigate to the 'Windows' subfolder
3. Run the prerequisites script:

```powershell
.\2 - Prerequisites.ps1
```

**Installs**:
- PowerShell modules
- PowerShell 7+
- Visual Studio Code
- Required dependencies

### Step 3: Apply DSC Configurations

Choose one of the following approaches:

#### Option A: SAS Token Authentication

```powershell
.\3 - AzureAutomanageMachineConfigurationWithSASToken.ps1
```

#### Option B: System Assigned Identity

```powershell
.\3 - AzureAutomanageMachineConfigurationWithSystemAssignedIdentity.ps1
```

> **Note**: System Assigned Identity is the recommended approach for production environments. More details: [Azure Policy Definition Guide](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/create-policy-definition#create-an-azure-policy-definition)

## ⚙️ Configuration Options

### Virtual Machine Specifications

| Setting           | Default Value                                                                               | Customizable  |
| ----------------- | ------------------------------------------------------------------------------------------- | ------------- |
| **OS**            | Windows Server 2022 Datacenter (Desktop Experience)                                         | ✅ (Line ~389) |
| **Generation**    | Generation 2                                                                                | ✅ (Line ~389) |
| **VM Size**       | [Standard_D4s_v5](https://learn.microsoft.com/en-us/azure/virtual-machines/dv5-dsv5-series) | ✅ (Line ~330) |
| **Region**        | East US 2                                                                                   | ✅ (Line ~329) |
| **Instance Type** | [Spot Instance](https://learn.microsoft.com/en-us/azure/virtual-machines/spot-vms)          | ✅ (Line ~185) |

### Network Configuration

- **RDP Access**: Restricted to deployment IP only
- **HTTP/HTTPS**: Open to internet (ports 80/443)
- **DNS Name**: `<VMName>.<Location>.cloudapp.azure.com`
- **Just-in-Time Access**: 3-hour policy enabled

### Cost Optimization

- **Spot Instance**: Enabled by default with 'Deallocate' eviction policy
- **Auto-shutdown**: Daily at 11:00 PM (local timezone)
- **Region**: Use [CloudPrice.net](https://cloudprice.net) for cost comparison

## 🔐 Security Features

### Authentication & Access

- **Randomized Credentials**: Auto-generated secure passwords
- **Current User Account**: Uses your Windows username
- **Credential Manager**: Automatic credential storage
- **JIT Access**: Just-in-time RDP access policies

![JIT Access](docs/jit.jpg)

### Network Security

- **Network Security Groups**: IP-restricted RDP access
- **Public IP Protection**: DNS name used instead of direct IP
- **Firewall Rules**: Minimal required port exposure

![Network Security Group](docs/nsg.jpg)

### Automated Hardening

The DSC configurations provide:

- ✅ **Account Management**: Controlled admin account creation
- ✅ **Audit Policies**: Comprehensive logging configuration  
- ✅ **Protocol Security**: SMBv1 disabled, SMB signing enabled
- ✅ **Encryption**: TLS hardening and certificate management
- ✅ **Monitoring**: Log parser and analysis tools

## 🛠️ Troubleshooting

### Common Issues

#### Authentication Problems

**Issue**: Azure connection failures
**Solution**: Ensure you're connected to the correct subscription:

```powershell
Connect-AzAccount
Set-AzContext -SubscriptionName "Your Subscription Name"
```

#### VM Deployment Failures

**Issue**: Resource creation errors  
**Solution**: Check Azure resource limits and permissions

**Issue**: Name conflicts  
**Solution**: VM names are auto-generated with availability testing

#### Network Access Issues

**Issue**: Cannot RDP to VM  
**Solution**: 
- Verify NSG rules allow your current IP
- Use JIT access policy if available
- Check VM is running (not deallocated)

### Important Notes

> **💡 Subscription Configuration**  
> Update line 65 in the deployment script with your subscription name for unattended operation.

> **🏷️ Naming Convention**  
> VM names follow pattern: `vmdscamcYYYXXXX` where YYY is location acronym and XXXX is random digits.

> **🌍 Regional Deployment**  
> Default region is East US 2. Modify line 329 to change deployment region.

> **💰 Cost Management**  
> Spot instances are used by default. Disable around line 185 if consistent availability is required.

---

**📖 Additional Resources**:
- [Azure Machine Configuration Documentation](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/)
- [Guest Configuration Policy Initiative](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policySetDefinitions/Guest%20Configuration/GuestConfiguration_Prerequisites.json)
