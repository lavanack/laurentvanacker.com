# AutomatedLab - Network Load Balancing (NLB) with IIS

[![PowerShell](https://img.shields.io/badge/PowerShell-5.0%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![AutomatedLab](https://img.shields.io/badge/AutomatedLab-5.0%2B-orange)](https://github.com/AutomatedLab/AutomatedLab)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Automated deployment of a complete Network Load Balancing (NLB) environment with IIS web servers, SSL certificates, and shared configuration using AutomatedLab**

## 📋 Table of Contents

- [Overview](#-overview)
- [Lab Architecture](#-lab-architecture)
- [Prerequisites](#-prerequisites)
- [Lab Components](#-lab-components)
- [Features](#-features)
- [Network Configuration](#-network-configuration)
- [Usage](#-usage)
- [What Gets Deployed](#-what-gets-deployed)
- [SSL Certificate Management](#-ssl-certificate-management)
- [Authentication Configuration](#-authentication-configuration)
- [Troubleshooting](#-troubleshooting)
- [Cleanup](#-cleanup)

## 🎯 Overview

This AutomatedLab script creates a complete **Network Load Balancing (NLB)** environment with **IIS web servers** for testing and demonstration purposes. The lab simulates a production-like web farm scenario with high availability, shared configuration, and enterprise-grade security features.

### Key Use Cases

- **Load Balancing Testing**: Demonstrate NLB capabilities with multiple IIS nodes
- **Web Farm Scenarios**: Test shared configuration and session state management
- **SSL/TLS Implementation**: Certificate management with Central Certificate Store
- **Authentication Testing**: Windows Authentication and Kerberos integration
- **High Availability Learning**: Understand fault tolerance and redundancy concepts

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NLB IIS Lab Environment                 │
│                      (10.0.0.0/16)                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │    DC01     │    │    CA01     │    │   Client    │     │
│  │Domain Ctrl. │    │Cert. Auth.  │    │  Access     │     │
│  │10.0.0.1     │    │10.0.0.2     │    │             │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              NLB Cluster                                │ │
│  │            nlb.contoso.com                              │ │
│  │             10.0.0.101                                  │ │
│  └─────────────────┬─────────────────┬───────────────────┘ │
│                    │                 │                     │
│  ┌─────────────────▼───┐    ┌────────▼─────────────┐       │
│  │    IISNODE01        │    │     IISNODE02        │       │
│  │  Internal: 10.0.0.21│    │  Internal: 10.0.0.22│       │
│  │  NLB: 10.0.0.201    │    │  NLB: 10.0.0.202    │       │
│  │                     │    │                      │       │
│  │  • IIS Web Server   │    │  • IIS Web Server    │       │
│  │  • DFS-R Replica    │    │  • DFS-R Replica     │       │
│  │  • Central Cert     │    │  • Central Cert      │       │
│  │  • Shared Config    │    │  • Shared Config     │       │
│  └─────────────────────┘    └──────────────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Prerequisites

### System Requirements

- **Windows 10/11** or **Windows Server 2016+** with Hyper-V enabled
- **Minimum 16GB RAM** (32GB recommended for optimal performance)
- **100GB free disk space** for VMs and lab files
- **Administrative privileges** on the host machine

### Required Software

```powershell
# Install AutomatedLab PowerShell module
Install-Module -Name AutomatedLab -AllowClobber -Force

# Verify Hyper-V is enabled
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

# Enable Hyper-V if needed (requires restart)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
```

### Required Files

Ensure the following file exists in the script directory:
- `nlb.contoso.com.zip` - Web application content archive

## 🖥️ Lab Components

### Virtual Machines

| VM Name       | Role                      | IP Address                               | Specifications  |
| ------------- | ------------------------- | ---------------------------------------- | --------------- |
| **DC01**      | Domain Controller         | 10.0.0.1                                 | 2GB RAM, 4 vCPU |
| **CA01**      | Certificate Authority     | 10.0.0.2                                 | 2GB RAM, 4 vCPU |
| **IISNODE01** | IIS Web Server + NLB Node | 10.0.0.21 (Internal)<br>10.0.0.201 (NLB) | 2GB RAM, 4 vCPU |
| **IISNODE02** | IIS Web Server + NLB Node | 10.0.0.22 (Internal)<br>10.0.0.202 (NLB) | 2GB RAM, 4 vCPU |

### Domain Configuration

- **Domain**: `contoso.com`
- **NetBIOS**: `CONTOSO`
- **Admin User**: `Administrator`
- **Password**: `P@ssw0rd`
- **Service Account**: `IISAppPoolUser` (for application pools)

## ✨ Features

### 🔄 **Network Load Balancing**
- **Windows NLB Cluster** with multicast mode
- **Automatic failover** between web servers
- **Session affinity** options (configurable)
- **Health monitoring** and traffic distribution

### 🌐 **IIS Web Farm**
- **Shared Configuration** using DFS-R replication
- **Central Certificate Store** for SSL certificate management
- **Identical application pools** across all nodes
- **Windows Authentication** with Kerberos support

### 🔐 **Security Features**
- **Enterprise Certificate Authority** with custom SSL templates
- **SAN certificates** supporting multiple hostnames
- **Windows Authentication** with AD integration
- **Service Principal Names (SPNs)** for Kerberos authentication

### 📁 **Shared Resources**
- **DFS-R replication** for configuration synchronization
- **Central Certificate Store** for certificate management
- **Machine key standardization** across web farm
- **Application pool identity** using domain service account

## 🌐 Network Configuration

### IP Address Scheme

```
Network: 10.0.0.0/16 (Internal Switch)

Infrastructure:
├── DC01 (Domain Controller): 10.0.0.1
├── CA01 (Certificate Authority): 10.0.0.2
└── NLB Virtual IP: 10.0.0.101

Web Servers:
├── IISNODE01
│   ├── Internal NIC: 10.0.0.21/16
│   └── NLB NIC: 10.0.0.201/16
└── IISNODE02
    ├── Internal NIC: 10.0.0.22/16
    └── NLB NIC: 10.0.0.202/16
```

### DNS Configuration

- **nlb.contoso.com** → 10.0.0.101 (NLB Virtual IP)
- **IISNODE01.contoso.com** → 10.0.0.21
- **IISNODE02.contoso.com** → 10.0.0.22

## 🚀 Usage

### Basic Deployment

1. **Prepare Environment**:
   ```powershell
   # Ensure you're running as Administrator
   # Place nlb.contoso.com.zip in the script directory
   ```

2. **Run the Script**:
   ```powershell
   .\AutomatedLab - NLB & IIS.ps1
   ```

3. **Monitor Progress**:
   - Script creates transcript log with timestamp
   - Watch for completion notification (system beep)
   - Check transcript file for detailed deployment log

### Deployment Timeline

| Phase                    | Duration        | Description                                |
| ------------------------ | --------------- | ------------------------------------------ |
| **VM Creation**          | ~15 minutes     | Creating and installing base VMs           |
| **Domain Setup**         | ~10 minutes     | Configuring domain controller and CA       |
| **Feature Installation** | ~15 minutes     | Installing IIS, NLB, and required features |
| **NLB Configuration**    | ~5 minutes      | Setting up load balancing cluster          |
| **SSL & Security**       | ~10 minutes     | Certificates and authentication setup      |
| **Web Farm Setup**       | ~10 minutes     | Shared configuration and replication       |
| **Total Time**           | **~65 minutes** | Complete lab deployment                    |

## 🎭 What Gets Deployed

### 1. Active Directory Environment
- **Domain Controller** with DNS and AD DS
- **Certificate Authority** with custom web server templates
- **Service accounts** for IIS application pools
- **DNS records** for load-balanced website

### 2. Network Load Balancing Cluster
- **NLB cluster** named `nlb.contoso.com`
- **Multicast mode** operation
- **Port rules** for HTTP (80) and HTTPS (443)
- **Health monitoring** for automatic failover

### 3. IIS Web Farm
- **Two identical IIS servers** with shared configuration
- **Custom application pools** with domain service account identity
- **Windows Authentication** enabled with Kerberos support
- **SSL/TLS encryption** with enterprise certificates

### 4. Shared Infrastructure
- **DFS-R replication groups** for configuration synchronization
- **Central Certificate Store** for SSL certificate management
- **Machine key synchronization** for session state consistency
- **Standardized security policies** across all nodes

### 5. Web Application
- **Sample web application** from `nlb.contoso.com.zip`
- **Default.aspx** configured as default document
- **SSL-only access** with certificate validation
- **Windows Authentication** required for access

## 🔒 SSL Certificate Management

### Certificate Architecture

```
Enterprise CA (CA01)
└── Web Server SSL Template
    └── SAN Certificate for:
        ├── nlb.contoso.com (Primary)
        ├── IISNODE01.contoso.com
        ├── IISNODE02.contoso.com
        ├── nlb (NetBIOS)
        ├── IISNODE01 (NetBIOS)
        └── IISNODE02 (NetBIOS)
```

### Central Certificate Store

- **Location**: `C:\CentralCertificateStore\` (replicated via DFS-R)
- **Certificates**: PFX files with private keys
- **Password Protection**: Secured with lab credentials
- **Automatic Loading**: IIS automatically discovers and loads certificates

## 🔐 Authentication Configuration

### Windows Authentication Setup

1. **Anonymous Authentication**: Disabled
2. **Windows Authentication**: Enabled with Kerberos
3. **ASP.NET Impersonation**: Enabled for user context
4. **Application Pool Identity**: Domain service account (`CONTOSO\IISAppPoolUser`)

### Service Principal Names (SPNs)

The script automatically configures SPNs for proper Kerberos authentication:

```
HTTP/nlb.contoso.com
HTTP/nlb
HTTP/IISNODE01.contoso.com
HTTP/IISNODE01
HTTP/IISNODE02.contoso.com
HTTP/IISNODE02
```

### Kerberos Requirements

- **Intranet Zone**: All sites added to IE intranet zone
- **SPN Registration**: Proper SPNs set on service account
- **Time Synchronization**: All VMs sync with domain controller
- **DNS Resolution**: Forward and reverse lookup zones configured

## 🛠️ Troubleshooting

### Common Issues

#### 1. NLB Cluster Not Accessible
**Symptoms**: Cannot reach nlb.contoso.com
**Solutions**:
```powershell
# Check NLB cluster status
Get-NlbCluster -HostName IISNODE01
Get-NlbClusterNode -HostName IISNODE01

# Verify DNS resolution
nslookup nlb.contoso.com

# Test individual nodes
Test-NetConnection -ComputerName IISNODE01.contoso.com -Port 443
Test-NetConnection -ComputerName IISNODE02.contoso.com -Port 443
```

#### 2. SSL Certificate Issues
**Symptoms**: Certificate warnings or errors
**Solutions**:
```powershell
# Check certificate store
Invoke-LabCommand -ComputerName IISNODE01 -ScriptBlock {
    Get-ChildItem -Path Cert:\LocalMachine\My\ -DnsName "nlb.contoso.com"
}

# Verify Central Certificate Store
Invoke-LabCommand -ComputerName IISNODE01 -ScriptBlock {
    Get-ChildItem -Path C:\CentralCertificateStore\
}
```

#### 3. Authentication Problems
**Symptoms**: 401 Unauthorized errors
**Solutions**:
```powershell
# Check SPN configuration
setspn -L CONTOSO\IISAppPoolUser

# Verify application pool identity
Invoke-LabCommand -ComputerName IISNODE01 -ScriptBlock {
    Get-IISAppPool -Name "nlb.contoso.com" | Select-Object Name, ProcessModel
}
```

#### 4. DFS-R Replication Issues
**Symptoms**: Configuration not synchronized
**Solutions**:
```powershell
# Check replication status
Invoke-LabCommand -ComputerName IISNODE01 -ScriptBlock {
    Get-DfsrBacklog -GroupName "IIS Shared Configuration" -FolderName "C:\IISSharedConfiguration"
}

# Force replication
Invoke-LabCommand -ComputerName IISNODE01 -ScriptBlock {
    Sync-DfsReplicationGroup -GroupName "IIS Shared Configuration"
}
```

### Log File Locations

- **Script Transcript**: `AutomatedLab - NLB & IIS_yyyyMMddHHmmss.txt`
- **AutomatedLab Logs**: `C:\ProgramData\AutomatedLab\Logs\`
- **IIS Logs**: `C:\inetpub\logs\LogFiles\`
- **Windows Event Logs**: System, Application, and Security logs on all VMs

### Performance Monitoring

```powershell
# Check NLB performance
Get-Counter -ComputerName IISNODE01 -Counter "\Network Load Balancing(*)\*"

# Monitor IIS performance
Get-Counter -ComputerName IISNODE01 -Counter "\Web Service(*)\*"

# Check DFS-R performance
Get-Counter -ComputerName IISNODE01 -Counter "\DFS Replication Service(*)\*"
```

## 🧹 Cleanup

### Remove the Lab

```powershell
# Remove the entire lab environment
Remove-Lab -Name 'NLBIISLab' -Confirm:$false

# Clean up Hyper-V virtual switches
Get-VMSwitch -Name 'NLBIISLab' | Remove-VMSwitch -Force

# Remove lab files (optional)
Remove-Item -Path "C:\AutomatedLab-VMs\NLBIISLab" -Recurse -Force
```

### Preserve Snapshots

The script creates snapshots at key points:
- `FreshInstall`: After initial VM installation
- `FullInstall`: After complete lab deployment

```powershell
# Restore to a specific snapshot
Restore-LabVMSnapshot -SnapshotName 'FullInstall' -All -Verbose
```

## 📖 Additional Resources

### AutomatedLab Documentation
- [AutomatedLab GitHub](https://github.com/AutomatedLab/AutomatedLab)
- [AutomatedLab Documentation](https://automatedlab.org/en/latest/)

### Microsoft Documentation
- [Network Load Balancing Overview](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-load-balancing)
- [IIS Shared Configuration](https://learn.microsoft.com/en-us/iis/web-hosting/configuring-servers-in-the-windows-web-platform/shared-configuration_264)
- [Central Certificate Store](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-8/iis-80-centralized-ssl-certificate-support-ssl-scalability-and-manageability)

### Related Technologies
- [DFS Replication](https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview)
- [Active Directory Certificate Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [Kerberos Authentication](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

---

## 📝 Notes

- **Lab Environment**: This is designed for testing and learning purposes only
- **Security**: Uses simplified credentials for demonstration - not suitable for production
- **Resource Usage**: Monitor system resources during deployment
- **Network Isolation**: Lab uses internal virtual switches for security

## 🤝 Contributing

Issues and suggestions are welcome! Please ensure any modifications maintain the lab's educational value and security considerations.

---

**📖 Additional Information**:
- **Script Type**: AutomatedLab deployment script
- **Target OS**: Windows Server 2019 Datacenter (Desktop Experience)
- **PowerShell Version**: 5.0+ required
- **Estimated Deployment Time**: 60-90 minutes depending on hardware