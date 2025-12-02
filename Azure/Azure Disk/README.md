# ConvertTo-EncryptionAtHost PowerShell Script

## Overview

This PowerShell script converts Azure Virtual Machines from Azure Disk Encryption (ADE) to Encryption at Host. This migration is necessary when moving from guest-based encryption to host-based encryption for better performance and simplified management.

## Prerequisites

- Windows PowerShell 5.1
- Required Azure PowerShell modules:
  - `Az.Accounts`
  - `Az.Compute`
  - `Az.Resources`
  - `Az.Security`
  - `Microsoft.PowerShell.ThreadJob`
- Azure authentication (Connect-AzAccount)
- Appropriate permissions to manage VMs, disks, and networking in the target resource groups

## Key Features

- **Sequential and Parallel Processing**: Supports both sequential processing and parallel execution using RunSpaces or ThreadJobs
- **Automated AzCopy Installation**: Downloads and installs AzCopy if not found on the system
- **Encryption Status Monitoring**: Real-time monitoring of BitLocker decryption progress
- **Spot Instance Support**: Preserves Spot instance configuration in the target VM
- **Network Configuration Preservation**: Maintains public IP, NSG, and subnet configurations
- **JIT Access Management**: Enables Just-In-Time VM access for enhanced security
- **Auto-shutdown Configuration**: Sets up automatic VM shutdown at 11 PM

## Functions

### ConvertTo-EncryptionAtHost

The main function that converts a single VM from ADE to Encryption at Host.

**Parameters:**

- `VM` (Mandatory): PSVirtualMachine object representing the source VM

**Process Overview:**

1. Revokes existing disk access
2. Disables Azure Disk Encryption and removes extensions
3. Monitors BitLocker decryption progress
4. Creates new managed disks with encryption at host
5. Copies disk data using AzCopy
6. Creates a new VM with encryption at host enabled

>[!NOTE]
> If a Public IP is attached to the source VM, a new one will be attached to the target one
>
> If a Network Security Group (NSG) is attached to the source NIC ,the same NSG willbe attached to the tget NIC.
>
> The "Bonus Track" region is just for checking the encryption status and to set up Just-In-Time Administration (JIT)

### ConvertTo-EncryptionAtHostWithThreadJob

Parallel processing version using ThreadJobs for better performance with multiple VMs.

### ConvertTo-EncryptionAtHostWithRunSpace

High-performance parallel processing using PowerShell RunSpaces for maximum efficiency.

### Get-AzVMBitLockerVolume

Retrieves BitLocker volume information from Azure VMs.

**Parameters:**

- `VM` (Mandatory): PSVirtualMachine object
- `Raw` (Switch): Returns raw BitLocker data instead of formatted output

## Usage Examples

### Basic Usage

```powershell
# Convert a single VM
$VM = Get-AzVM -ResourceGroupName "myRG" -Name "myVM"
$ConvertedVM = $VM | ConvertTo-EncryptionAtHost -Verbose
```

### Parallel Processing with ThreadJobs

```powershell
# Convert multiple VMs in parallel using ThreadJobs
$VMs = Get-AzVM -ResourceGroupName "myRG"
$ConvertedVMs = $VMs | ConvertTo-EncryptionAtHostWithThreadJob -Verbose
```

### High-Performance Parallel Processing

```powershell
# Convert multiple VMs using RunSpaces (highest performance)
$VMs = Get-AzVM -ResourceGroupName "myRG"
$ConvertedVMs = ConvertTo-EncryptionAtHostWithRunSpace -VM $VMs -RunspacePoolSize 4 -Verbose
```

### Check BitLocker Status

```powershell
# Check BitLocker encryption status on running VMs
$VMs = Get-AzVM -ResourceGroupName "myRG"
$BitLockerStatus = $VMs | Get-AzVMBitLockerVolume -Verbose
```

## Script Parameters

### Global Parameters

- `AzCopyDir`: Directory where AzCopy will be installed (Default: "C:\Tools")

## Important Notes

### Naming Convention

The script creates target resources with a "_Target" suffix:

- Original VM: `myVM` → Target VM: `myVM_Target`
- Original Disk: `myVM_OSDisk` → Target Disk: `myVM_OSDisk_Target`

### Security Features

1. **Trusted Launch**: All target VMs are created with Trusted Launch security type
2. **System-Assigned Identity**: Enables managed identity for enhanced security
3. **JIT Access**: Automatically configures Just-In-Time VM access
4. **Boot Diagnostics**: Enables boot diagnostics for troubleshooting

### Performance Considerations

- **Sequential Processing**: Use for single VMs or when system resources are limited
- **ThreadJob Processing**: Good balance of performance and resource usage
- **RunSpace Processing**: Maximum performance for bulk operations

### Disk Encryption Timeline

The script monitors BitLocker decryption progress and waits for full decryption before proceeding. This ensures data integrity during the migration process.

## Error Handling

- Comprehensive error handling with detailed verbose logging
- Automatic cleanup of failed resources
- Progress monitoring with time stamps
- Graceful handling of disk access revocation

## Security Considerations

- The script requires elevated permissions for VM and disk operations
- Source VMs must be fully decrypted before creating target VMs
- SAS tokens are used temporarily for disk copying and are automatically revoked
- JIT access is configured with time-limited access (3 hours by default)

## Troubleshooting

### Common Issues

1. **Insufficient Permissions**: Ensure your account has Contributor access to the resource groups
2. **VM Running State**: Source VMs must be running during the decryption phase
3. **Disk Space**: Ensure sufficient storage quota for duplicate disks during migration
4. **AzCopy Installation**: Script will auto-download AzCopy if not found

### Verbose Logging

Use the `-Verbose` parameter to get detailed logging information including:

- Processing timestamps
- Operation duration tracking
- BitLocker decryption progress
- Resource creation status

## Sample Output

The script provides detailed verbose output showing:

- VM processing start and end times
- Disk creation and copying progress
- BitLocker decryption status
- Network configuration setup
- Overall processing duration

## License

This sample code is provided for illustration purposes only and is not intended for production use without proper testing and validation.

## Related Documentation

- [Azure Disk Encryption Migration](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-migrate)
- [Encryption at Host](https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption#encryption-at-host)
- [Azure Resource Manager Request Limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling)
