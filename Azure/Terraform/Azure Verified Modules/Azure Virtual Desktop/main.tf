
###############################################################################
# Identity & RBAC data sources
###############################################################################

# Entra ID security group whose members will be granted access to the Desktop
# Application Group (DAG) and its hosting resource group.
resource "azuread_group" "virtual_desktop_dag_group" {
  display_name     = local.virtual_desktop_dag_group_name
  security_enabled = true
}

# Current subscription (used as scope for role lookups and assignments).
data "azurerm_subscription" "current" {}

# Built-in service principal for the Azure Virtual Desktop first-party app.
# Required to grant the "Power On/Off Contributor" role for Start VM on Connect.
data "azuread_service_principal" "avd_spn" {
  display_name = "Azure Virtual Desktop"
}

# Built-in role: granted to end users so they can launch the published desktop.
data "azurerm_role_definition" "desktop_virtualization_user" {
  name  = "Desktop Virtualization User"
  scope = data.azurerm_subscription.current.id
}

# Built-in role: granted to the AVD service principal so it can start/stop VMs
# (used by Start VM on Connect and the scaling plan).
data "azurerm_role_definition" "power_role" {
  name  = "Desktop Virtualization Power On Off Contributor"
  scope = data.azurerm_subscription.current.id
}

# List all role assignments at subscription scope. The result is consumed in
# locals.tf to detect whether the AVD power role assignment already exists
# (avoids creating duplicate assignments on re-runs).
data "azapi_resource_list" "role_assignments_sub" {
  type      = "Microsoft.Authorization/roleAssignments@2022-04-01"
  parent_id = data.azurerm_subscription.current.id

  # Export full payload so we can read .value[] in locals
  response_export_values = ["*"]
}

###############################################################################
# Randomization (region selection + unique instance index)
###############################################################################

# Pick a random AVD-supported region for the deployment
resource "random_shuffle" "avd_region" {
  input        = keys(local.virtual_desktop_azure_regions)
  result_count = 1
}

# Random index appended to resource names to make them unique across runs
resource "random_integer" "instance_index" {
  max = 999
  min = 0
}

###############################################################################
# Core infrastructure: Resource Group + Log Analytics
###############################################################################

# Resource group hosting all AVD resources for this deployment
resource "azurerm_resource_group" "hostpoool_rg" {
  location = random_shuffle.avd_region.result[0]
  name     = "rg-avd-${local.virtual_desktop_hostpool_name}"
  tags     = var.tags
}

# Log Analytics workspace used as the diagnostic settings target for the
# host pool and the workspace.
resource "azurerm_log_analytics_workspace" "law" {
  location            = azurerm_resource_group.hostpoool_rg.location
  name                = "log${replace(local.virtual_desktop_hostpool_name, "-", "")}"
  resource_group_name = azurerm_resource_group.hostpoool_rg.name
}

###############################################################################
# AVD Host Pool (AVM module)
###############################################################################

# Deploys the AVD host pool with diagnostic settings, custom RDP properties,
# scheduled agent updates, and Start VM on Connect.
module "avm_res_desktopvirtualization_hostpool" {
  source  = "Azure/avm-res-desktopvirtualization-hostpool/azurerm"
  version = "0.4.0"

  resource_group_name                           = azurerm_resource_group.hostpoool_rg.name
  virtual_desktop_host_pool_load_balancer_type  = var.virtual_desktop_host_pool_load_balancer_type
  virtual_desktop_host_pool_location            = azurerm_resource_group.hostpoool_rg.location
  virtual_desktop_host_pool_name                = local.virtual_desktop_hostpool_name
  virtual_desktop_host_pool_resource_group_name = azurerm_resource_group.hostpoool_rg.name
  virtual_desktop_host_pool_type                = var.virtual_desktop_host_pool_type
  diagnostic_settings = {
    to_law = {
      name                  = local.virtual_desktop_hostpool_name
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
    }
  }
  enable_telemetry = var.enable_telemetry
  virtual_desktop_host_pool_custom_rdp_properties = {
    audiomode        = 1 # Local audio only
    use_multimon     = 1 # Enable multi-monitor
    redirectprinters = 0 # Disable printer redirection   
    custom_properties = {
      "enablerdsaadauth"  = "i:1"
      "camerastoredirect" = "s:*"
      "redirectlocation"  = "i:1"
    }
  }
  virtual_desktop_host_pool_maximum_sessions_allowed = var.virtual_desktop_host_pool_maximum_sessions_allowed
  virtual_desktop_host_pool_scheduled_agent_updates = {
    enabled = "true"
    schedule = tolist([{
      day_of_week = "Sunday"
      hour_of_day = 0
    }])
  }
  virtual_desktop_host_pool_start_vm_on_connect = var.virtual_desktop_host_pool_start_vm_on_connect
}

###############################################################################
# Role assignments
###############################################################################

# Allow DAG group members to launch the published desktop (assignment scoped
# to the application group). Name is a deterministic GUID so re-runs are idempotent.
resource "azurerm_role_assignment" "desktop_virtualization_user_assignment_on_dag" {
  principal_id                     = azuread_group.virtual_desktop_dag_group.object_id
  scope                            = module.avm_res_desktopvirtualization_applicationgroup.resource.id
  role_definition_id               = data.azurerm_role_definition.desktop_virtualization_user.id
  skip_service_principal_aad_check = false
  name                             = uuidv5("00000000-0000-0000-0000-000000000000", "${module.avm_res_desktopvirtualization_applicationgroup.resource.id}-${azuread_group.virtual_desktop_dag_group.object_id}-${data.azurerm_role_definition.desktop_virtualization_user.id}")
}

# Same role granted at the resource group scope so DAG group members can also
# see/connect to the underlying session host VMs.
resource "azurerm_role_assignment" "desktop_virtualization_user_assignment_on_rg" {
  principal_id                     = azuread_group.virtual_desktop_dag_group.object_id
  scope                            = azurerm_resource_group.hostpoool_rg.id
  role_definition_id               = data.azurerm_role_definition.desktop_virtualization_user.id
  skip_service_principal_aad_check = false
  name                             = uuidv5("00000000-0000-0000-0000-000000000000", "${azurerm_resource_group.hostpoool_rg.id}-${azuread_group.virtual_desktop_dag_group.object_id}-${data.azurerm_role_definition.desktop_virtualization_user.id}")
}

# Grant the AVD service principal the Power On/Off Contributor role at
# subscription scope. Created only if a matching assignment doesn't already
# exist (see role_assignment_exists in locals.tf).
resource "azapi_resource" "avd_power_on_off_contributor" {
  count     = local.role_assignment_exists ? 0 : 1
  type      = "Microsoft.Authorization/roleAssignments@2022-04-01"
  name      = local.role_assignment_guid
  parent_id = data.azurerm_subscription.current.id

  body = {
    properties = {
      principalId      = data.azuread_service_principal.avd_spn.object_id
      principalType    = "ServicePrincipal"
      roleDefinitionId = data.azurerm_role_definition.power_role.id
    }
  }
}

###############################################################################
# Application Group, Workspace and Workspace<->AppGroup association (AVM modules)
###############################################################################

# Desktop Application Group (DAG) attached to the host pool
module "avm_res_desktopvirtualization_applicationgroup" {
  source                                                         = "Azure/avm-res-desktopvirtualization-applicationgroup/azurerm"
  enable_telemetry                                               = var.enable_telemetry
  virtual_desktop_application_group_default_desktop_display_name = local.virtual_desktop_application_group_default_desktop_display_name
  virtual_desktop_application_group_description                  = local.virtual_desktop_application_group_description
  virtual_desktop_application_group_friendly_name                = local.virtual_desktop_application_group_friendly_name
  virtual_desktop_application_group_host_pool_id                 = module.avm_res_desktopvirtualization_hostpool.resource.id
  virtual_desktop_application_group_location                     = azurerm_resource_group.hostpoool_rg.location
  virtual_desktop_application_group_resource_group_name          = azurerm_resource_group.hostpoool_rg.name
  virtual_desktop_application_group_name                         = local.virtual_desktop_application_group_default_desktop_display_name
  virtual_desktop_application_group_type                         = var.virtual_desktop_application_group_type
}

# AVD workspace that publishes the application group to end users
module "avm_res_desktopvirtualization_workspace" {
  source = "Azure/avm-res-desktopvirtualization-workspace/azurerm"

  virtual_desktop_workspace_location            = azurerm_resource_group.hostpoool_rg.location
  virtual_desktop_workspace_name                = local.virtual_desktop_workspace_name
  virtual_desktop_workspace_resource_group_name = azurerm_resource_group.hostpoool_rg.name
  diagnostic_settings = {
    to_law = {
      name                  = "to-law"
      workspace_resource_id = azurerm_log_analytics_workspace.law.id
    }
  }
  enable_telemetry                        = var.enable_telemetry
  virtual_desktop_workspace_description   = local.virtual_desktop_workspace_description
  virtual_desktop_workspace_friendly_name = local.virtual_desktop_workspace_friendly_name
}

# Bind the application group to the workspace so the desktop appears in the client
resource "azurerm_virtual_desktop_workspace_application_group_association" "workappgrassoc" {
  application_group_id = module.avm_res_desktopvirtualization_applicationgroup.resource.id
  workspace_id         = module.avm_res_desktopvirtualization_workspace.resource.id
}

###############################################################################
# Scaling Plan (AVM module)
###############################################################################

# Auto-scales session hosts based on weekday/weekend ramp-up, peak,
# ramp-down, and off-peak schedules (Paris time zone).
module "avm-res-desktopvirtualization-scalingplan" {
  source = "Azure/avm-res-desktopvirtualization-scalingplan/azurerm"


  virtual_desktop_scaling_plan_location            = azurerm_resource_group.hostpoool_rg.location
  virtual_desktop_scaling_plan_name                = local.virtual_desktop_scalingplan_name
  virtual_desktop_scaling_plan_resource_group_name = azurerm_resource_group.hostpoool_rg.name
  virtual_desktop_scaling_plan_schedule = toset(
    [
      {
        name                                 = "Weekday"
        days_of_week                         = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        ramp_up_start_time                   = "09:00"
        ramp_up_load_balancing_algorithm     = "BreadthFirst"
        ramp_up_minimum_hosts_percent        = 50
        ramp_up_capacity_threshold_percent   = 80
        peak_start_time                      = "10:00"
        peak_load_balancing_algorithm        = "DepthFirst"
        ramp_down_start_time                 = "17:00"
        ramp_down_load_balancing_algorithm   = "BreadthFirst"
        ramp_down_minimum_hosts_percent      = 50
        ramp_down_force_logoff_users         = true
        ramp_down_wait_time_minutes          = 15
        ramp_down_notification_message       = "The session will end in 15 minutes."
        ramp_down_capacity_threshold_percent = 50
        ramp_down_stop_hosts_when            = "ZeroActiveSessions"
        off_peak_start_time                  = "18:00"
        off_peak_load_balancing_algorithm    = "BreadthFirst"
      },
      {
        name                                 = "Weekend"
        days_of_week                         = ["Saturday", "Sunday"]
        ramp_up_start_time                   = "09:00"
        ramp_up_load_balancing_algorithm     = "BreadthFirst"
        ramp_up_minimum_hosts_percent        = 50
        ramp_up_capacity_threshold_percent   = 80
        peak_start_time                      = "10:00"
        peak_load_balancing_algorithm        = "DepthFirst"
        ramp_down_start_time                 = "17:00"
        ramp_down_load_balancing_algorithm   = "BreadthFirst"
        ramp_down_minimum_hosts_percent      = 50
        ramp_down_force_logoff_users         = true
        ramp_down_wait_time_minutes          = 15
        ramp_down_notification_message       = "The session will end in 15 minutes."
        ramp_down_capacity_threshold_percent = 50
        ramp_down_stop_hosts_when            = "ZeroActiveSessions"
        off_peak_start_time                  = "18:00"
        off_peak_load_balancing_algorithm    = "BreadthFirst"
      }
    ]
  )
  virtual_desktop_scaling_plan_time_zone = "Romance Standard Time" #Paris
  enable_telemetry                       = var.enable_telemetry
  virtual_desktop_scaling_plan_host_pool = toset(
    [
      {
        hostpool_id          = module.avm_res_desktopvirtualization_hostpool.resource.id
        scaling_plan_enabled = true
      }
    ]
  )

  depends_on = [azurerm_resource_group.hostpoool_rg, module.avm_res_desktopvirtualization_hostpool]
}


###############################################################################
# Networking: VNet + Subnet for session hosts
###############################################################################

# Virtual network hosting the session host NICs
resource "azurerm_virtual_network" "vnet" {
  address_space       = var.vnet_address_space
  location            = azurerm_resource_group.hostpoool_rg.location
  name                = "vnet-avd-${local.virtual_desktop_hostpool_name}"
  resource_group_name = azurerm_resource_group.hostpoool_rg.name
}

# Subnet for session host NICs
resource "azurerm_subnet" "subnet_1" {
  address_prefixes     = var.subnet_address_prefixes
  name                 = "snet-avd-${local.virtual_desktop_hostpool_name}-1"
  resource_group_name  = azurerm_resource_group.hostpoool_rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
}

###############################################################################
# Session host VMs and extensions
###############################################################################

# One NIC per session host (with accelerated networking enabled)
resource "azurerm_network_interface" "nic" {
  count = var.vm_count

  location                       = azurerm_resource_group.hostpoool_rg.location
  name                           = "${local.virtual_desktop_vm_prefix}-${count.index}-nic"
  resource_group_name            = azurerm_resource_group.hostpoool_rg.name
  accelerated_networking_enabled = true

  ip_configuration {
    name                          = "internal"
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.subnet_1.id
  }
}

# Random local-admin password (exposed via outputs.tf as a sensitive value)
resource "random_password" "vmpass" {
  length  = 20
  special = true
}

# Windows 11 multi-session AVD session host VMs (Trusted Launch + host encryption)
resource "azurerm_windows_virtual_machine" "sessionhost" {
  count = var.vm_count

  admin_password             = random_password.vmpass.result
  admin_username             = "adminuser"
  location                   = azurerm_resource_group.hostpoool_rg.location
  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}"
  network_interface_ids      = [azurerm_network_interface.nic[count.index].id]
  resource_group_name        = azurerm_resource_group.hostpoool_rg.name
  size                       = var.virtual_desktop_vm_size
  computer_name              = "${local.virtual_desktop_vm_prefix}-${count.index}"
  encryption_at_host_enabled = true
  secure_boot_enabled        = true
  vtpm_enabled               = true

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    name                 = "${local.virtual_desktop_vm_prefix}-${count.index}-osdisk"
  }
  identity {
    type = "SystemAssigned"
  }
  source_image_reference {
    offer     = "windows-11"
    publisher = "microsoftwindowsdesktop"
    sku       = "win11-25h2-avd"
    version   = "latest"
  }

  lifecycle {
    ignore_changes = [
      tags
    ]
  }
}

# Azure Monitor Agent extension - sends VM metrics/logs to Log Analytics
resource "azurerm_virtual_machine_extension" "ama" {
  count = var.vm_count

  name                      = "AzureMonitorWindowsAgent-${count.index}"
  publisher                 = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.2"
  virtual_machine_id        = azurerm_windows_virtual_machine.sessionhost[count.index].id
  automatic_upgrade_enabled = true

  depends_on = [module.avm_res_desktopvirtualization_hostpool]
}

# AAD Join extension - joins the VM to Entra ID (required for AVD AAD-joined hosts)
resource "azurerm_virtual_machine_extension" "aadjoin" {
  count = var.vm_count

  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}-aadJoin"
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADLoginForWindows"
  type_handler_version       = "2.0"
  virtual_machine_id         = azurerm_windows_virtual_machine.sessionhost[count.index].id
  auto_upgrade_minor_version = true
}

# DSC extension - installs the AVD agent and registers the VM with the host pool
# using the registration token exported by the host pool module
resource "azurerm_virtual_machine_extension" "vmext_dsc" {
  count = var.vm_count

  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}-avd_dsc"
  publisher                  = "Microsoft.Powershell"
  type                       = "DSC"
  type_handler_version       = "2.73"
  virtual_machine_id         = azurerm_windows_virtual_machine.sessionhost[count.index].id
  auto_upgrade_minor_version = true
  protected_settings         = <<PROTECTED_SETTINGS
  {
    "properties": {
      "registrationInfoToken": "${module.avm_res_desktopvirtualization_hostpool.registrationinfo_token}"
    }
  }
PROTECTED_SETTINGS
  settings                   = <<-SETTINGS
    {
      "modulesUrl": "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_1.0.03266.1110.zip",
      "configurationFunction": "Configuration.ps1\\AddSessionHost",
      "properties": {
        "HostPoolName":"${module.avm_res_desktopvirtualization_hostpool.resource.name}"
    }
 } 
  SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.aadjoin,
    module.avm_res_desktopvirtualization_hostpool
  ]
}
