
# This ensures we have unique CAF compliant names for our resources.
module "naming" {
  source  = "Azure/naming/azurerm"
  version = "0.3.0"
}


resource "random_shuffle" "region" {
  input        = keys(local.virtual_desktop_azure_regions)
  result_count = 1
}

resource "random_integer" "instance_index" {
  max = 999
  min = 0
}

# This is required for resource modules
resource "azurerm_resource_group" "this" {
  location = random_shuffle.region.result[0]
  #name     = module.naming.resource_group.name_unique
  name = "rg-avd-${local.virtual_desktop_hostpool_name}"
  tags = var.tags
}

resource "azurerm_log_analytics_workspace" "this" {
  location            = azurerm_resource_group.this.location
  name                = "log${replace(local.virtual_desktop_hostpool_name, "-", "")}"
  resource_group_name = azurerm_resource_group.this.name
}

# This is the module call
module "avm_res_desktopvirtualization_hostpool" {
  source  = "Azure/avm-res-desktopvirtualization-hostpool/azurerm"
  version = "0.4.0"

  resource_group_name                           = azurerm_resource_group.this.name
  virtual_desktop_host_pool_load_balancer_type  = var.virtual_desktop_host_pool_load_balancer_type
  virtual_desktop_host_pool_location            = azurerm_resource_group.this.location
  virtual_desktop_host_pool_name                = local.virtual_desktop_hostpool_name
  virtual_desktop_host_pool_resource_group_name = azurerm_resource_group.this.name
  virtual_desktop_host_pool_type                = var.virtual_desktop_host_pool_type
  diagnostic_settings = {
    to_law = {
      name                  = local.virtual_desktop_hostpool_name
      workspace_resource_id = azurerm_log_analytics_workspace.this.id
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

# Get an existing built-in role definition
data "azurerm_role_definition" "this" {
  name = "Desktop Virtualization User"
}

data "azuread_group" "existing" {
  display_name     = var.user_group_name
  security_enabled = true
}

# Get the subscription
data "azurerm_subscription" "primary" {}

# Get the service principal for Azure Vitual Desktop
data "azuread_service_principal" "spn" {
  client_id = "9cdead84-a844-4324-93f2-b2e6bb768d07"
}

# Assign the Azure AD group to the application group
resource "azurerm_role_assignment" "this" {
  principal_id                     = data.azuread_group.existing.object_id
  scope                            = module.avm_res_desktopvirtualization_applicationgroup.resource.id
  role_definition_id               = data.azurerm_role_definition.this.id
  skip_service_principal_aad_check = false
}

# This is the module desktop application group
module "avm_res_desktopvirtualization_applicationgroup" {
  source                                                         = "Azure/avm-res-desktopvirtualization-applicationgroup/azurerm"
  enable_telemetry                                               = var.enable_telemetry
  virtual_desktop_application_group_default_desktop_display_name = local.virtual_desktop_application_group_default_desktop_display_name
  virtual_desktop_application_group_description                  = local.virtual_desktop_application_group_description
  virtual_desktop_application_group_friendly_name                = local.virtual_desktop_application_group_friendly_name
  virtual_desktop_application_group_host_pool_id                 = module.avm_res_desktopvirtualization_hostpool.resource.id
  virtual_desktop_application_group_location                     = azurerm_resource_group.this.location
  virtual_desktop_application_group_resource_group_name          = azurerm_resource_group.this.name
  virtual_desktop_application_group_name                         = local.virtual_desktop_application_group_default_desktop_display_name
  virtual_desktop_application_group_type                         = var.virtual_desktop_application_group_type
}

# This is the module call
module "avm_res_desktopvirtualization_workspace" {
  source = "Azure/avm-res-desktopvirtualization-workspace/azurerm"

  virtual_desktop_workspace_location            = azurerm_resource_group.this.location
  virtual_desktop_workspace_name                = local.virtual_desktop_workspace_name
  virtual_desktop_workspace_resource_group_name = azurerm_resource_group.this.name
  diagnostic_settings = {
    to_law = {
      name                  = "to-law"
      workspace_resource_id = azurerm_log_analytics_workspace.this.id
    }
  }
  enable_telemetry                        = var.enable_telemetry
  virtual_desktop_workspace_description   = local.virtual_desktop_workspace_description
  virtual_desktop_workspace_friendly_name = local.virtual_desktop_workspace_friendly_name
}

resource "azurerm_virtual_desktop_workspace_application_group_association" "workappgrassoc" {
  application_group_id = module.avm_res_desktopvirtualization_applicationgroup.resource.id
  workspace_id         = module.avm_res_desktopvirtualization_workspace.resource.id
}


resource "random_uuid" "example" {}

data "azurerm_role_definition" "roles" {
  for_each = toset([
    "Desktop Virtualization Power On Off Contributor",
  ])

  name  = each.key
  scope = data.azurerm_subscription.primary.id
}


data "azurerm_role_assignments" "existing" {
  scope        = data.azurerm_subscription.primary.id
  principal_id = data.azuread_service_principal.spn.object_id
}

resource "azurerm_role_assignment" "new" {
  for_each = {
    for k, v in local.expected_roles :
    k => v
    if(!contains(data.azurerm_role_assignments.existing.role_assignments[*].role_definition_id, v))
  }

  principal_id                     = data.azuread_service_principal.spn.object_id
  scope                            = data.azurerm_subscription.primary.id
  role_definition_name             = each.key
  skip_service_principal_aad_check = true

  lifecycle {
    ignore_changes = all
  }
}

# This is the module call
module "avm-res-desktopvirtualization-scalingplan" {
  source = "Azure/avm-res-desktopvirtualization-scalingplan/azurerm"


  virtual_desktop_scaling_plan_location            = azurerm_resource_group.this.location
  virtual_desktop_scaling_plan_name                = local.virtual_desktop_scalingplan_name
  virtual_desktop_scaling_plan_resource_group_name = azurerm_resource_group.this.name
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

  depends_on = [azurerm_resource_group.this, module.avm_res_desktopvirtualization_hostpool]
}


# Deploy an vnet and subnet for AVD session hosts
resource "azurerm_virtual_network" "this_vnet" {
  address_space       = var.vnet_address_space
  location            = azurerm_resource_group.this.location
  name                = "vnet-avd-${local.virtual_desktop_hostpool_name}"
  resource_group_name = azurerm_resource_group.this.name
}

resource "azurerm_subnet" "this_subnet_1" {
  address_prefixes     = var.subnet_address_prefixes
  name                 = "snet-avd-${local.virtual_desktop_hostpool_name}-1"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this_vnet.name
}

# Deploy a single AVD session host using marketplace image
resource "azurerm_network_interface" "this" {
  count = var.vm_count

  location                       = azurerm_resource_group.this.location
  name                           = "${local.virtual_desktop_vm_prefix}-${count.index}-nic"
  resource_group_name            = azurerm_resource_group.this.name
  accelerated_networking_enabled = true

  ip_configuration {
    name                          = "internal"
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.this_subnet_1.id
  }
}

# Generate VM local password
resource "random_password" "vmpass" {
  length  = 20
  special = true
}

resource "azurerm_windows_virtual_machine" "this" {
  count = var.vm_count

  admin_password             = random_password.vmpass.result
  admin_username             = "adminuser"
  location                   = azurerm_resource_group.this.location
  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}"
  network_interface_ids      = [azurerm_network_interface.this[count.index].id]
  resource_group_name        = azurerm_resource_group.this.name
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
}

# Virtual Machine Extension for AMA agent
resource "azurerm_virtual_machine_extension" "ama" {
  count = var.vm_count

  name                      = "AzureMonitorWindowsAgent-${count.index}"
  publisher                 = "Microsoft.Azure.Monitor"
  type                      = "AzureMonitorWindowsAgent"
  type_handler_version      = "1.2"
  virtual_machine_id        = azurerm_windows_virtual_machine.this[count.index].id
  automatic_upgrade_enabled = true

  depends_on = [module.avm_res_desktopvirtualization_hostpool]
}

# Virtual Machine Extension for AAD Join
resource "azurerm_virtual_machine_extension" "aadjoin" {
  count = var.vm_count

  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}-aadJoin"
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADLoginForWindows"
  type_handler_version       = "2.0"
  virtual_machine_id         = azurerm_windows_virtual_machine.this[count.index].id
  auto_upgrade_minor_version = true
}

# Virtual Machine Extension for AVD Agent
resource "azurerm_virtual_machine_extension" "vmext_dsc" {
  count = var.vm_count

  name                       = "${local.virtual_desktop_vm_prefix}-${count.index}-avd_dsc"
  publisher                  = "Microsoft.Powershell"
  type                       = "DSC"
  type_handler_version       = "2.73"
  virtual_machine_id         = azurerm_windows_virtual_machine.this[count.index].id
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
