# main.tftest.hcl

#mock_provider "azurerm" {}

# Test resource group
run "verify_resource_group" {
	command = plan

  assert {
    condition     = azurerm_resource_group.main.name == "${var.prefix}-resources"
    error_message = "Resource group name does not match expected value"
  }

  assert {
    condition     = azurerm_resource_group.main.location == var.location
    error_message = "Resource group location does not match expected value"
  }
}

run "verify_virtual_network" {
	command = plan

  assert {
    condition     = azurerm_virtual_network.main.name == "${var.prefix}-network"
    error_message = "Virtual network name does not match expected value"
  }

  assert {
    condition     = azurerm_virtual_network.main.location == var.location
    error_message = "Resource group location does not match expected value"
  }
}