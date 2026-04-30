output "vm_password" {
  value     = random_password.vmpass.result
  sensitive = true
}

output "expected_roles" {
  value = local.expected_roles
}

output "rbac_assignment_on_subscription" {
  value = azurerm_role_assignment.rbac_assignment_on_subscription
}

output "avd_power_assigned_on_subscription" {
  value = data.azurerm_role_definition.roles
}
