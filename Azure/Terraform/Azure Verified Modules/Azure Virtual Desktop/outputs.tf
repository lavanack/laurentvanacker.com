output "vm_password" {
  value     = random_password.vmpass.result
  sensitive = true
}

output "expected_roles" {
  value = local.expected_roles
}

output "asigned_roles" {
  value = values(azurerm_role_assignment.new).*
}
