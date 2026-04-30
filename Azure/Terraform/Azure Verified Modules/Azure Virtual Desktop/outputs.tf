output "vm_password" {
  value     = random_password.vmpass.result
  sensitive = true
}

output "avd_power_role_assignment_id" {
  value = local.role_assignment_exists ? local.matching_role_assignments[0].id : azapi_resource.avd_power_on_off_contributor[0].id
}
