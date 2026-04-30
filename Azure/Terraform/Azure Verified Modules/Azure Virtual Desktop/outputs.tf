# Output the randomly generated password for the session host VMs (marked sensitive to prevent display in logs)
output "vm_password" {
  value     = random_password.vmpass.result
  sensitive = true
}

# Output the role assignment ID for the AVD power on/off contributor role
# Uses the existing role assignment if one already exists, otherwise uses the newly created one
output "avd_power_role_assignment_id" {
  value = local.role_assignment_exists ? local.matching_role_assignments[0].id : azapi_resource.avd_power_on_off_contributor[0].id
}
