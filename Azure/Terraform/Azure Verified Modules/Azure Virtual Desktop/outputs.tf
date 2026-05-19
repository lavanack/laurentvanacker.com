###############################################################################
# Outputs for the Azure Virtual Desktop deployment.
#
# Exposes:
#   - The generated local-admin password for the session host VMs (sensitive)
#   - The ID of the AVD "Power On/Off Contributor" role assignment
#     (existing one if already present, otherwise the newly created assignment)
#   - The deterministic host pool name (useful for downstream tooling/CI)
###############################################################################

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


# Deterministic name of the deployed AVD host pool (see locals.tf)
output "hostpool_name" {
  value = local.virtual_desktop_hostpool_name
}


output "public_ip" {
  value = data.http.ip.response_body
}
