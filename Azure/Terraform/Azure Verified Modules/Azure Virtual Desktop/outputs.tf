output "vm_password" {
  value     = random_password.vmpass.result
  sensitive = true
}

