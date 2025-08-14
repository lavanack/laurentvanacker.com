plugin "azurerm" {
    enabled = true
    version = "0.27.0"
    source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# General Terraform rules
rule "terraform_deprecated_interpolation" {
  enabled = true
}
 
# Disallow variables, data sources, and locals that are declared but never used.
rule "terraform_unused_declarations" {
enabled = true
}
 
# Disallow // comments in favor of #.
rule "terraform_comment_syntax" {
enabled = false
}
 
# Disallow output declarations without description.
rule "terraform_documented_outputs" {
enabled = true
}
 
# Disallow variable declarations without description.
rule "terraform_documented_variables" {
enabled = true
}
 
# Disallow variable declarations without type.
rule "terraform_typed_variables" {
enabled = true
}

# Azure-specific rules

# Additional customisations as needed
