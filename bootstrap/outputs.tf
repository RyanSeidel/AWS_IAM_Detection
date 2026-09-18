output "state_bucket_name" {
  description = "Name of the Terraform state bucket."
  value       = aws_s3_bucket.tfstate.id
}

output "backend_config_snippet" {
  description = "Paste this into main/backend.hcl (that file is gitignored — it would otherwise leak the account ID)."
  value       = <<-EOT
    bucket       = "${aws_s3_bucket.tfstate.id}"
    key          = "${var.project_name}/terraform.tfstate"
    region       = "${var.aws_region}"
    use_lockfile = true
  EOT
}
