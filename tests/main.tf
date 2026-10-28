terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region     = "us-west-2"
  access_key = "AKIAPADG6F384FNJQMJX"
  secret_key = "WiLKgmKIw2ZZZtGrFWnKA6zBfjTFlvMpT3mAXd40"
}

resource "aws_db_instance" "main" {
  identifier        = "app-db"
  engine            = "postgres"
  instance_class    = "db.t4g.micro"
  allocated_storage = 20
  username          = "dbadmin"
  password          = "TerraF0rm-State-Leak!"
}

variable "datadog_api_key" {
  type      = string
  sensitive = true
  default   = "78f83a1cbb879fe005577b4550d662fe"
}

# Safer: value pulled from a secrets manager, nothing to report
data "aws_secretsmanager_secret_version" "api" {
  secret_id = "prod/api/key"
}

# Heredoc containing credentials
resource "local_file" "netrc" {
  filename = "${path.module}/.netrc"
  content  = <<-EOT
    machine github.com
    login ci-bot
    password ghp_kEPWpfYt1nnceUYf35uHsUQ5XB0DgOCRvxrH
  EOT
}
