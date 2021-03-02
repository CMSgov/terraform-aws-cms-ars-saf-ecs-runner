variable "app_name" {
  type = string
  description = "Name of the application"
}

variable "task_name" {
  type = string
  description = "Name of the task to be run"
}

variable "cms_ars_repo_arn" {
  type        = string
  description = "Arn of the ecr repo hosting the scanner container image"
}

variable "environment" {
  type = string
  description = "Environment name"
}

variable "tags" {
  type        = map(any)
  description = "Additional tags to apply."
  default     = {}
}

variable "scan_on_push" {
  type        = bool
  description = "Scan image on push to repo."
  default     = true
}