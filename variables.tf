variable "app_name" {
  type = string
  description = "Name of the application"
}

variable "task_name" {
  type = string
  description = "Name of the task to be run"
}

variable "ecs_vpc_id" {
  description = "VPC ID to be used by ECS."
  type        = string
}

variable "ecs_subnet_ids" {
  description = "Subnet IDs for the ECS tasks."
  type        = list(string)
}

variable "logs_cloudwatch_retention" {
  description = "Number of days you want to retain log events in the log group"
  default = 732 //  two years
  type = number
}

variable "logs_cloudwatch_group" {
  description = "CloudWatch log group to create and use. Default: /ecs/{app_name}-{environment}"
  default     = ""
  type        = string
}

variable "repo_url" {
  type = string
  description = "The url of the ECR repo to pull images and run in ecs"
}

variable "repo_tag" {
  type = string
  description = "The tag to identify and pull the image in ECR repo"
  default = "latest"
}

variable "schedule_task_expression" {
  type = string
  description = "Cron based schedule task to run on a cadence"
  default = "cron(30 9 * * ? *)" // run 9:30 everyday"
}

variable "repo_arn" {
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
}v