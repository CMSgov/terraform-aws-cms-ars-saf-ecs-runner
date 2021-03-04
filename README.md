# terraform-aws-cms-ars-saf-ecs-runner

This repo contains a Terraform module which will deploy a scheduled ECS
task which can run a periodic Inspec scan against an AWS account. The module supports following features:

* Run an ECS task and stream output to Cloudwatch
* Cloudwatch rule to run tasks on a cron based cadence
* Use a user defined ECR repo to run ECs tasks 

## Usage

```hcl
module "ecs_saf_runner" {
  source = "github.com/CMSgov/terraform-aws-cms-ars-saf-ecs-runner"
  
  app_name    = "aws-scanner"
  environment = "prod"
  
  task_name                = "CIS-Moderate"
  ecs_vpc_id               = module.vpc.vpc_id
  ecs_subnet_ids           = module.vpc.private_subnets
  repo_url                 = module.ecr.url
  repo_tag                 = "latest"
  schedule_task_expression = "cron(30 9 * * ? *)"
  repo_arn                 = module.ecr.arn
}

```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.13 |
| aws | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 3.0 |

## Modules

No Modules.
