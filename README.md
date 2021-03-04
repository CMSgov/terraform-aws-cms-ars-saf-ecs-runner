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
  ecs_vpc_id               = aws_vpc.myvpc.id
  ecs_subnet_ids           = [aws_subnet.mysubnet.id]
  repo_url                 = aws_ecr_repository.ecrrepo.repository_url
  repo_tag                 = "latest"
  schedule_task_expression = "cron(30 9 * * ? *)"
  repo_arn                 = aws_ecr_repository.ecrrepo.arn
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
