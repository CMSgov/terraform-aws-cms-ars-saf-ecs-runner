data "aws_ami" "ecs_ami" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-*-amazon-ecs-optimized"]
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "cloudwatch_logs_allow_kms" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }

    actions = [
      "kms:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow logs KMS access"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.us-west-2.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]
    resources = ["*"]
  }
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-west-2a"]
  public_subnets  = ["10.0.101.0/24"] // not using but needed for nat, can we use internet gateway?
  private_subnets = ["10.0.1.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = {
    Automation  = "Terraform"
    Environment = "Test"
  }
}

resource "aws_kms_key" "log_enc_key" {
  description         = "KMS key for encrypting logs"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.cloudwatch_logs_allow_kms.json

  tags = {
    Automation = "Terraform"
  }
}

resource "aws_ecs_cluster" "inspec_cluster" {
  name = "inspec"
  tags = {
    Environment = var.environment
    Automation  = "Terraform"
  }
  lifecycle {
    create_before_destroy = true
  }
}

# ECS service for running inspec profile container
module "cms_ecs_service" {
  source = "trussworks/ecs-service/aws"

  name          = "cis-aws"
  environment   = "test"
  ecr_repo_arns = [var.cms_ars_repo_arn]

  ecs_cluster = {
    name = aws_ecs_cluster.inspec_cluster.name,
    arn  = aws_ecs_cluster.inspec_cluster.arn
  }

  logs_cloudwatch_retention = 731
  ecs_vpc_id                = module.vpc.vpc_id
  ecs_subnet_ids            = module.vpc.private_subnets
  kms_key_id                = aws_kms_key.log_enc_key.arn
  ecs_use_fargate           = true
}

### ECS schedule task ##

### Set up Assume Role policies

locals {
  name                = "inspec"
  environment         = "test"
  task_name           = "aws-moderate-scan"
  schedule_expression = "cron(30 9 * * ? *)" // run 9:30 everyday
  // minute, hour, day of month, month, day of week, year
  //https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html

  repo_url = "004351505091.dkr.ecr.us-west-2.amazonaws.com/cms-aws-inspec-profile"
  repo_tag = "1613146248"

}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "ecs_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    effect = "Allow"
  }
}

data "aws_iam_policy_document" "events_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    effect = "Allow"
  }
}

### CloudWatch Target IAM
# Allows CloudWatch Rule to run ECS Task

data "aws_iam_policy_document" "cloudwatch_target_role_policy_doc" {
  statement {
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }

  statement {
    actions   = ["ecs:RunTask"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "cloudwatch_target_role" {
  name               = "cw-target-role-${local.name}-${var.environment}-${var.task_name}"
  description        = "Role allowing CloudWatch Events to run the task"
  assume_role_policy = data.aws_iam_policy_document.events_assume_role_policy.json
}

resource "aws_iam_role_policy" "cloudwatch_target_role_policy" {
  name   = "${aws_iam_role.cloudwatch_target_role.name}-policy"
  role   = aws_iam_role.cloudwatch_target_role.name
  policy = data.aws_iam_policy_document.cloudwatch_target_role_policy_doc.json
}

### ECS Task Role
# Allows ECS to start the task by decrypting secrets for Chamber

data "aws_iam_policy_document" "task_role_policy_doc" {
  # Allow access to the environment specific app secrets
  statement {
    actions = [
      "ssm:GetParametersByPath",
    ]

    resources = ["arn:${data.aws_partition.current.partition}:ssm:*:*:parameter/${local.name}-${var.environment}/*"]
  }
}

resource "aws_iam_role_policy_attachment" "read_only_everything" {
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
  role       = aws_iam_role.task_role.name
}

resource "aws_iam_role" "task_role" {
  name               = "ecs-task-role-${local.name}-${var.environment}-${local.task_name}"
  description        = "Role allowing container definition to execute"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

resource "aws_iam_role_policy" "task_role_policy" {
  name   = "${aws_iam_role.task_role.name}-policy"
  role   = aws_iam_role.task_role.name
  policy = data.aws_iam_policy_document.task_role_policy_doc.json
}

### ECS Task Execution Role https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html
# Allows ECS to Pull down the ECR Image and write Logs to CloudWatch

data "aws_iam_policy_document" "task_execution_role_policy_doc" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${module.cms_ecs_service.awslogs_group_arn}:*"]
  }

  statement {
    actions = [
      "ecr:GetAuthorizationToken",
    ]

    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]

    resources = [module.cms_ars_repo.arn]
  }

  statement {
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:/${local.name}-${local.environment}*",
    ]
  }

  statement {
    actions = [
      "ssm:GetParameters",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.name}-${local.environment}*",
    ]
  }
}

resource "aws_iam_role" "task_execution_role" {
  name               = "ecs-task-exec-role-${local.name}-${local.environment}-${local.task_name}"
  description        = "Role allowing ECS tasks to execute"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

resource "aws_iam_role_policy" "task_execution_role_policy" {
  name   = "${aws_iam_role.task_execution_role.name}-policy"
  role   = aws_iam_role.task_execution_role.name
  policy = data.aws_iam_policy_document.task_execution_role_policy_doc.json
}

#
# CloudWatch
#

resource "aws_cloudwatch_event_rule" "run_command" {
  name                = "${local.task_name}-${local.environment}"
  description         = "Scheduled task for ${local.task_name} in ${local.environment}"
  schedule_expression = local.schedule_expression
}

resource "aws_cloudwatch_event_target" "ecs_scheduled_task" {
  target_id = "run-scheduled-task-${local.task_name}-${local.environment}"
  arn       = aws_ecs_cluster.inspec_cluster.arn
  rule      = aws_cloudwatch_event_rule.run_command.name
  role_arn  = aws_iam_role.cloudwatch_target_role.arn

  ecs_target {
    launch_type = "FARGATE"
    task_count  = 1

    # Use latest active revision
    task_definition_arn = aws_ecs_task_definition.scheduled_task_def.arn

    network_configuration {
      subnets          = module.vpc.private_subnets
      security_groups  = [module.cms_ecs_service.ecs_security_group_id]
      assign_public_ip = false
    }
  }

  lifecycle {
    ignore_changes = [ecs_target[0].task_definition_arn]
  }
}

#
# ECS
#

resource "aws_ecs_task_definition" "scheduled_task_def" {
  family        = "${local.name}-${local.environment}-${local.task_name}"
  network_mode  = "awsvpc"
  task_role_arn = aws_iam_role.task_role.arn

  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "1024"
  execution_role_arn       = join("", aws_iam_role.task_execution_role.*.arn)

  container_definitions = <<DEFINITION
[
  {
    "name": "${local.name}-${local.environment}-${local.task_name}",
    "image": "${local.repo_url}:${local.repo_tag}",
    "cpu": 128,
    "memory": 1024,
    "essential": true,
    "portMappings": [],
    "environment": [],
      "logConfiguration": {
        "logDriver": "awslogs",
        "secretOptions": null,
        "options": {
          "awslogs-group": "/ecs/test/cis-aws",
          "awslogs-region": "${data.aws_region.current.name}",
          "awslogs-stream-prefix": "cis-task"
        }
      },
    "mountPoints": [],
    "volumesFrom": [],
    "entryPoint": [
            "inspec",
            "exec",
            "profiles/cms-ars-3.1-moderate-aws-foundations-cis-overlay",
            "--target",
            "aws://",
            "--chef-license",
            "accept-silent",
            "--no-color"
          ]
  }
]
DEFINITION
}

# Create a data source to pull the latest active revision from
data "aws_ecs_task_definition" "scheduled_task_def" {
  task_definition = aws_ecs_task_definition.scheduled_task_def.family
  depends_on      = [aws_ecs_task_definition.scheduled_task_def] # ensures at least one task def exists
}


