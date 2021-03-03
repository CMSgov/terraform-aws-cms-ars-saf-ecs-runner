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

# Create a data source to pull the latest active revision from
data "aws_ecs_task_definition" "scheduled_task_def" {
  task_definition = aws_ecs_task_definition.scheduled_task_def.family
  depends_on      = [aws_ecs_task_definition.scheduled_task_def] # ensures at least one task def exists
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
  name = "${var.app_name}-inspec"

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
  ecs_vpc_id                = var.ecs_vpc_id
  ecs_subnet_ids            = var.ecs_subnet_ids
  kms_key_id                = aws_kms_key.log_enc_key.arn
  ecs_use_fargate           = true
}

### ECS schedule task ##

### Set up Assume Role policies

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
  name               = "cw-target-role-${var.app_name}-${var.environment}-${var.task_name}"
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

    resources = ["arn:${data.aws_partition.current.partition}:ssm:*:*:parameter/${var.app_name}-${var.environment}/*"]
  }
}

resource "aws_iam_role_policy_attachment" "read_only_everything" {
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
  role       = aws_iam_role.task_role.name
}

resource "aws_iam_role" "task_role" {
  name               = "ecs-task-role-${var.app_name}-${var.environment}-${var.task_name}"
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
      "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:/${var.app_name}-${var.environment}*",
    ]
  }

  statement {
    actions = [
      "ssm:GetParameters",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.app_name}-${var.environment}*",
    ]
  }
}

resource "aws_iam_role" "task_execution_role" {
  name               = "ecs-task-exec-role-${var.app_name}-${var.environment}-${var.task_name}"
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
  name                = "${var.task_name}-${var.environment}"
  description         = "Scheduled task for ${var.task_name} in ${var.environment}"
  schedule_expression = var.schedule_task_expression
}

resource "aws_cloudwatch_event_target" "ecs_scheduled_task" {
  target_id = "run-scheduled-task-${var.task_name}-${var.environment}"
  arn       = aws_ecs_cluster.inspec_cluster.arn
  rule      = aws_cloudwatch_event_rule.run_command.name
  role_arn  = aws_iam_role.cloudwatch_target_role.arn

  ecs_target {
    launch_type = "FARGATE"
    task_count  = 1

    # Use latest active revision
    task_definition_arn = aws_ecs_task_definition.scheduled_task_def.arn

    network_configuration {
      subnets          = var.ecs_subnet_ids
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
  family        = "${var.app_name}-${var.environment}-${var.task_name}"
  network_mode  = "awsvpc"
  task_role_arn = aws_iam_role.task_role.arn

  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "1024"
  execution_role_arn       = join("", aws_iam_role.task_execution_role.*.arn)

  container_definitions = <<DEFINITION
[
  {
    "name": "${var.app_name}-${var.environment}-${var.task_name}",
    "image": "${var.repo_url}:${var.repo_tag}",
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

