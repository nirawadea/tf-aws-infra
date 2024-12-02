
# Security Group for EC2 (Application Security Group)
resource "aws_security_group" "app_sg" {
  vpc_id = aws_vpc.csye6225_vpc.id

  name        = "application-security-group"
  description = "Allow traffic on ports 22 and application port."

  # Allow inbound SSH traffic
  ingress {
    description = "Allow SSH from Load Balancer SG"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Open to all,
    # Referencing the load balancer security group as the source
    # security_groups = [aws_security_group.lb_security_group.id]
  }

  # Allow inbound HTTP traffic
  #   ingress {
  #     description = "Allow HTTP"
  #     from_port   = 80
  #     to_port     = 80
  #     protocol    = "tcp"
  #     cidr_blocks = ["0.0.0.0/0"]
  #   }

  # Allow inbound HTTPS traffic
  #   ingress {
  #     description = "Allow HTTPS"
  #     from_port   = 443
  #     to_port     = 443
  #     protocol    = "tcp"
  #     cidr_blocks = ["0.0.0.0/0"]
  #   }

  # Allow inbound traffic on application port
  ingress {
    description = "Allow application traffic from Load Balancer SG"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    # Referencing the load balancer security group as the source
    security_groups = [aws_security_group.lb_security_group.id]

  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application-security-group"
  }
}

#Load Balancer Security Group
resource "aws_security_group" "lb_security_group" {
  name_prefix = "load-balancer-sg"
  description = "Security group for load balancer to access web application"
  vpc_id      = aws_vpc.csye6225_vpc.id

  #Allow HTTP traffic on port 80 from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS traffic on port 443 from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "${var.provider_profile}-load-balancer-sg"
  }
}

#Create DB Security Group for RDS
resource "aws_security_group" "db_security_group" {
  name        = "db_security_group"
  description = "Security Group for RDS Instance,inbound/outbound from the VPC"
  vpc_id      = aws_vpc.csye6225_vpc.id
  #   depends_on  = [aws_vpc.csye6225_vpc]

  # Ingress rule to allow traffic from application security group to MySQL
  ingress {
    description     = "Allow TCP traffic from application security group"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id] # Only allow traffic from app security group
  }

  # Restrict all outbound traffic (no egress required from the DB to external)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "database-security-group"
  }
}

# Create RDS Parameter Group
resource "aws_db_parameter_group" "db_param_group" {
  name        = "db-param-group"
  family      = "mysql8.0"
  description = "Custom parameter group for MySQL"

  parameter {
    name  = "max_connections"
    value = "500"  # Set this to the desired value
  }

  tags = {
    Name = "db-parameter-group"
  }
}

#db subnet group for rds
resource "aws_db_subnet_group" "db_subnet_group" {
  description = "Subnet group for RDS"
  subnet_ids  = [aws_subnet.private_subnet[0].id, aws_subnet.private_subnet[1].id, aws_subnet.private_subnet[2].id]
  tags = {
    "Name" = "db-subnet-group"
  }
}

# Generate a unique UUID for the bucket name
locals {
  bucket_name = "my-dev-bucket-${uuid()}"
}

# Create a private S3 bucket with encryption, lifecycle policy, and the ability to delete non-empty buckets
resource "aws_s3_bucket" "s3_bucket" {
  bucket        = lower(local.bucket_name)
  force_destroy = true # Allows deletion even if bucket is not empty
}

# Restrict Public Access to the Bucket
resource "aws_s3_bucket_public_access_block" "private_bucket" {
  bucket                  = aws_s3_bucket.s3_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle Policy for Storage Transition to STANDARD_IA after 30 days
resource "aws_s3_bucket_lifecycle_configuration" "bucket_lifecycle" {
  bucket = aws_s3_bucket.s3_bucket.id
  rule {
    id     = "transition-to-standard-ia"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "encrypt" {
  bucket = aws_s3_bucket.s3_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Create an IAM for Role for ec2 to access S3.
resource "aws_iam_role" "ec2_role" {
  name = "tf-s3-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Define the IAM policy for managing the S3 bucket
data "aws_iam_policy_document" "s3_management_policy" {
  statement {
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.s3_bucket.arn,
      "${aws_s3_bucket.s3_bucket.arn}/*"
    ]
  }
  depends_on = [aws_s3_bucket.s3_bucket]
}

# Attach the S3 Access Policy to the Role
resource "aws_iam_role_policy" "attach_s3_policy" {
  name       = "tf-s3-policy"
  policy     = data.aws_iam_policy_document.s3_management_policy.json
  role       = aws_iam_role.ec2_role.name
  depends_on = [aws_s3_bucket.s3_bucket]
}


# Create the RDS instance
resource "aws_db_instance" "rds" {
  allocated_storage      = var.db_storage_size
  identifier             = "csye6225"
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  instance_class         = var.db_instance_class
  engine                 = var.db_engine
  engine_version         = var.db_engine_version
  db_name                = var.db_name
  username               = var.db_username
  # password             = var.db_password
  password               = random_password.db_password.result # Use the generated password
  publicly_accessible    = var.db_public_access
  multi_az               = var.db_multiaz
  parameter_group_name   = aws_db_parameter_group.db_param_group.name
  skip_final_snapshot    = true

  #Enable encryption
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_key.arn

  tags = {
    Name        = "rds"
    Environment = "dev"
  }
}

#iam instance profile for ec2
resource "aws_iam_instance_profile" "ec2_profile" {
  role = aws_iam_role.ec2_role.name
}

# EC2 Instance
# resource "aws_instance" "app_instance" {
#   ami                         = var.custom_ami_id
#   instance_type               = "t3.medium"  # Default instance type
#   key_name                    = "cloupApp"
#   subnet_id                   = aws_subnet.public_subnet[0].id
#   vpc_security_group_ids      = [aws_security_group.app_sg.id]
#   iam_instance_profile        = aws_iam_instance_profile.ec2_profile.id
#   associate_public_ip_address = true  # Ensure instance has a public IP
#
#   # Root EBS Volume (SSD GP2, 25GB)
#   root_block_device {
#     volume_size           = 25
#     volume_type           = "gp2"
#     delete_on_termination = true
#   }
#   user_data = <<-EOF
#     #!/bin/bash
#     echo "DB_URL=jdbc:mysql://${aws_db_instance.rds.address}/csye6225" >> /etc/environment
#     echo "DB_USERNAME=${var.db_username}" >> /etc/environment
#     echo "DB_PASSWORD=${var.db_password}" >> /etc/environment
#     echo "S3_BUCKET_NAME=${aws_s3_bucket.s3_bucket.id}" >> /etc/environment
#     echo "FILESYSTEM_DRIVER=s3" >> /etc/environment
#     echo "REGION=${var.provider_region}" >> /etc/environment
#
#     source /etc/environment
#
#     #Restart cloudwatch
#     sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json -s
#
#     # Restart the application to ensure it picks up the environment variables
#     sudo systemctl restart csye6225.service
#   EOF
#
#   tags = {
#     Name = "ec2-app-instance"
#   }
#   depends_on = [aws_db_instance.rds]
# }


#Launch configuration template
resource "aws_launch_template" "app_launch_template" {
  name          = "csye6225_asg"
  image_id      = var.custom_ami_id
  instance_type = "t3.medium" # Default instance type
  key_name      = "cloupApp"
  #   iam_instance_profile        = aws_iam_instance_profile.ec2_profile.id

  network_interfaces {
    associate_public_ip_address = true # Ensure instance has a public IP
    security_groups             = [aws_security_group.app_sg.id]
  }

  # Root EBS Volume
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 25
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }
  # echo "DB_URL=jdbc:mysql://${aws_db_instance.rds.address}/csye6225" >> /etc/environment
  # echo "DB_USERNAME=${var.db_username}" >> /etc/environment
  # echo "DB_PASSWORD=${random_password.db_password.result}" >> /etc/environment

  # User data script
  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "SECRET_NAME"  =${aws_secretsmanager_secret.db_credentials.arn} >> /etc/environment
    echo "S3_BUCKET_NAME=${aws_s3_bucket.s3_bucket.id}" >> /etc/environment
    echo "FILESYSTEM_DRIVER=s3" >> /etc/environment
    echo "REGION=${var.provider_region}" >> /etc/environment
    echo "SNS_TOPIC_ARN=${aws_sns_topic.user_creation_topic.arn}" >> /etc/environment

    source /etc/environment

    #Restart cloudwatch
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json -s

    # Restart the application to ensure it picks up the environment variables
    sudo systemctl restart csye6225.service
  EOF
  )

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.id
  }

  # Tags for instances launched from this template
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "ec2-app-instance"
    }
  }
}

#Auto Scaling Group
resource "aws_autoscaling_group" "app_asg" {
  name              = "app_asg"
  target_group_arns = [aws_lb_target_group.webapp_tg.arn]
  launch_template {
    id      = aws_launch_template.app_launch_template.id
    version = "$Latest"
  }

  min_size            = 2
  max_size            = 5
  desired_capacity    = 2
  vpc_zone_identifier = [for s in aws_subnet.public_subnet : s.id]

  # Health Check Configuration
  health_check_type         = "EC2"
  health_check_grace_period = 500
  default_cooldown          = 60

  # Auto Scaling Tags
  tag {
    key                 = "Name"
    value               = "ec2-app-instance"
    propagate_at_launch = true
  }
  depends_on = [aws_db_instance.rds]
}

#Defining auto scale policies for CPU utilization
resource "aws_cloudwatch_metric_alarm" "scale_up_alarm" {
  alarm_name          = "high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric checks if CPU usage is higher than 5%."
  alarm_actions       = [aws_autoscaling_policy.scale_up_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

#Scale up policy
resource "aws_autoscaling_policy" "scale_up_policy" {
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  name                   = "webapp_scale-up-policy"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
}

#AS for scale down
resource "aws_cloudwatch_metric_alarm" "scale_down_alarm" {
  alarm_name          = "low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 3
  alarm_description   = "This metric checks if CPU usage is lower than 3%."
  alarm_actions       = [aws_autoscaling_policy.scale_down_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

#Scale down policy
resource "aws_autoscaling_policy" "scale_down_policy" {
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  name                   = "webapp_scale-down-policy"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
}

#Application Load Balancer
resource "aws_alb" "webapp_lb" {
  name               = "${var.provider_profile}-app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public_subnet : s.id]
  security_groups    = [aws_security_group.lb_security_group.id]

  tags = {
    Name = "${var.provider_profile}-app-load-balancer"
  }
}

# Target Group for Application Instances
resource "aws_lb_target_group" "webapp_tg" {
  name        = "webapp-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.csye6225_vpc.id
  target_type = "instance"

  health_check {
    path = "/healthz"
    # port                = 8080
    # protocol            = "HTTP"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 2
    unhealthy_threshold = 5
    matcher             = "200"
  }
  tags = {
    Name = "webapp-target-group"
  }
}

# Listener for Application Load Balancer
# resource "aws_lb_listener" "http" {
#   load_balancer_arn = aws_alb.webapp_lb.arn
#   port              = 80
#   protocol          = "HTTP"
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.webapp_tg.arn
#   }
# }
  resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_alb.webapp_lb.arn
  port              = 443
  protocol          = "HTTPS"

  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.dev_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webapp_tg.arn
  }
  depends_on = [aws_route53_record.cert_validation]
}

resource "aws_route53_record" "cert_validation" {
  for_each = { for dvo in aws_acm_certificate.dev_certificate.domain_validation_options : dvo.domain_name => dvo }

  zone_id = data.aws_route53_zone.selected_zone.id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  ttl     = 300
  records = [each.value.resource_record_value]

  depends_on = [aws_acm_certificate.dev_certificate]
}


# Find the Hosted Zone
data "aws_route53_zone" "selected_zone" {
  name = var.domain_name
}

# Create or Update Route 53 A Record
# Create a new A record that points to the Load balancer.
resource "aws_route53_record" "app_record" {
  name                     = data.aws_route53_zone.selected_zone.name
  type                     = "A"
  zone_id = data.aws_route53_zone.selected_zone.id
  #   ttl     = "60"
  alias {
    evaluate_target_health = true
    name                   = aws_alb.webapp_lb.dns_name
    zone_id                = aws_alb.webapp_lb.zone_id
  }
  # Set the record to the EC2 instance's public IP
  #   records = [aws_launch_template.app_instance.public_ip]
}


data "aws_iam_policy" "agent_policy" {
  arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "agent_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = data.aws_iam_policy.agent_policy.arn
}

#create sns topic
resource "aws_sns_topic" "user_creation_topic" {
  name = "my-user-creation-topic"
}

#lambda function
resource "aws_lambda_function" "my_sns_lambda" {
  function_name = "my_sns_lambda_function"
  role          =  aws_iam_role.lambda_execution_role.arn
  handler       = "awslambda.EmailVerificationLambda::handleRequest"
  runtime       = "java17"
  memory_size   = 512
  timeout       = 60

  #path to lambda function code
  filename = "/Users/macbookpro/Desktop/spring-serverless-1.0-SNAPSHOT.jar"

  environment {
    variables = {
      # SEND_GRID_API_KEY     = var.sendgrid_api_key
      SEND_GRID_SECRET_NAME = "sendgrid-api-key-new6"
      SEND_GRID_DOMAIN_NAME = var.domain_name
      SNS_TOPIC_ARN         = aws_sns_topic.user_creation_topic.arn
    }
  }
}

# SNS Subscription to Trigger Lambda
resource "aws_sns_topic_subscription" "sns_lamdba_subscription" {
  topic_arn = aws_sns_topic.user_creation_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.my_sns_lambda.arn
}

#Allow sns to invoke lambda function
resource "aws_lambda_permission" "allow_sns_invoke" {
  statement_id    = "AllowExecutionFromSNS"
  action          = "lambda:InvokeFunction"
  function_name   = aws_lambda_function.my_sns_lambda.function_name
  principal       = "sns.amazonaws.com"
  source_arn      = aws_sns_topic.user_creation_topic.arn
}

#crete Role and policies for lambda
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda_execution_role"

  assume_role_policy = jsonencode({
    Version       = "2012-10-17",
    Statement     = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Policy for accessing SNS and RDS (customize the resource ARNs)
resource "aws_iam_policy" "lambda_access_policy" {
  name = "lambda_access_policy"

  policy         = jsonencode({
    Version      = "2012-10-17",
    Statement    = [
      {
        Action   = [
          "sns:Publish",
          "secretsmanager:GetSecretValue"
        ],
        Effect   = "Allow",
        Resource  = [
          aws_sns_topic.user_creation_topic.arn,
          aws_secretsmanager_secret.sendgrid_api_key.arn
        ]
      },
      {
        Action   = [
          "rds:DescribeDBInstances",
          "rds-db:connect"
        ],
        Effect   = "Allow",
        Resource = aws_db_instance.rds.arn
      },
      {
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:us-east-1:047719656602:log-group:/aws/lambda/my_sns_lambda_function:*"
      },
      {
        Effect   = "Allow",
        Action   = [
          "kms:Decrypt"
        ],
        Resource = aws_secretsmanager_secret.sendgrid_api_key.kms_key_id
      }
    ]
  })
}

# Attach the policy to the Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_access_policy.arn
}

# IAM policy for SNS publishing
resource "aws_iam_policy" "sns_publish_policy" {
  name        = "sns_publish_policy"
  description = "Policy to allow publishing to the SNS topic for user creation"

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "sns:Publish",
        Resource = aws_sns_topic.user_creation_topic.arn
      }
    ]
  })
}

# Attach the sns policy to the IAM role for EC2
resource "aws_iam_role_policy_attachment" "sns_publish_policy_attachment" {
  role       = aws_iam_role.ec2_role.name # Replace with your actual IAM role name
  policy_arn = aws_iam_policy.sns_publish_policy.arn
}

#Auto-Generate DB password
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*+,-.:;<=>?[]^_{|}~"  # Allow only specific special characters if needed
}

#create KMS key for EC2
resource "aws_kms_key" "ec2_key" {
  description         = "KMS key for EC2 encryption"
  enable_key_rotation = true
}

#create KMS key for RDS
resource "aws_kms_key" "rds_key" {
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
}

#create KMS key for s3
resource "aws_kms_key" "s3_key" {
  description         = "KMS key for S3 bucket encryption"
  enable_key_rotation = true
}

#create KMS key for secret manager
resource "aws_kms_key" "secrets_key" {
  description         = "KMS key for Secrets Manager encryption"
  enable_key_rotation = true
}

# Define the secret for SendGrid API key
resource "aws_secretsmanager_secret" "sendgrid_api_key" {
  name        = "sendgrid-api-key-new6"
  description = "SendGrid API key for email service"
  kms_key_id  = aws_kms_key.secrets_key.arn
}

# Store the SendGrid API key in the secret
resource "aws_secretsmanager_secret_version" "sendgrid_api_key_version" {
  secret_id     = aws_secretsmanager_secret.sendgrid_api_key.id
  secret_string = jsonencode({
    # api_key     = "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"
    api_key = var.sendgrid_api_key
  })
}

# Store the db secret in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name       = "db_credentials_new6"
  kms_key_id = aws_kms_key.secrets_key.arn
}

# Add the secret version with the generated password
resource "aws_secretsmanager_secret_version" "db_credentials_version" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id

  secret_string = jsonencode({
    DB_URL      = "jdbc:mysql://${aws_db_instance.rds.address}/csye6225",
    DB_USERNAME = var.db_username,
    DB_PASSWORD = random_password.db_password.result
  })
}

# IAM policy for accessing the secret
resource "aws_iam_policy" "ec2_secrets_access_policy" {
  name           = "ec2-secrets-access-policy"
  policy         = jsonencode({
    Version      = "2012-10-17",
    Statement    = [
      {
        Action   = ["secretsmanager:GetSecretValue"],
        Effect   = "Allow",
        # Resource = aws_secretsmanager_secret.db_credentials.arn
        Resource = [
          aws_secretsmanager_secret.db_credentials.arn,
          aws_secretsmanager_secret.sendgrid_api_key.arn
        ]
      }
    ]
  })
}

# Attach the secrets policy to the EC2 IAM role
resource "aws_iam_role_policy_attachment" "ec2_secrets_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_secrets_access_policy.arn
}

# Attach the policy to Lambda IAM role
resource "aws_iam_role_policy_attachment" "lambda_secrets_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.ec2_secrets_access_policy.arn
}

# IAM Policy to allow access to KMS keys
resource "aws_iam_policy" "kms_policy" {
  name   = "kms-access-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ],
        Resource  = [
          aws_kms_key.ec2_key.arn,
          aws_kms_key.rds_key.arn,
          aws_kms_key.s3_key.arn,
          aws_kms_key.secrets_key.arn
        ]
      }
    ]
  })
}

#Lambda role requires additional permissions for accessing Secrets Manager, RDS, and SNS:
# resource "aws_iam_policy" "lambda_access_policy" {
#   name   = "lambda-access-policy"
#
#   policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect    = "Allow",
#         Action    = [
#           "sns:Publish",
#           "secretsmanager:GetSecretValue"
#         ],
#         Resource  = [
#           aws_sns_topic.user_creation_topic.arn,
#           aws_secretsmanager_secret.sendgrid_api_key.arn
#         ]
#       },
#       {
#         Effect    = "Allow",
#         Action    = [
#           "rds:DescribeDBInstances",
#           "rds-db:connect"
#         ],
#         Resource  = aws_db_instance.rds.arn
#       }
#     ]
#   })
# }

#attch this above policy to lambda
resource "aws_iam_role_policy_attachment" "lambda_access_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_access_policy.arn
}


# Attach the policy to relevant roles
resource "aws_iam_role_policy_attachment" "attach_kms_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.kms_policy.arn
}

#ACM to provision an SSL certificate
resource "aws_acm_certificate" "dev_certificate" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = {
    Environment = "dev"
  }
}









