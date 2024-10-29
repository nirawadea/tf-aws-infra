
# Security Group for EC2 (Application Security Group)
resource "aws_security_group" "app_sg" {
  vpc_id      = aws_vpc.csye6225_vpc.id

  name        = "application-security-group"
  description = "Allow traffic on ports 22, 80, 443, and application port."

  # Allow inbound SSH traffic
  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to all, change if needed
  }

  # Allow inbound HTTP traffic
  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow inbound HTTPS traffic
  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow inbound traffic on application port
  ingress {
    description = "Allow application traffic"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

#Create DB Security Group for RDS
resource "aws_security_group" "db_security_group" {
  name        = "db_security_group"
  description = "Security Group for RDS Instance,inbound/outbound from the VPC"
  vpc_id      = aws_vpc.csye6225_vpc.id
#   depends_on  = [aws_vpc.csye6225_vpc]

  # Ingress rule to allow traffic from application security group to MySQL
  ingress {
    description = "Allow TCP traffic from application security group"
    from_port   =  3306
    to_port     =  3306
    protocol    = "tcp"
    security_groups = [aws_security_group.app_sg.id]   # Only allow traffic from app security group
  }

  # Restrict all outbound traffic (no egress required from the DB to external)
  egress {
    from_port     = 0
    to_port       = 0
    protocol      = "-1"
    cidr_blocks   = ["0.0.0.0/0"]
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
  bucket = lower(local.bucket_name)
  force_destroy = true # Allows deletion even if bucket is not empty
}

# Restrict Public Access to the Bucket
resource "aws_s3_bucket_public_access_block" "private_bucket" {
  bucket = aws_s3_bucket.s3_bucket.id
  block_public_acls        = true
  block_public_policy      = true
  ignore_public_acls       = true
  restrict_public_buckets  = true
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

# Create an IAM Role for S3 Access.
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
  allocated_storage       = var.db_storage_size
  identifier              = "csye6225"
  db_subnet_group_name    = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.db_security_group.id]
  instance_class          = var.db_instance_class
  engine                  = var.db_engine
  engine_version          = var.db_engine_version
  db_name                 = var.db_name
  username                = var.db_username
  password                = var.db_password
  publicly_accessible     = var.db_public_access
  multi_az                = var.db_multiaz
  parameter_group_name    = aws_db_parameter_group.db_param_group.name
  skip_final_snapshot     = true

  tags = {
    Name                  = "rds"
    Environment           = "dev"
  }
}

#iam instance profile for ec2
resource "aws_iam_instance_profile" "ec2_profile" {
  role = aws_iam_role.ec2_role.name
}

# EC2 Instance
resource "aws_instance" "app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = "t3.medium"  # Default instance type
  key_name                    = "cloupApp"
  subnet_id                   = aws_subnet.public_subnet[0].id
  vpc_security_group_ids      = [aws_security_group.app_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.id
  associate_public_ip_address = true  # Ensure instance has a public IP

  # Root EBS Volume (SSD GP2, 25GB)
  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<-EOF
    #!/bin/bash
    echo "DB_URL=jdbc:mysql://${aws_db_instance.rds.address}/csye6225" >> /etc/environment
    echo "DB_USERNAME=${var.db_username}" >> /etc/environment
    echo "DB_PASSWORD=${var.db_password}" >> /etc/environment

    source /etc/environment
    # Restart the application to ensure it picks up the environment variables
    sudo systemctl restart myapp.service
  EOF

  tags = {
    Name = "ec2-app-instance"
  }
  depends_on = [aws_db_instance.rds]
}

# Find the Hosted Zone
data "aws_route53_zone" "selected_zone"{
  name = var.domain_name
}

# Create or Update Route 53 A Record
resource "aws_route53_record" "app_record" {
  name    = data.aws_route53_zone.selected_zone.name
  type    = "A"
  zone_id = data.aws_route53_zone.selected_zone.id
  ttl     = "60"
  # Set the record to the EC2 instance's public IP
  records = [aws_instance.app_instance.public_ip]
}

data "aws_iam_policy" "agent_policy" {
  arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "agent_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = data.aws_iam_policy.agent_policy.arn
}



