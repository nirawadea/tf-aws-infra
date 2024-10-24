
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

# EC2 Instance
resource "aws_instance" "app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = "t3.medium"  # Default instance type
  key_name                    = "cloupApp"
  subnet_id                   = aws_subnet.public_subnet[0].id
  vpc_security_group_ids      = [aws_security_group.app_sg.id]
  associate_public_ip_address = true  # Ensure instance has a public IP

  # Root EBS Volume (SSD GP2, 25GB)
  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  user_data = <<EOF
  #!/bin/bash
  set -e  # Exit script on error
  set -x  # Enable debug mode for easier troubleshooting

  # Clear /etc/environment file and write new environment variables
  sudo truncate -s 0 /etc/environment

  # Add environment variables
  echo "DATABASE_ENDPOINT=${aws_db_instance.rds.address}" | sudo tee -a /etc/environment
  echo "DATABASE_NAME=${var.db_name}" | sudo tee -a /etc/environment
  echo "DB_USERNAME=${var.db_username}" | sudo tee -a /etc/environment
  echo "DB_PASSWORD=${var.db_password}" | sudo tee -a /etc/environment

  # Load the environment variables for the current shell session
  set -o allexport
  . /etc/environment
  set +o allexport

  # Ensure the application directory exists
  mkdir -p /opt/cloudApp

  # Wait for 30 seconds to ensure services are ready (you can adjust this)
  sleep 30

  # Restart the systemd service to load new environment variables
  sudo systemctl daemon-reload

  # Enable and start the application service
  sudo systemctl enable csye6225.service
  sudo systemctl start csye6225.service

  # Check the status of the service
  sudo systemctl status csye6225.service
  EOF


  tags = {
    Name = "ec2-app-instance"
  }
  depends_on = [aws_db_instance.rds]
}