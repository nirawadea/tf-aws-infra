
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


# EC2 Instance
resource "aws_instance" "app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = "t3.micro"  # Default instance type
  subnet_id                   = aws_subnet.public_subnet[0].id
  vpc_security_group_ids      = [aws_security_group.app_sg.id]
  associate_public_ip_address = true  # Ensure instance has a public IP

  # Root EBS Volume (SSD GP2, 25GB)
  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "ec2-app-instance"
  }
}








