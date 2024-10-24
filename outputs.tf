output "vpc_id" {
  description = "ID of the VPC"
  value = aws_vpc.csye6225_vpc.id
}

# Output for the VPC CIDR block
output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.csye6225_vpc.cidr_block
}

output "public_subnets" {
  value = aws_subnet.public_subnet[*].id
}

output "private_subnets" {
  value = aws_subnet.private_subnet[*].id
}

output "internet_gateway_id" {
  value = aws_internet_gateway.igw.id
}

# Output for the application security group
output "app_sg_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app_sg.id
}

# Output for the database security group
output "db_sg_id" {
  description = "ID of the database security group"
  value       = aws_security_group.db_security_group.id
}

# Output for the RDS DB subnet group
output "db_subnet_group_name" {
  description = "Name of the RDS DB subnet group"
  value       = aws_db_subnet_group.db_subnet_group.name
}

# Output for the EC2 instance ID
output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.app_instance.id
}

# Output for the RDS instance identifier
output "rds_instance_identifier" {
  description = "RDS instance identifier"
  value       = aws_db_instance.rds.identifier
}