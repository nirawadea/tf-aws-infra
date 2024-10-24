variable "cidr" {
  type        = string
  description = "The CIDR block for the VPC"
}

variable "provider_profile" {
  description = "Profile for Provider"
  type        = string
  default     = "dev"
}

variable "provider_region" {
  description = "Region for Provider"
  type        = string
  default     = "us-east-1"
}


variable "public_subnet_cidrs" {
  description = "CIDR blocks for the public subnets"
  type        = list(string)
 
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the private subnets"
  type        = list(string)
  
}

variable "availability_zones" {
  description = "The list of availability zones"
  type        = list(string)
  
}

variable "custom_ami_id" {
  description = "The ID of the custom AMI to use for the EC2 instance."
  type        = string
}

variable "db_port" {
  description = "Port for the database"
  type        = number
  default     = 3306
}

variable "db_storage_size" {
  description = "Size of db"
  type        = number
  default     = 20
}

variable "db_instance_class" {
  description = "Instance class for RDS"
  default     = "db.t3.micro"
}

variable "db_engine" {
  description = "DB engine for RDS"
  default     = "mysql"
}

variable "db_engine_version" {
  description = "DB engine version for RDS"
  default     = "8.0.34"
}

variable "db_name" {
  description = "DB  name"
  default     = "csye6225"
}

variable "db_username" {
  description = "DB username"
  default     = "csye6225"
}

variable "db_password"{
  description = "DB password"
  default     = "Safari-12345"
}

variable "db_public_access" {
  description = "DB public accessibility"
  type        = bool
  default     = false
}

variable "db_multiaz" {
  description = "DB multi AZ"
  type        = bool
  default     = false
}