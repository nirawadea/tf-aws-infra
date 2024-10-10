variable "cidr" {
  type        = string
  description = "The CIDR block for the VPC"
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
