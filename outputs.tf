output "vpc_id" {
  value = aws_vpc.csye6225_vpc.id
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
