# Create Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.csye6225_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

# Routing Public Subnets with Public Route Table
resource "aws_route_table_association" "public_association" {
  count = length(var.public_subnet_cidrs)

  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public.id
}

# Create Private Route Table (no internet access)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.csye6225_vpc.id

  tags = {
    Name = "private-route-table"
  }
}

# Routing Private Subnets with Private Route Table
resource "aws_route_table_association" "private_association" {
  count = length(var.private_subnet_cidrs)

  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private.id
}