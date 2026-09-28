resource "aws_vpc" "shop" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "shop-vpc" }
}

resource "aws_internet_gateway" "shop" {
  vpc_id = aws_vpc.shop.id

  tags = { Name = "shop-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.shop.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = { Name = "shop-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.shop.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.shop.id
  }

  tags = { Name = "shop-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Free gateway endpoint: DynamoDB traffic stays on the AWS network.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.shop.id
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]

  tags = { Name = "shop-dynamodb-endpoint" }
}

resource "aws_security_group" "web" {
  name        = "shop-web"
  description = "HTTP in, all out"
  vpc_id      = aws_vpc.shop.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
