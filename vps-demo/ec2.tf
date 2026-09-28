data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web" {
  name               = "shop-web-role"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

# The website may only touch its own two tables.
data "aws_iam_policy_document" "web" {
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [
      aws_dynamodb_table.products.arn,
      aws_dynamodb_table.orders.arn,
    ]
  }
}

resource "aws_iam_role_policy" "web" {
  name   = "shop-dynamodb"
  role   = aws_iam_role.web.id
  policy = data.aws_iam_policy_document.web.json
}

# Session Manager shell access instead of SSH keys.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "web" {
  name = "shop-web-profile"
  role = aws_iam_role.web.name
}

resource "aws_instance" "web" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    app            = file("${path.module}/app.py")
    index_html     = file("${path.module}/templates/index.html")
    style_css      = file("${path.module}/static/style.css")
    app_js         = file("${path.module}/static/app.js")
    region         = "us-east-1"
    products_table = aws_dynamodb_table.products.name
    orders_table   = aws_dynamodb_table.orders.name
  })
  user_data_replace_on_change = true

  tags = { Name = "shop-web" }
}

output "website_url" {
  value = "http://${aws_instance.web.public_ip}"
}

output "instance_id" {
  value = aws_instance.web.id
}
