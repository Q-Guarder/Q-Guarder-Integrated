# ──────────────────────────────────────────────
#  Q-Guarder 핵심 인프라 — API Gateway, Lambda, S3, RDS, EventBridge
# ──────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ── Remote Backend (S3 + DynamoDB State Lock) ──
  backend "s3" {
    bucket         = "q-guarder-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "ap-northeast-2"
    encrypt        = true
    dynamodb_table = "q-guarder-tfstate-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ══════════════════════════════════════════════
#  네트워크 (VPC / Subnets / Security Groups)
# ══════════════════════════════════════════════

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

# ── Public Subnets (NAT Gateway 배치용) ──

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.11.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-b" }
}

# ── Private Subnets (Lambda, RDS 배치) ──

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "${var.project_name}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = { Name = "${var.project_name}-private-b" }
}

# ── Internet Gateway ──

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.project_name}-igw" }
}

# ── Public Route Table (IGW 경유) ──

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ── NAT Gateway (AZ-a에 배치, Private Subnet 아웃바운드 경로) ──

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  depends_on = [aws_internet_gateway.main]

  tags = { Name = "${var.project_name}-nat-gw" }
}

# ── Private Route Table (NAT Gateway 경유) ──

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.project_name}-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# ── S3 Gateway Endpoint (NAT 우회, 비용 절감) ──

resource "aws_vpc_endpoint" "s3" {
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids = [aws_route_table.private.id]

  tags = { Name = "${var.project_name}-s3-endpoint" }
}

# ── Security Groups ──

resource "aws_security_group" "lambda_sg" {
  name        = "${var.project_name}-lambda-sg"
  description = "Lambda 함수용 보안 그룹"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-lambda-sg" }
}

resource "aws_security_group" "rds_sg" {
  name        = "${var.project_name}-rds-sg"
  description = "RDS PostgreSQL용 보안 그룹"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda_sg.id]
    description     = "Lambda에서 RDS 접근 허용"
  }

  tags = { Name = "${var.project_name}-rds-sg" }
}

# ══════════════════════════════════════════════
#  S3 — ML 모델 저장 버킷
# ══════════════════════════════════════════════

resource "aws_s3_bucket" "ml_models" {
  bucket = var.s3_model_bucket_name

  tags = { Name = "${var.project_name}-ml-models" }
}

resource "aws_s3_bucket_versioning" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# ══════════════════════════════════════════════
#  RDS — PostgreSQL
# ══════════════════════════════════════════════

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { Name = "${var.project_name}-db-subnet" }
}

resource "aws_db_instance" "postgres" {
  identifier     = "${var.project_name}-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.db_instance_class

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  allocated_storage     = 20
  max_allocated_storage = 50
  storage_encrypted     = true

  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  multi_az            = true
  publicly_accessible = false
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-final-snapshot"

  backup_retention_period = 7

  tags = { Name = "${var.project_name}-postgres" }
}

# ══════════════════════════════════════════════
#  Lambda — API 서버 (FastAPI + Mangum)
# ══════════════════════════════════════════════

resource "aws_lambda_function" "api" {
  function_name = "${var.project_name}-api-${var.environment}"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "app.main.handler"
  runtime       = "python3.10"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = "lambda_api.zip"
  source_code_hash = filebase64sha256("lambda_api.zip")

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DATABASE_URL       = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.postgres.endpoint}/${var.db_name}"
      JWT_SECRET_KEY     = var.jwt_secret_key
      JWT_ALGORITHM      = var.jwt_algorithm
      AWS_REGION         = var.aws_region
      S3_MODEL_BUCKET    = var.s3_model_bucket_name
      S3_MODEL_KEY       = var.s3_model_key
      SES_SENDER_EMAIL   = var.ses_sender_email
      KISA_REPORT_ENABLED = "true"
      VIRUSTOTAL_API_KEY = var.virustotal_api_key
      CORS_ORIGINS       = join(",", var.cors_allowed_origins)
    }
  }

  tags = { Name = "${var.project_name}-api" }
}

# ══════════════════════════════════════════════
#  Lambda — Queue Processor (Feedback Queue 처리)
# ══════════════════════════════════════════════

resource "aws_lambda_function" "queue_processor" {
  function_name = "${var.project_name}-queue-processor-${var.environment}"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "background.queue_processor.handler"
  runtime       = "python3.10"
  timeout       = 300
  memory_size   = 256

  filename         = "lambda_queue.zip"
  source_code_hash = filebase64sha256("lambda_queue.zip")

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DATABASE_URL       = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.postgres.endpoint}/${var.db_name}"
      JWT_SECRET_KEY     = var.jwt_secret_key
      AWS_REGION         = var.aws_region
      SES_SENDER_EMAIL   = var.ses_sender_email
      KISA_REPORT_ENABLED = "true"
      VIRUSTOTAL_API_KEY = var.virustotal_api_key
    }
  }

  tags = { Name = "${var.project_name}-queue-processor" }
}

# ══════════════════════════════════════════════
#  EventBridge — Queue Processor 스케줄 트리거
# ══════════════════════════════════════════════

resource "aws_cloudwatch_event_rule" "queue_schedule" {
  name                = "${var.project_name}-queue-schedule"
  description         = "FeedbackQueue 주기적 처리 스케줄"
  schedule_expression = var.queue_processor_schedule

  tags = { Name = "${var.project_name}-queue-schedule" }
}

resource "aws_cloudwatch_event_target" "queue_lambda" {
  rule      = aws_cloudwatch_event_rule.queue_schedule.name
  target_id = "${var.project_name}-queue-lambda"
  arn       = aws_lambda_function.queue_processor.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.queue_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.queue_schedule.arn
}

# ══════════════════════════════════════════════
#  API Gateway — HTTP API → Lambda API
# ══════════════════════════════════════════════

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-api-gateway"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins     = var.cors_allowed_origins
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers     = ["Content-Type", "Authorization"]
    allow_credentials = true
    max_age           = 3600
  }

  tags = { Name = "${var.project_name}-api-gateway" }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 30000
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  tags = { Name = "${var.project_name}-stage" }
}

resource "aws_lambda_permission" "apigw_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

# ══════════════════════════════════════════════
#  Outputs
# ══════════════════════════════════════════════

output "api_gateway_url" {
  description = "API Gateway 엔드포인트 URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "rds_endpoint" {
  description = "RDS PostgreSQL 엔드포인트"
  value       = aws_db_instance.postgres.endpoint
  sensitive   = true
}

output "nat_gateway_ip" {
  description = "NAT Gateway 퍼블릭 IP (아웃바운드 트래픽 출구)"
  value       = aws_eip.nat.public_ip
}

output "rds_endpoint" {
  description = "RDS PostgreSQL 엔드포인트"
  value       = aws_db_instance.postgres.endpoint
}

output "s3_model_bucket" {
  description = "ML 모델 S3 버킷 이름"
  value       = aws_s3_bucket.ml_models.id
}

output "api_lambda_name" {
  description = "API Lambda 함수 이름"
  value       = aws_lambda_function.api.function_name
}

output "queue_processor_lambda_name" {
  description = "Queue Processor Lambda 함수 이름"
  value       = aws_lambda_function.queue_processor.function_name
}
