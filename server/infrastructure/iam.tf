# ──────────────────────────────────────────────
#  Q-Guarder IAM 역할 및 정책 — AWS 최소 권한 원칙
# ──────────────────────────────────────────────

# ── Lambda 실행 기본 역할 (Assume Role) ──

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_execution_role" {
  name               = "${var.project_name}-lambda-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# ── CloudWatch Logs 권한 ──

data "aws_iam_policy_document" "lambda_logging" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:*"]
  }
}

resource "aws_iam_role_policy" "lambda_logging" {
  name   = "${var.project_name}-lambda-logging"
  role   = aws_iam_role.lambda_execution_role.id
  policy = data.aws_iam_policy_document.lambda_logging.json
}

# ── SES 이메일 발송 권한 (KISA 신고) ──

data "aws_iam_policy_document" "lambda_ses" {
  statement {
    effect    = "Allow"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_ses" {
  name   = "${var.project_name}-lambda-ses"
  role   = aws_iam_role.lambda_execution_role.id
  policy = data.aws_iam_policy_document.lambda_ses.json
}

# ── S3 모델 버킷 접근 권한 (model.pkl 다운로드) ──

data "aws_iam_policy_document" "lambda_s3" {
  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::${var.s3_model_bucket_name}",
      "arn:aws:s3:::${var.s3_model_bucket_name}/*",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_s3" {
  name   = "${var.project_name}-lambda-s3"
  role   = aws_iam_role.lambda_execution_role.id
  policy = data.aws_iam_policy_document.lambda_s3.json
}

# ── VPC / RDS 접근을 위한 네트워크 인터페이스 권한 ──

data "aws_iam_policy_document" "lambda_vpc" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_vpc" {
  name   = "${var.project_name}-lambda-vpc"
  role   = aws_iam_role.lambda_execution_role.id
  policy = data.aws_iam_policy_document.lambda_vpc.json
}
