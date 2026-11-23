# ──────────────────────────────────────────────
#  Q-Guarder Terraform 변수 정의
# ──────────────────────────────────────────────

# ── 프로젝트 ──
variable "project_name" {
  description = "프로젝트 이름 (리소스 네이밍 프리픽스)"
  type        = string
  default     = "q-guarder"
}

variable "aws_region" {
  description = "AWS 배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "environment" {
  description = "배포 환경 (dev / staging / prod)"
  type        = string
  default     = "prod"
}

# ── 데이터베이스 (RDS PostgreSQL) ──
variable "db_name" {
  description = "RDS 데이터베이스 이름"
  type        = string
  default     = "qguarder"
}

variable "db_username" {
  description = "RDS 마스터 사용자명"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "RDS 마스터 비밀번호"
  type        = string
  sensitive   = true
}

variable "db_instance_class" {
  description = "RDS 인스턴스 클래스"
  type        = string
  default     = "db.t3.small"
}

# ── JWT ──
variable "jwt_secret_key" {
  description = "JWT 토큰 서명용 시크릿 키"
  type        = string
  sensitive   = true
}

variable "jwt_algorithm" {
  description = "JWT 알고리즘"
  type        = string
  default     = "HS256"
}

# ── AWS SES ──
variable "ses_sender_email" {
  description = "SES 발신자 이메일 (인증 필요)"
  type        = string
}

# ── VirusTotal ──
variable "virustotal_api_key" {
  description = "VirusTotal API v3 키"
  type        = string
  sensitive   = true
}

# ── S3 ──
variable "s3_model_bucket_name" {
  description = "ML 모델 저장용 S3 버킷 이름"
  type        = string
  default     = "q-guarder-ml-models"
}

variable "s3_model_key" {
  description = "S3 내 모델 파일 경로 (With FS · XGB+LGBM Top-17 · threshold 0.41)"
  type        = string
  default     = "models/final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl"
}

# ── Lambda ──
variable "lambda_memory_size" {
  description = "Lambda 메모리 크기 (MB)"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Lambda 타임아웃 (초)"
  type        = number
  default     = 60
}

variable "queue_processor_schedule" {
  description = "Queue Processor EventBridge 스케줄 (cron/rate)"
  type        = string
  default     = "rate(5 minutes)"
}

# ── CORS ──
variable "cors_allowed_origins" {
  description = "API Gateway 및 FastAPI CORS 허용 출처 목록"
  type        = list(string)
  default     = ["https://q-guarder.example.com"]
}
