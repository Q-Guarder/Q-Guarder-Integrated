# Q-Guarder-Server
Qshing 탐지 시스템 백엔드 서버 및 ML API

## 🐳 Docker로 로컬 개발 환경 실행

### 사전 준비
1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) 설치
2. 프로젝트 루트에 `.env` 파일 생성 (필수 환경변수 설정)

### 실행
```bash
# 이미지 빌드 + 컨테이너 실행 (최초 1회 또는 requirements.txt 변경 시)
docker-compose up --build

# 이후 재실행
docker-compose up
```

### 접속
- API 문서: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 종료
```bash
docker-compose down
```

### Hot Reload
`app/` 폴더의 코드를 수정하면 컨테이너를 재시작하지 않아도 자동 반영됩니다.
