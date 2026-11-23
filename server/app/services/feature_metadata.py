"""XAI 피처 한글 메타데이터 및 risk_level 사용자 문구 매핑 테이블"""

# ═══════════════════════════════════════════════════════════════
#  risk_level 사용자 문구
# ═══════════════════════════════════════════════════════════════

RISK_LEVEL_META: dict[str, dict[str, str]] = {
    "SECURED": {
        "label": "안전",
        "description": "안전한 URL입니다. 정상적으로 접속할 수 있습니다.",
    },
    "SUSPICIOUS": {
        "label": "주의",
        "description": "의심스러운 URL입니다. 접속 시 주의가 필요합니다.",
    },
    "BLOCKED": {
        "label": "위험",
        "description": "악성 URL로 판정되었습니다. 접속을 권장하지 않습니다.",
    },
}

# ═══════════════════════════════════════════════════════════════
#  XAI 피처 한글 매핑 (26개)
#  - value > 0일 때만 사용자에게 노출되므로 positive 문구만 정의
#  - severity: "high" | "medium" | "low"
# ═══════════════════════════════════════════════════════════════

FEATURE_META: dict[str, dict[str, str]] = {
    # ── 위험 패턴 (high) ──
    "has_at_symbol": {
        "title": "@ 기호 포함",
        "description": "주소에 @기호가 포함되어 있습니다. 실제 접속 주소를 숨기는 데 악용될 수 있습니다.",
        "severity": "high",
    },
    "has_double_slash_anomaly": {
        "title": "이중 슬래시 이상",
        "description": "주소에 비정상적인 이중 슬래시(//)가 포함되어 있습니다. 리다이렉트 공격에 악용될 수 있습니다.",
        "severity": "high",
    },
    "has_ip_address": {
        "title": "IP 주소 직접 사용",
        "description": "도메인 대신 IP 주소가 직접 사용되었습니다. 피싱 사이트에서 자주 발견됩니다.",
        "severity": "high",
    },
    "domain_entropy": {
        "title": "도메인 무작위성",
        "description": "도메인이 무작위 문자로 구성되어 있습니다. 자동 생성된 악성 도메인일 수 있습니다.",
        "severity": "high",
    },
    "suspicious_tld": {
        "title": "위험 도메인 확장자",
        "description": "악성 사이트에서 자주 사용되는 도메인 확장자(.tk, .xyz 등)가 사용되었습니다.",
        "severity": "high",
    },
    "brand_similarity": {
        "title": "브랜드 사칭 의심",
        "description": "유명 브랜드와 유사한 도메인입니다. 피싱 목적의 사칭일 수 있습니다.",
        "severity": "high",
    },
    "is_shortened_url": {
        "title": "단축 URL 사용",
        "description": "원본 주소가 가려진 단축 URL입니다. 피싱에 자주 악용됩니다.",
        "severity": "high",
    },
    "contains_bank": {
        "title": "금융기관 사칭 키워드",
        "description": "금융기관을 사칭하는 키워드가 포함되어 있습니다.",
        "severity": "high",
    },
    "contains_password": {
        "title": "비밀번호 유도 키워드",
        "description": "비밀번호 입력을 유도하는 키워드가 포함되어 있습니다.",
        "severity": "high",
    },
    # ── 주의 패턴 (medium) ──
    "url_length": {
        "title": "URL 길이 이상",
        "description": "URL의 전체 길이가 비정상적으로 깁니다. 악성 URL은 주소를 복잡하게 만드는 경향이 있습니다.",
        "severity": "medium",
    },
    "ratio_digits": {
        "title": "숫자 비율 이상",
        "description": "주소 전체에서 숫자가 차지하는 비율이 비정상적으로 높습니다.",
        "severity": "medium",
    },
    "ratio_special_chars": {
        "title": "특수문자 비율 이상",
        "description": "주소에 특수문자가 비정상적으로 많이 포함되어 있습니다.",
        "severity": "medium",
    },
    "ratio_url_encoded": {
        "title": "URL 난독화 의심",
        "description": "주소에 비정상적으로 많은 인코딩 문자가 포함되어 있습니다.",
        "severity": "medium",
    },
    "num_subdomains": {
        "title": "서브도메인 과다",
        "description": "서브도메인이 비정상적으로 많습니다. 정상 사이트를 사칭하는 데 악용될 수 있습니다.",
        "severity": "medium",
    },
    "contains_login": {
        "title": "피싱 키워드: login",
        "description": "로그인을 유도하는 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    "contains_verify": {
        "title": "피싱 키워드: verify",
        "description": "인증을 사칭하는 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    "contains_account": {
        "title": "피싱 키워드: account",
        "description": "계정 관련 사칭 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    "contains_secure": {
        "title": "피싱 키워드: secure",
        "description": "보안을 사칭하는 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    "contains_update": {
        "title": "피싱 키워드: update",
        "description": "업데이트를 사칭하는 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    "contains_confirm": {
        "title": "피싱 키워드: confirm",
        "description": "확인을 사칭하는 키워드가 포함되어 있습니다.",
        "severity": "medium",
    },
    # ── 보조 지표 (low) ──
    "num_dots": {
        "title": "마침표 과다 사용",
        "description": "주소에 마침표(.)가 비정상적으로 많이 포함되어 있습니다.",
        "severity": "low",
    },
    "num_hyphens": {
        "title": "하이픈 과다 사용",
        "description": "주소에 하이픈(-)이 비정상적으로 많이 포함되어 있습니다.",
        "severity": "low",
    },
    "num_slashes": {
        "title": "슬래시 과다 사용",
        "description": "주소에 경로 구분자(/)가 비정상적으로 많이 포함되어 있습니다.",
        "severity": "low",
    },
    "num_digits": {
        "title": "숫자 과다 포함",
        "description": "주소에 숫자가 비정상적으로 많이 포함되어 있습니다.",
        "severity": "low",
    },
    "path_length": {
        "title": "경로 길이 이상",
        "description": "URL의 경로 부분이 비정상적으로 깁니다.",
        "severity": "low",
    },
    "domain_length": {
        "title": "도메인 길이 이상",
        "description": "도메인 이름이 비정상적으로 깁니다.",
        "severity": "low",
    },
}

# severity 우선순위 (contribution 동률 시 2차 정렬용)
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# XAI 응답 최대 피처 수
XAI_MAX_FEATURES = 5
