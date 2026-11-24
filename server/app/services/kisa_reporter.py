"""KISA 자동 신고 메일 발송 — SMTP(Gmail 등) 기반 CERT/CSIRT 수준 위협 리포트

엔터프라이즈 사건 리포트 양식:
  - TLP:AMBER 정보 공유 등급 (FIRST.org 국제 표준)
  - URL Defanging (메일 클라이언트 자동 링크 방지)
  - Incident Reference ID (사건 추적 번호)
  - XAI 기반 탐지 근거 첨부
  - MITRE ATT&CK 초기 접근 벡터 참조
  - 6-섹션 구조화 리포트
"""

import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.services.feature_metadata import FEATURE_META

logger = logging.getLogger(__name__)
settings = get_settings()

SMTP_TIMEOUT_SECONDS = 20


# ═══════════════════════════════════════════════════════════════
#  URL Defanging — 메일 본문 내 URL 자동 클릭 방지 (OSINT 보안 표준)
# ═══════════════════════════════════════════════════════════════

def _defang_url(url: str) -> str:
    """
    URL을 안전한 표기로 변환합니다.
    예: https://evil.example.com/path → hxxps[://]evil[.]example[.]com/path

    ※ 문자열 치환 후 "/"로 split하면 안 된다. 치환 결과인 "[://]" 안에 슬래시가
      들어 있어 split이 엉뚱한 지점에서 잘리고, 도메인의 점이 그대로 남는다.
      반드시 파싱 후 호스트 부분만 치환할 것.
    """
    parsed = urlsplit(url)

    host = parsed.netloc.replace(".", "[.]")
    rest = parsed.path or ""
    if parsed.query:
        rest += f"?{parsed.query}"
    if parsed.fragment:
        rest += f"#{parsed.fragment}"

    if not parsed.scheme:
        return f"{host}{rest}" if host else url.replace(".", "[.]")

    scheme = parsed.scheme.lower().replace("http", "hxxp")
    return f"{scheme}[://]{host}{rest}"


# ═══════════════════════════════════════════════════════════════
#  XAI 피처 → 구조화 텍스트 (탐지 근거 섹션)
# ═══════════════════════════════════════════════════════════════

_SEVERITY_LABEL = {"high": "■ HIGH", "medium": "▲ MEDIUM", "low": "○ LOW"}


def _build_xai_section(xai_features: dict | None, max_features: int = 3) -> str:
    """XAI 피처 딕셔너리를 CERT 리포트용 구조화 텍스트 블록으로 변환"""
    if not xai_features:
        return "  해당 스캔 건에 대한 XAI 피처 데이터가 존재하지 않습니다."

    sorted_features = sorted(
        xai_features.items(),
        key=lambda x: x[1].get("contribution", 0),
        reverse=True,
    )
    top_features = [
        (name, data) for name, data in sorted_features
        if data.get("contribution", 0) > 0
    ][:max_features]

    if not top_features:
        return "  유의미한 기여도를 가진 XAI 피처가 탐지되지 않았습니다."

    lines = []
    for i, (feat_name, feat_data) in enumerate(top_features, 1):
        meta = FEATURE_META.get(feat_name, {})
        title = meta.get("title", feat_name)
        description = meta.get("description", "-")
        severity = _SEVERITY_LABEL.get(meta.get("severity", ""), "- N/A")
        contribution = round(feat_data.get("contribution", 0) * 100, 1)

        lines.append(f"  Indicator #{i}")
        lines.append(f"    명칭       : {title}")
        lines.append(f"    위험 등급   : {severity}")
        lines.append(f"    기여도      : {contribution}%")
        lines.append(f"    상세       : {description}")
        lines.append("")

    return "\n".join(lines).rstrip()


# ═══════════════════════════════════════════════════════════════
#  가중치 케이스 한글 설명 매핑
# ═══════════════════════════════════════════════════════════════

_WEIGHTING_DESC = {
    "CASE_A_HIGH": "VT 다수 탐지 확인 — ML 25% + VT 75% 가중 적용",
    "CASE_A_LOW":  "VT 소수 탐지 확인 — ML 50% + VT 50% 균등 적용",
    "CASE_B":      "VT 미탐지 (Clean) — ML 30% + VT 70% 가중 적용",
    "CASE_C":      "VT 응답 없음 — ML 80% + VT 20% (ML 의존 모드)",
    "OVERRIDE":    "VT 규칙 우선 판정 — 탐지 비율 5% 이상 즉시 BLOCKED 처리",
}


# ═══════════════════════════════════════════════════════════════
#  CERT/CSIRT 엔터프라이즈 사건 리포트 템플릿
# ═══════════════════════════════════════════════════════════════

MAIL_BODY_TEMPLATE = """\
══════════════════════════════════════════════════════════════════
  Q-GUARDER AUTOMATED THREAT INTELLIGENCE REPORT
  Classification : TLP:AMBER
  Incident Ref   : {incident_ref}
  Generated      : {detected_at}
══════════════════════════════════════════════════════════════════

한국인터넷진흥원 인터넷침해대응센터(KrCERT/CC) 담당자님께,

본 메일은 Q-Guarder 자동화 악성 URL 탐지 시스템에서 자동
생성·발송된 위협 인텔리전스 리포트입니다.

머신러닝 앙상블 모델(XGBoost + LightGBM Soft-Voting)과
외부 위협 인텔리전스(VirusTotal API v3) 융합 분석 결과,
아래 URL이 악성(Zero-Day 포함)으로 의심되어 신고드립니다.


──────────────────────────────────────────────────────────────────
 § 1. INCIDENT SUMMARY (사건 개요)
──────────────────────────────────────────────────────────────────

  Incident Reference  : {incident_ref}
  Detection Timestamp  : {detected_at}
  Risk Classification  : BLOCKED (위험 — 접속 차단 권고)
  Reported URL         : {defanged_url}
  MITRE ATT&CK Ref     : T1566.002 (Phishing: Spearphishing Link)


──────────────────────────────────────────────────────────────────
 § 2. THREAT ANALYSIS DETAIL (위협 분석 상세)
──────────────────────────────────────────────────────────────────

  ┌─────────────────────────┬─────────────────────────────────┐
  │ Metric                  │ Value                           │
  ├─────────────────────────┼─────────────────────────────────┤
  │ Final Threat Score      │ {threat_score} / 100            │
  │ ML Ensemble Confidence  │ {ml_probability} / 100          │
  │ VT Detection Ratio      │ {vt_detected} / {vt_total}      │
  │ Fusion Weight Policy    │ {weighting_desc}                │
  └─────────────────────────┴─────────────────────────────────┘

  ※ Final Score = ML 가중치 × ML 확률 + VT 가중치 × VT 비선형 증폭값


──────────────────────────────────────────────────────────────────
 § 3. DETECTION RATIONALE — Explainable AI (탐지 근거)
──────────────────────────────────────────────────────────────────

{xai_section}

  ※ 피처 기여도는 XGBoost/LightGBM feature_importance 기반
    정규화 값이며, 상위 기여 Indicator만 발췌하여 수록합니다.


──────────────────────────────────────────────────────────────────
 § 4. REQUESTED ACTIONS (요청 사항)
──────────────────────────────────────────────────────────────────

  1. 신고 대상 URL에 대한 악성 여부 확인 및 차단 조치 검토
  2. 관련 도메인/IP에 대한 추가 위협 인텔리전스 조사
  3. 필요 시 피싱 사이트 테이크다운(Takedown) 절차 진행


──────────────────────────────────────────────────────────────────
 § 5. TLP CLASSIFICATION (정보 공유 등급)
──────────────────────────────────────────────────────────────────

  본 리포트는 TLP:AMBER 등급으로 분류됩니다.

  공유 범위: 수신 기관 및 해당 기관의 고객·관련 조직에 한하여
  "알 필요가 있는(need-to-know)" 대상에게만 공유가 허용됩니다.

  참조 표준: FIRST (Forum of Incident Response and Security Teams)
            Traffic Light Protocol (TLP) v2.0


──────────────────────────────────────────────────────────────────
 § 6. REPORTING SYSTEM INFORMATION (발신 시스템)
──────────────────────────────────────────────────────────────────

  System Name     : Q-Guarder Automated Threat Detection System
  Analysis Engine : XGBoost + LightGBM Top-17 Soft-Voting (t=0.41)
  Intel Source    : VirusTotal API v3 (70+ AV Engines)
  Infrastructure  : FastAPI + PostgreSQL (자체 운영 서버)
  Contact         : {sender_email}


══════════════════════════════════════════════════════════════════
  This report was generated automatically by Q-Guarder.
  For raw logs, IOC exports, or STIX/TAXII formatted data,
  please reply to this email.
══════════════════════════════════════════════════════════════════
  Q-Guarder — Protecting Users from QR-based Phishing Threats
══════════════════════════════════════════════════════════════════\
"""


# ═══════════════════════════════════════════════════════════════
#  메일 발송 함수
# ═══════════════════════════════════════════════════════════════

async def send_kisa_report(
    reported_url: str,
    threat_score: float,
    vt_detected_count: int,
    report_id: str,
    ml_probability: float = 0.0,
    vt_total_engines: int = 0,
    weighting_case: str = "",
    xai_features: dict | None = None,
    detected_at: datetime | None = None,
) -> bool:
    """
    SMTP(Gmail 등)로 KISA KrCERT/CC에 엔터프라이즈 수준
    위협 인텔리전스 리포트를 발송합니다.
    받는 주소는 .env의 KISA_REPORT_RECIPIENT입니다 (테스트: 본인 메일, 실제 신고: cert@kisa.or.kr).

    Args:
        reported_url:     신고 대상 URL 원문
        threat_score:     최종 위협 스코어 (0.0~1.0)
        vt_detected_count: VirusTotal 탐지 엔진 수
        report_id:        신고 건 UUID (사건 추적 번호 생성용)
        ml_probability:   ML 앙상블 악성 확률 (0.0~1.0)
        vt_total_engines:  VirusTotal 전체 검사 엔진 수
        weighting_case:   융합 가중치 케이스 (CASE_A_HIGH 등)
        xai_features:     XAI 피처 딕셔너리 (ScoreDetail.xai_features)
        detected_at:      탐지 일시 (None이면 현재 UTC 시각)

    Returns:
        True: 발송 성공, False: 발송 실패 또는 발송 비활성화(설정 누락 포함)
    """
    # ── 발송 차단 장치 ──
    # 외부 기관으로 나갈 수 있는 메일이므로 명시적으로 켜고 받는 주소를 정한 경우에만 보낸다.
    # 하나라도 빠지면 메일 서버에 접속하지도 않는다.
    if not settings.KISA_REPORT_ENABLED:
        logger.warning(
            "KISA 자동 신고 비활성화(KISA_REPORT_ENABLED=False) — 메일을 보내지 않습니다: %s",
            reported_url,
        )
        return False
    if not settings.KISA_REPORT_RECIPIENT:
        logger.warning(
            "KISA_REPORT_RECIPIENT 미설정 — 메일을 보내지 않습니다: %s", reported_url
        )
        return False
    if not (settings.SMTP_HOST and settings.SMTP_USERNAME and settings.SMTP_PASSWORD):
        logger.warning(
            "SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD 미설정 — 메일을 보내지 않습니다: %s",
            reported_url,
        )
        return False
    sender = settings.MAIL_FROM or settings.SMTP_USERNAME

    if detected_at is None:
        detected_at = datetime.now(timezone.utc)

    # 사건 추적 번호: QG-{연도}-{report_id 앞 8자리 대문자}
    ref_short = report_id.replace("-", "")[:8].upper()
    incident_ref = f"QG-{detected_at.year}-{ref_short}"

    # 스코어 변환 (0~1 → 0~100 정수 표기)
    score_display = round(threat_score * 100, 1)
    ml_display = round(ml_probability * 100, 1)

    body = MAIL_BODY_TEMPLATE.format(
        incident_ref=incident_ref,
        detected_at=detected_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        defanged_url=_defang_url(reported_url),
        threat_score=score_display,
        ml_probability=ml_display,
        vt_detected=vt_detected_count,
        vt_total=vt_total_engines,
        weighting_desc=_WEIGHTING_DESC.get(weighting_case, weighting_case or "N/A"),
        xai_section=_build_xai_section(xai_features),
        sender_email=sender,
    )

    subject = f"[TLP:AMBER] 악성 URL 위협 리포트 — {incident_ref}"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = settings.KISA_REPORT_RECIPIENT
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1] if "@" in sender else None)
    msg.set_content(body, charset="utf-8")

    try:
        # smtplib는 동기 라이브러리 → 이벤트 루프를 막지 않도록 스레드에서 실행
        await asyncio.to_thread(_smtp_send, msg)
    except (smtplib.SMTPException, OSError) as e:
        logger.error(
            "KISA 위협 리포트 발송 실패 — incident=%s, url=%s, error=%s",
            incident_ref, reported_url, e,
        )
        return False

    logger.info(
        "KISA 위협 리포트 발송 성공 — incident=%s, to=%s, message_id=%s, url=%s",
        incident_ref, settings.KISA_REPORT_RECIPIENT, msg["Message-ID"], reported_url,
    )
    return True


def _smtp_send(msg: EmailMessage) -> None:
    """SMTP 서버에 접속해 메일 1건을 보낸다 (Gmail: 587 + STARTTLS + 앱 비밀번호)."""
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
        if settings.SMTP_USE_TLS:
            smtp.starttls(context=ssl.create_default_context())
        smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(msg)
