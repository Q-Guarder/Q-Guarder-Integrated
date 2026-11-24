"""하이브리드 위협 분석 엔진 — ML 앙상블 추론 + VirusTotal API 융합"""

import base64
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import get_settings
from urllib.parse import urlsplit

from app.services.fusion import (
    SERVER_PARAMS, FusionParams, VTStatus, fuse,
)
from app.services.model_loader import get_model
from app.services.url_features import extract_features, preprocess_url

logger = logging.getLogger(__name__)
settings = get_settings()

VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{url_id}"

_VT_TIMEOUT_SECONDS = 30.0


def vt_url_id(url: str) -> str:
    """VirusTotal API v3의 URL 식별자를 생성합니다.

    ⚠️ SHA-256을 쓰면 안 됩니다. VT의 SHA-256 식별자는 '원문'이 아니라 VT가
       **정규화한 URL** 기준이라, 루트 URL처럼 trailing slash가 붙는 경우 어긋납니다.

           sha256("https://gmail.com")    → 404 (오탐: 미등재로 읽힘)
           sha256("https://gmail.com/")   → 200 (d=0, n=92)
           base64url("https://gmail.com") → 200 (d=0, n=92)

       경로가 있는 URL은 우연히 일치해서 문제가 드러나지 않지만, 루트 URL은
       전부 404가 되어 '제로데이'로 오분류됩니다.

       base64url 식별자는 VT가 서버 측에서 정규화하므로 안전합니다.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

# ML 추론 실패 시 사용하는 중립값 (BLOCKED도 SECURED도 아닌 보수적 기본값)
ML_FALLBACK_PROBABILITY = 0.5


class InvalidUrlError(ValueError):
    """URL 파싱·정규화 실패 — 모델 장애가 아니라 입력 오류.

    ML 추론 실패(중립값 대체)와 반드시 구분해야 한다. 무효 URL을 중립값 0.5로
    처리하면 실험 데이터에 '측정된 적 없는 0.5'가 섞여 결과가 오염된다.
    """


# ═══════════════════════════════════════════════════════════════
#  지연 시간 측정
# ═══════════════════════════════════════════════════════════════

@dataclass
class LatencyBreakdown:
    """처리 단계별 소요 시간 (ms) — 논문 '실시간성' 근거 자료용"""
    feature_ms: float = 0.0    # URL 피처 추출
    inference_ms: float = 0.0  # 앙상블 추론 + XAI 산출
    vt_ms: float = 0.0         # VirusTotal 조회 (네트워크)
    fusion_ms: float = 0.0     # 가중 융합 계산
    total_ms: float = 0.0      # 전체 E2E


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


# ═══════════════════════════════════════════════════════════════
#  ML 앙상블 추론 (XGBoost + LightGBM Top-17 Soft Voting, threshold 0.41)
# ═══════════════════════════════════════════════════════════════

@dataclass
class MLPredictionResult:
    """ML 모델 추론 결과 구조체"""
    ml_probability: float          # 악성 확률 (0.0 ~ 1.0)
    xai_features: dict[str, dict]  # XAI feature contributions
    feature_ms: float = 0.0
    inference_ms: float = 0.0


def predict_url_with_ml(url: str) -> MLPredictionResult:
    """
    SoftVotingEnsemble (XGB + LGBM Top-17) 모델로 URL 위험도를 추론합니다.

    Args:
        url: 분석 대상 URL 문자열

    Returns:
        MLPredictionResult: ml_probability (0~1), xai_features, 단계별 소요 시간

    Raises:
        InvalidUrlError: URL이 파싱·정규화 불가능한 경우
    """
    model = get_model()

    started = time.perf_counter()
    try:
        X = extract_features(url)
    except ValueError as e:
        # 피처 추출 실패 = 입력이 URL이 아님. 모델 장애와 구분해서 올린다.
        raise InvalidUrlError(str(e)) from e
    feature_ms = _elapsed_ms(started)

    started = time.perf_counter()
    # 앙상블 추론 — predict_proba[:, 1] = 악성 확률
    proba = model.predict_proba(X)[:, 1][0]

    # XAI: 각 피처의 값과 기여도 산출 (feature_importances 기반)
    xai_features = _build_xai_features(model, X)
    inference_ms = _elapsed_ms(started)

    return MLPredictionResult(
        ml_probability=float(proba),
        xai_features=xai_features,
        feature_ms=feature_ms,
        inference_ms=inference_ms,
    )


def _build_xai_features(model, X) -> dict[str, dict]:
    """모델별 feature_importance를 평균 내어 피처 기여도 산출"""
    import numpy as np

    feature_contributions: dict[str, list[float]] = {}

    for sub_model, feats in zip(model.models, model.features):
        # feature_importances_ 가 있는 모델 (XGB, LGBM 모두 지원)
        if hasattr(sub_model, "feature_importances_"):
            importances = sub_model.feature_importances_
            for feat_name, importance in zip(feats, importances):
                feature_contributions.setdefault(feat_name, []).append(float(importance))

    # 평균 importance 계산 후 정규화
    xai: dict[str, dict] = {}
    total_importance = sum(
        np.mean(v) for v in feature_contributions.values()
    ) if feature_contributions else 1.0

    for feat_name, importances in feature_contributions.items():
        avg_importance = float(np.mean(importances))
        value = float(X[feat_name].iloc[0]) if feat_name in X.columns else 0.0
        xai[feat_name] = {
            "value": value,
            "contribution": round(avg_importance / total_importance, 4) if total_importance > 0 else 0.0,
        }

    return xai


# ═══════════════════════════════════════════════════════════════
#  VirusTotal API 연동
# ═══════════════════════════════════════════════════════════════

@dataclass
class VTResult:
    """VirusTotal 검사 결과"""
    detected_engines: int
    total_engines: int
    status: VTStatus
    http_status: int | None = None
    latency_ms: float = 0.0


async def scan_url_with_virustotal(url: str, *, submit_unknown: bool = False) -> VTResult:
    """
    VirusTotal API v3로 URL 평판을 **조회(GET)** 합니다.

    ⚠️ submit_unknown을 명시적으로 켜지 않는 한 POST(스캔 제출)를 하지 않습니다.
       제출은 해당 URL을 VT에 등재시켜 '미등재(제로데이)' 상태를 소멸시키므로,
       실험용 데이터 수집 경로에서는 절대 켜서는 안 됩니다. 조회만 하면 쿼터도
       URL당 1회로 줄어듭니다(무료 티어 4 req/min에서 체감 차이가 큼).

    Args:
        url: 조회 대상 URL
        submit_unknown: 404(미등재)일 때 VT에 스캔 제출까지 할지 여부

    Returns:
        VTResult: 탐지 수/전체 수/응답 상태/HTTP 코드/소요 시간
    """
    started = time.perf_counter()

    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY 미설정 — VT 조회를 건너뜁니다")
        return VTResult(0, 0, VTStatus.UNAVAILABLE, None, _elapsed_ms(started))

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    url_id = vt_url_id(url)

    try:
        async with httpx.AsyncClient(timeout=_VT_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                VIRUSTOTAL_URL_REPORT.format(url_id=url_id),
                headers=headers,
            )

            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                # 논문 식 (2)·(4)의 n, d 정의 — 논문 수치가 이 정의로 산출되었으므로 바꾸지 말 것.
                #   n = last_analysis_stats 전체 합 (harmless·undetected·malicious·suspicious·timeout)
                #   d = malicious + suspicious
                total = sum(stats.values()) if stats else 0
                if total == 0:
                    # 등재는 됐으나 분석 이력이 없음 → TI 정보가 없다는 점에서 미등재와 동일
                    logger.info("VirusTotal 분석 이력 없음 (제로데이 후보): %s", url)
                    return VTResult(0, 0, VTStatus.NOT_FOUND, 200, _elapsed_ms(started))

                detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
                return VTResult(detected, total, VTStatus.OK, 200, _elapsed_ms(started))

            if resp.status_code == 404:
                logger.info("VirusTotal 미등재 URL (제로데이 후보): %s", url)
                if submit_unknown:
                    # 운영 환경에서만 사용. 실험 수집 경로에서는 호출 금지.
                    await client.post(VIRUSTOTAL_URL_SCAN, headers=headers, data={"url": url})
                    logger.info("VirusTotal 스캔 제출 완료: %s", url)
                return VTResult(0, 0, VTStatus.NOT_FOUND, 404, _elapsed_ms(started))

            if resp.status_code == 401:
                logger.error("VirusTotal API 인증 실패: API 키를 확인하세요")
            elif resp.status_code == 429:
                logger.warning("VirusTotal API 요청 한도 초과 (Rate Limit): %s", url)
            else:
                logger.warning("VirusTotal API 응답 코드 %d: %s", resp.status_code, url)
            return VTResult(0, 0, VTStatus.UNAVAILABLE, resp.status_code, _elapsed_ms(started))

    except httpx.TimeoutException:
        logger.error("VirusTotal API 타임아웃 (%.0f초 초과): %s", _VT_TIMEOUT_SECONDS, url)
    except httpx.ConnectError:
        logger.error("VirusTotal API 연결 실패 (네트워크 오류): %s", url)
    except httpx.HTTPError as e:
        logger.error("VirusTotal API HTTP 에러: %s — %s", url, e)

    return VTResult(0, 0, VTStatus.UNAVAILABLE, None, _elapsed_ms(started))


# ═══════════════════════════════════════════════════════════════
#  하이브리드 점수 융합 엔진
# ═══════════════════════════════════════════════════════════════

@dataclass
class HybridScanResult:
    """하이브리드 엔진 최종 분석 결과"""
    risk_level: str              # SECURED | SUSPICIOUS | BLOCKED
    final_score: float           # 0.0 ~ 1.0
    ml_probability: float
    ml_weighted_score: float
    vt_detected_engines: int
    vt_total_engines: int
    vt_weighted_score: float
    weighting_case: str
    xai_features: dict[str, dict]
    vt_status: str = VTStatus.UNAVAILABLE.value  # ok | not_found | unavailable
    ml_failed: bool = False                      # ML 추론 실패로 중립값을 썼는지
    latency: LatencyBreakdown = field(default_factory=LatencyBreakdown)


def _path_type(url: str) -> str:
    """CASE_B 가중치용 URL 구조 — 정규화 후 경로가 없으면 root, 있으면 deep.

    experiments/build_evalset.classify_path_type()과 같은 규칙. 파싱 실패 시 root
    (더 보수적인 W_ML 0.30)로 둔다.
    """
    normalized = preprocess_url(url)
    if normalized is None:
        return "root"
    return "root" if urlsplit(normalized).path in ("", "/") else "deep"


async def analyze_url(
    url: str, params: FusionParams = SERVER_PARAMS
) -> HybridScanResult:
    """
    URL을 하이브리드(ML + VT) 방식으로 분석합니다.

    융합 계산 자체는 app.services.fusion.fuse()에 위임한다. 실험 스크립트도
    동일한 함수를 호출하므로 논문 수치와 서버 동작이 일치한다.

    기본 파라미터 = fusion.SERVER_PARAMS (재심 수정본 확정값, fixed_params.json 2026-10-18):
    - α = 18.4, τL = 0.45, τH = 0.65, d_high = 5
    - CASE_A_HIGH : VT ≥5 탐지            → ML 25% / VT 75%
    - CASE_A_LOW  : VT 1~4 탐지           → ML 50% / VT 50%
    - CASE_B      : VT clean (0/N, N>0)   → 루트 URL ML 30% / 경로 포함 URL ML 50%
    - CASE_C      : VT 미등재 또는 API 장애 → ML 80% / VT 20%
    - 우선 판정(Override): VT ratio ≥ 0.05 → BLOCKED

    Raises:
        InvalidUrlError: 입력이 URL로 파싱되지 않는 경우 (라우터에서 400 처리)
    """
    total_started = time.perf_counter()

    # 1) ML 앙상블 추론 — 입력 오류(InvalidUrlError)는 그대로 올리고,
    #    모델/로딩 장애만 중립값으로 대체한다.
    ml_failed = False
    try:
        ml_result = predict_url_with_ml(url)
    except InvalidUrlError:
        raise
    except Exception as e:
        logger.error("ML 추론 실패, 중립값(%.2f) 사용: %s — %s", ML_FALLBACK_PROBABILITY, url, e)
        ml_result = MLPredictionResult(
            ml_probability=ML_FALLBACK_PROBABILITY, xai_features={}
        )
        ml_failed = True

    # 2) VirusTotal 조회 (GET only)
    vt_result = await scan_url_with_virustotal(url)

    # 3) 융합 (순수 함수)
    fusion_started = time.perf_counter()
    fused = fuse(
        p_ml=ml_result.ml_probability,
        detected=vt_result.detected_engines,
        total=vt_result.total_engines,
        status=vt_result.status,
        params=params,
        path_type=_path_type(url),
    )
    fusion_ms = _elapsed_ms(fusion_started)

    return HybridScanResult(
        risk_level=fused.risk_level,
        final_score=fused.final_score,
        ml_probability=ml_result.ml_probability,
        ml_weighted_score=fused.ml_weighted,
        vt_detected_engines=vt_result.detected_engines,
        vt_total_engines=vt_result.total_engines,
        vt_weighted_score=fused.vt_weighted,
        weighting_case=fused.case,
        xai_features=ml_result.xai_features,
        vt_status=vt_result.status.value,
        ml_failed=ml_failed,
        latency=LatencyBreakdown(
            feature_ms=ml_result.feature_ms,
            inference_ms=ml_result.inference_ms,
            vt_ms=vt_result.latency_ms,
            fusion_ms=fusion_ms,
            total_ms=_elapsed_ms(total_started),
        ),
    )
