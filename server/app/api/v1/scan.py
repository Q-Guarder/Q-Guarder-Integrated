"""URL 스캔 API 라우터 — 하이브리드 엔진(ML + VT) 기반 위험도 분석"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user_id
from app.crud import crud_scan
from app.db.session import get_db
from app.schemas.scan_schema import (
    RiskLevel,
    ScanUrlRequest,
    ScanUrlResponse,
    XaiFeatureDetail,
)
from app.services.feature_metadata import (
    FEATURE_META,
    RISK_LEVEL_META,
    XAI_MAX_FEATURES,
    _SEVERITY_ORDER,
)
from app.services.hybrid_engine import InvalidUrlError, analyze_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["Scan"])


@router.post(
    "/url",
    response_model=ScanUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="URL 위험도 분석",
    description=(
        "QR 코드에서 추출한 URL을 하이브리드 엔진(XGBoost + LightGBM + VirusTotal)으로 "
        "분석하여 위험도(SECURED / SUSPICIOUS / BLOCKED)를 반환합니다. "
        "XAI 기반 특성 기여도(Feature Contribution)도 함께 제공됩니다."
    ),
)
async def scan_url(
    body: ScanUrlRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    # 1) 하이브리드 엔진 분석
    try:
        result = await analyze_url(body.url)
    except InvalidUrlError:
        # 입력 오류 — 서버 장애가 아니므로 4xx로 구분해서 응답한다
        logger.info("URL 형식 오류로 분석 거부: %s", body.url)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="올바른 URL 형식이 아닙니다.",
        )
    except Exception:
        logger.exception("하이브리드 엔진 분석 실패: %s", body.url)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="URL 분석 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
        )

    # 처리 지연 기록 (논문 실시간성 근거 자료 수집용)
    logger.info(
        "scan latency ms — feature=%.2f inference=%.2f vt=%.2f fusion=%.2f total=%.2f "
        "| case=%s vt_status=%s ml_failed=%s",
        result.latency.feature_ms, result.latency.inference_ms, result.latency.vt_ms,
        result.latency.fusion_ms, result.latency.total_ms,
        result.weighting_case, result.vt_status, result.ml_failed,
    )

    # 2) 스캔 로그 저장
    url_hash = hashlib.sha256(body.url.encode()).hexdigest()
    scan_log = await crud_scan.create_scan_log(
        db=db,
        user_id=uuid.UUID(current_user_id),
        url=body.url,
        url_hash=url_hash,
        risk_level=result.risk_level,
        final_score=result.final_score,
        scan_source=body.source,
    )

    # 3) 점수 상세 저장
    await crud_scan.create_score_detail(
        db=db,
        scan_log_id=scan_log.id,
        vt_detected_engines=result.vt_detected_engines,
        vt_total_engines=result.vt_total_engines,
        vt_weighted_score=result.vt_weighted_score,
        ml_probability=result.ml_probability,
        ml_weighted_score=result.ml_weighted_score,
        weighting_case=result.weighting_case,
        xai_features=result.xai_features,
    )

    # 4) risk_level: 코드 → 사용자 문구 객체 변환
    risk_meta = RISK_LEVEL_META.get(result.risk_level, RISK_LEVEL_META["SUSPICIOUS"])
    risk_level = RiskLevel(
        code=result.risk_level,
        label=risk_meta["label"],
        description=risk_meta["description"],
    )

    # 5) final_score: 0.0~1.0 → 0~100 정수 변환
    final_score = round(result.final_score * 100)

    # 6) xai_features: SECURED는 빈 배열, 그 외 필터링 → 정렬 → 상위 N개
    xai_list: list[XaiFeatureDetail] = []
    if result.risk_level != "SECURED":
        for feat_name, feat_data in result.xai_features.items():
            value = feat_data.get("value", 0)
            if not value:
                continue
            meta = FEATURE_META.get(feat_name)
            if meta is None:
                continue
            xai_list.append(XaiFeatureDetail(
                title=meta["title"],
                description=meta["description"],
                severity=meta["severity"],
                contribution=round(feat_data.get("contribution", 0) * 100),
            ))

        xai_list.sort(
            key=lambda x: (-x.contribution, _SEVERITY_ORDER.get(x.severity, 99)),
        )
        xai_list = xai_list[:XAI_MAX_FEATURES]

    return ScanUrlResponse(
        scan_id=str(scan_log.id),
        url=body.url,
        risk_level=risk_level,
        final_score=final_score,
        vt_total_engines=result.vt_total_engines,
        vt_detected_engines=result.vt_detected_engines,
        xai_features=xai_list,
        scanned_at=scan_log.scanned_at or datetime.now(timezone.utc),
    )
