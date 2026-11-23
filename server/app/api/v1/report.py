"""신고 API 라우터 — 악성 URL 신고 접수 및 Feedback Queue 적재, KISA 자동 신고 (BackgroundTasks)"""

import uuid
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user_id
from app.crud import crud_report, crud_scan
from app.db.session import AsyncSessionLocal, get_db
from app.schemas.report_schema import ReportRequest, ReportResponse
from app.services.kisa_reporter import send_kisa_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/report", tags=["Report"])


async def _send_kisa_background(
    feedback_id: uuid.UUID,
    report_id: str,
    url: str,
    threat_score: float,
    vt_detected: int,
    vt_total: int,
    ml_probability: float,
    weighting_case: str,
    xai_features: dict | None,
) -> None:
    """BackgroundTasks에서 실행되는 KISA 신고 작업.

    FastAPI는 코루틴 함수를 그대로 await하므로 별도 이벤트 루프가 필요 없다.
    발송이 성공한 경우에만 is_reported_to_kisa를 갱신하여, 실패 건이 '신고 완료'로
    남아 재시도가 막히는 상황을 방지한다. 요청 세션은 이미 닫혔으므로 새 세션을 연다.
    """
    try:
        sent = await send_kisa_report(
            reported_url=url,
            threat_score=threat_score,
            vt_detected_count=vt_detected,
            report_id=report_id,
            ml_probability=ml_probability,
            vt_total_engines=vt_total,
            weighting_case=weighting_case,
            xai_features=xai_features,
        )
    except Exception:
        logger.exception("KISA 자동 신고 중 예외 발생 (background): %s", url)
        return

    if not sent:
        logger.warning("KISA 자동 신고 실패 — 다음 기회에 재시도 가능: %s", url)
        return

    logger.info("KISA 자동 신고 완료 (background): %s", url)
    try:
        async with AsyncSessionLocal() as db:
            await crud_report.mark_kisa_reported(db, feedback_id)
            await db.commit()
    except Exception:
        logger.exception("KISA 신고 플래그 갱신 실패 (feedback_id=%s)", feedback_id)


@router.post(
    "",
    response_model=ReportResponse,
    status_code=status.HTTP_200_OK,
    summary="악성 URL 신고",
    description=(
        "사용자가 스캔 결과를 기반으로 URL을 악성으로 신고합니다. "
        "신고 접수 후 Feedback Queue에 적재되며, "
        "해당 URL이 BLOCKED 판정인 경우 BackgroundTasks를 통해 "
        "AWS SES → KISA(cert@kisa.or.kr) 자동 신고 메일을 비동기로 발송합니다."
    ),
)
async def report_url(
    body: ReportRequest,
    background_tasks: BackgroundTasks,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    # 1) 스캔 로그 존재 확인
    scan_log = await crud_scan.get_scan_log_by_id(db, uuid.UUID(body.scan_log_id))
    if not scan_log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="해당 스캔 기록을 찾을 수 없습니다.",
        )

    # 1-b) 소유자 검증 — 본인의 스캔 기록만 신고 가능
    if str(scan_log.user_id) != current_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="본인의 스캔 기록만 신고할 수 있습니다.",
        )

    # 2) 신고 접수
    reported = await crud_report.create_reported_url(
        db=db,
        user_id=uuid.UUID(current_user_id),
        scan_log_id=scan_log.id,
        url=body.url,
        reason=body.reason,
    )

    # 3) Feedback Queue 적재
    feedback_item = await crud_report.create_feedback_queue(db, reported.id, body.url)

    # 4) BLOCKED 판정 URL → KISA 자동 신고 (BackgroundTasks 비동기)
    #    is_reported_to_kisa는 여기서 세우지 않는다. 발송 성공 후 백그라운드에서 갱신한다.
    if scan_log.risk_level == "BLOCKED":
        detail = scan_log.score_detail
        background_tasks.add_task(
            _send_kisa_background,
            feedback_id=feedback_item.id,
            report_id=str(reported.id),
            url=body.url,
            threat_score=scan_log.final_score,
            vt_detected=(detail.vt_detected_engines or 0) if detail else 0,
            vt_total=(detail.vt_total_engines or 0) if detail else 0,
            ml_probability=(detail.ml_probability or 0.0) if detail else 0.0,
            weighting_case=(detail.weighting_case or "") if detail else "",
            xai_features=detail.xai_features if detail else None,
        )
        logger.info("KISA 자동 신고 BackgroundTask 등록: %s", body.url)

    return ReportResponse(
        report_id=str(reported.id),
        status="queued",
        message="신고가 접수되어 추가 검증을 진행합니다.",
    )
