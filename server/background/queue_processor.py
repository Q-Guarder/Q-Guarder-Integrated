"""백그라운드 큐 프로세서 — FeedbackQueue 미처리 건을 VT 재검사

FEEDBACK_QUEUE에서 processed_at이 NULL인 건들을 순차 처리합니다.
필요할 때 server/ 폴더에서 직접 실행합니다:
  python -m background.queue_processor
  (Docker: docker compose exec web python -m background.queue_processor)

처리 흐름:
  1. 미처리 FeedbackQueue 항목 조회
  2. VirusTotal API로 URL 재검사
  3. VT 결과(vt_verdict, is_approved) 기록
  4. 처리 완료 → processed_at 기록

※ KISA 신고는 사용자가 BLOCKED URL을 신고할 때 즉시 발송됩니다. (report.py)
"""

import asyncio
import logging
from datetime import datetime, timezone

from app.db.session import AsyncSessionLocal
from app.crud.crud_report import get_pending_feedback_items
from app.services.hybrid_engine import VTStatus, scan_url_with_virustotal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


async def process_feedback_queue() -> dict:
    """미처리 FeedbackQueue 항목을 VT 재검사 처리"""
    processed_count = 0
    deferred_count = 0

    async with AsyncSessionLocal() as db:
        try:
            pending_items = await get_pending_feedback_items(db)
            logger.info("미처리 FeedbackQueue 항목: %d건", len(pending_items))

            for item in pending_items:
                try:
                    # 1) VirusTotal 재검사
                    vt_result = await scan_url_with_virustotal(item.url)

                    # 2) 조회 실패는 '판정'이 아니다 — processed_at을 남기지 않고
                    #    다음 스케줄에서 재시도한다. (과거에는 clean 0/0으로 오기록됨)
                    if vt_result.status is VTStatus.UNAVAILABLE:
                        logger.warning(
                            "VT 조회 불가 — 다음 주기에 재시도: %s (http=%s)",
                            item.url, vt_result.http_status,
                        )
                        deferred_count += 1
                        continue

                    # 3) VT 결과 기록
                    if vt_result.status is VTStatus.NOT_FOUND:
                        item.vt_verdict = "unlisted (not in VT)"
                        item.is_approved = False
                    elif vt_result.detected_engines > 0:
                        item.vt_verdict = f"malicious ({vt_result.detected_engines}/{vt_result.total_engines})"
                        item.is_approved = True
                    else:
                        item.vt_verdict = f"clean (0/{vt_result.total_engines})"
                        item.is_approved = False

                    # 4) 처리 완료 기록
                    item.processed_at = datetime.now(timezone.utc)
                    processed_count += 1

                except Exception:
                    logger.exception("FeedbackQueue 항목 처리 실패: %s", item.url)
                    continue

            await db.commit()

        except Exception:
            await db.rollback()
            logger.exception("FeedbackQueue 전체 처리 중 오류 발생")
            raise

    summary = {
        "processed": processed_count,
        "deferred": deferred_count,  # VT 조회 실패로 다음 주기에 재시도할 건수
    }
    logger.info("큐 처리 완료: %s", summary)
    return summary


# ── 직접 실행: python -m background.queue_processor ──

if __name__ == "__main__":
    asyncio.run(process_feedback_queue())
