package com.qguarder.android.ui.logs

import com.qguarder.android.data.remote.dto.ScanLogItemDto

/**
 * 로그 탭 RecyclerView 통합 아이템 타입.
 *
 * - [ScanLog]  : QR 스캔 분석 결과 항목 (서버 /scan-logs)
 * - [VisitLog] : 사용자가 직접 URL을 열었을 때 기록 (서버 /visits)
 *
 * 두 타입을 scannedAt / visitedAt 기준으로 내림차순 정렬해 하나의 목록으로 표시한다.
 */
sealed class LogListItem {

    /** QR 스캔 분석 결과 항목 */
    data class ScanLog(val dto: ScanLogItemDto) : LogListItem()

    /** URL 직접 접속(방문) 항목 */
    data class VisitLog(
        val url:       String,
        val riskLevel: String,
        val visitedAt: String,
    ) : LogListItem()
}
