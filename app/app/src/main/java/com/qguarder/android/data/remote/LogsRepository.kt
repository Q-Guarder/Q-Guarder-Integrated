package com.qguarder.android.data.remote

import android.util.Log
import com.qguarder.android.data.local.ScanLogCacheDao
import com.qguarder.android.data.local.ScanLogCacheEntity
import com.qguarder.android.data.local.ScanSummaryCacheEntity
import com.qguarder.android.data.remote.dto.ReportRequest
import com.qguarder.android.data.remote.dto.ScanLogItemDto
import com.qguarder.android.data.remote.dto.ScanSummaryDto
import com.qguarder.android.data.remote.dto.VisitItemDto
import javax.inject.Inject
import javax.inject.Singleton

data class LogsData(
    val logs:      List<ScanLogItemDto>,
    val summary:   ScanSummaryDto?,
    val total:     Int = 0,             // 서버 전체 로그 수 (페이지네이션용)
    val fromCache: Boolean = false,     // UI에서 "캐시 데이터" 표시 여부 판단용
)

@Singleton
class LogsRepository @Inject constructor(
    private val apiService:      ApiService,
    private val scanLogCacheDao: ScanLogCacheDao,
) {
    private companion object { const val TAG = "LogsRepository" }

    /**
     * Offline-first 로그 조회
     * 1. 서버 요청 성공 → Room에 저장 후 반환
     * 2. 서버 실패(네트워크 오류 / 4xx~5xx) → 로컬 캐시 반환
     * 3. 캐시도 없으면 → Result.failure
     */
    /**
     * @param page 페이지 번호 (1부터 시작)
     * @param size 페이지 크기
     * @param useCache page=1 일 때만 오프라인 캐시 사용
     */
    suspend fun getLogs(page: Int = 1, size: Int = 20): Result<LogsData> {
        return try {
            val response = apiService.getScanLogs(page = page, size = size)
            if (response.isSuccessful) {
                val body = response.body()
                val logs    = body?.logs    ?: emptyList()
                val summary = body?.summary
                val total   = body?.total   ?: 0

                // 첫 페이지일 때만 로컬 캐시 교체 (오프라인 대비)
                if (page == 1) {
                    if (summary != null) {
                        scanLogCacheDao.replaceAll(
                            logs    = logs.map { it.toEntity() },
                            summary = summary.toEntity()
                        )
                    } else {
                        scanLogCacheDao.clearLogs()
                        scanLogCacheDao.insertLogs(logs.map { it.toEntity() })
                    }
                }

                Result.success(LogsData(logs = logs, summary = summary, total = total, fromCache = false))
            } else {
                Log.w(TAG, "서버 응답 실패 (${response.code()}) → 캐시 사용")
                if (page == 1) loadFromCache() else Result.success(LogsData(emptyList(), null))
            }
        } catch (e: Exception) {
            Log.w(TAG, "네트워크 오류 → 캐시 사용", e)
            if (page == 1) loadFromCache() else Result.success(LogsData(emptyList(), null))
        }
    }

    /**
     * 방문 기록 조회 — 실패해도 빈 목록 반환 (스캔 로그가 없어지는 것을 방지)
     */
    suspend fun getVisits(page: Int = 1, size: Int = 20): Result<List<VisitItemDto>> {
        return try {
            val response = apiService.getVisits(page = page, size = size)
            if (response.isSuccessful) {
                Result.success(response.body()?.items ?: emptyList())
            } else {
                Log.w(TAG, "방문 기록 조회 실패 (${response.code()})")
                Result.success(emptyList())
            }
        } catch (e: Exception) {
            Log.w(TAG, "방문 기록 네트워크 오류", e)
            Result.success(emptyList())
        }
    }

    suspend fun report(scanLogId: String, url: String, reason: String): Result<Unit> {
        return try {
            val response = apiService.report(
                ReportRequest(scanLogId = scanLogId, url = url, reason = reason)
            )
            if (response.isSuccessful) Result.success(Unit)
            else Result.failure(Exception("신고 처리에 실패했습니다 (${response.code()})"))
        } catch (e: Exception) {
            Log.w(TAG, "신고 API 오류", e)
            Result.failure(Exception("서버에 연결할 수 없습니다"))
        }
    }

    private suspend fun loadFromCache(): Result<LogsData> {
        val cachedLogs    = scanLogCacheDao.getLogs()
        val cachedSummary = scanLogCacheDao.getSummary()

        return if (cachedLogs.isNotEmpty() || cachedSummary != null) {
            Result.success(
                LogsData(
                    logs      = cachedLogs.map { it.toDto() },
                    summary   = cachedSummary?.toDto(),
                    fromCache = true,
                )
            )
        } else {
            Result.failure(Exception("서버에 연결할 수 없고 저장된 데이터가 없습니다"))
        }
    }
}

// ── Entity ↔ DTO 변환 ────────────────────────────────────────────

private fun ScanLogItemDto.toEntity() = ScanLogCacheEntity(
    scanId     = scanId,
    url        = url,
    riskLevel  = riskLevel,
    finalScore = finalScore,
    scannedAt  = scannedAt,
)

private fun ScanLogCacheEntity.toDto() = ScanLogItemDto(
    scanId     = scanId,
    url        = url,
    riskLevel  = riskLevel,
    finalScore = finalScore,
    scannedAt  = scannedAt,
)

private fun ScanSummaryDto.toEntity() = ScanSummaryCacheEntity(
    id              = 0,
    totalScans      = totalScans,
    securedCount    = securedCount,
    suspiciousCount = suspiciousCount,
    blockedCount    = blockedCount,
    reportedCount   = reportedCount,
)

private fun ScanSummaryCacheEntity.toDto() = ScanSummaryDto(
    totalScans      = totalScans,
    securedCount    = securedCount,
    suspiciousCount = suspiciousCount,
    blockedCount    = blockedCount,
    reportedCount   = reportedCount,
)