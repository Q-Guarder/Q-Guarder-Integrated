package com.qguarder.android.data.remote

import android.util.Log
import com.qguarder.android.data.local.ScanLogCacheDao
import com.qguarder.android.data.local.ScanLogCacheEntity
import com.qguarder.android.data.local.WhitelistDao
import com.qguarder.android.data.remote.dto.AddVisitRequest
import com.qguarder.android.data.remote.dto.ScanRequest
import com.qguarder.android.data.remote.dto.ScanResponse
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.domain.model.ScanResult
import com.qguarder.android.domain.model.XaiItem
import javax.inject.Inject
import javax.inject.Singleton

/**
 * URL 분석 Repository — v3.0
 *
 * 캐시 계층:
 * 1. Room DB 화이트리스트 → 히트 시 즉시 SECURED 반환
 * 2. 서버 실시간 분석 (Redis 없음 — 매번 VT + ML 호출)
 *
 * URL 이동 시:
 * - openUrl() 호출 후 POST /users/me/visits로 방문 기록 자동 저장
 */
@Singleton
class UrlRepository @Inject constructor(
    private val apiService:      ApiService,
    private val whitelistDao:    WhitelistDao,
    private val scanLogCacheDao: ScanLogCacheDao,
) {
    // tag 상수
    private companion object { const val TAG = "UrlRepository" }
    /** URL 위험도 분석 */
    suspend fun analyzeUrl(url: String, source: String = "camera"): Result<ScanResult> {
        // 1. 로컬 화이트리스트
        if (whitelistDao.isWhitelisted(url)) {
            return Result.success(
                ScanResult(
                    scanId            = "local",
                    url               = url,
                    riskLevel         = RiskLevel.SECURED,
                    riskLabel         = "안전",
                    riskDescription   = "안전한 URL입니다. 정상적으로 접속할 수 있습니다.",
                    finalScore        = 0,
                    vtTotalEngines    = 0,
                    vtDetectedEngines = 0,
                    xaiFeatures       = emptyList(),
                    scannedAt         = "",
                )
            )
        }

        // 2. 서버 실시간 분석
        return try {
            val resp = apiService.scanUrl(ScanRequest(url = url, source = source))
            if (!resp.isSuccessful || resp.body() == null) {
                Log.w(TAG, "scanUrl failed: HTTP ${resp.code()}")
                Result.failure(Exception("URL 분석에 실패했습니다 (${resp.code()})"))
            } else {
                val result = resp.body()!!.toDomain()
                // 스캔 시점에 바로 캐시 저장 — 로그 화면 미방문 시에도 폴백 가능
                scanLogCacheDao.insertLogs(listOf(result.toEntity()))
                Result.success(result)
            }
        } catch (e: java.net.UnknownHostException) {
            Log.e(TAG, "scanUrl 네트워크 오류", e)
            cachedScanResult(url) ?: Result.failure(Exception("인터넷에 연결할 수 없습니다"))
        } catch (e: java.net.SocketTimeoutException) {
            Log.e(TAG, "scanUrl 타임아웃", e)
            cachedScanResult(url) ?: Result.failure(Exception("서버 응답 시간이 초과되었습니다"))
        } catch (e: Exception) {
            Log.e(TAG, "scanUrl exception", e)
            cachedScanResult(url) ?: Result.failure(Exception("URL 분석 중 오류가 발생했습니다"))
        }
    }

    /**
     * Level 3 폴백 — 서버 장애 시 Room 캐시에서 이전 스캔 결과 반환
     * 캐시 있으면 → 이전 결과 + "이전 분석 결과" 안내
     * 캐시 없으면 → null (호출부에서 failure 처리)
     */
    private suspend fun cachedScanResult(url: String): Result<ScanResult>? {
        val cached = scanLogCacheDao.getByUrl(url) ?: return null
        val riskLevel = RiskLevel.from(cached.riskLevel)
        return Result.success(
            ScanResult(
                scanId            = cached.scanId,
                url               = cached.url,
                riskLevel         = riskLevel,
                riskLabel         = riskLevel.label,
                riskDescription   = "서버에 연결할 수 없어 이전 분석 결과를 표시합니다.",
                finalScore        = cached.finalScore,
                vtTotalEngines    = 0,
                vtDetectedEngines = 0,
                xaiFeatures       = emptyList(),
                scannedAt         = cached.scannedAt,
            )
        )
    }

    /** URL 방문 기록 저장 (브라우저/앱으로 열기 버튼 눌렀을 때) */
    suspend fun recordVisit(url: String, riskLevel: RiskLevel) {
        try {
            apiService.addVisit(
                AddVisitRequest(url = url, riskLevel = riskLevel.name)
            )
        } catch (_: Exception) {
            // 방문 기록 실패는 무시 (UX에 영향 없음)
        }
    }
}

// ── Domain → Cache Entity 변환 ───────────────────────
private fun ScanResult.toEntity() = ScanLogCacheEntity(
    scanId     = scanId,
    url        = url,
    riskLevel  = riskLevel.name,
    finalScore = finalScore,
    scannedAt  = scannedAt,
)

// ── DTO → Domain 변환 ────────────────────────────────
private fun ScanResponse.toDomain() = ScanResult(
    scanId            = scanId,
    url               = url,
    riskLevel         = RiskLevel.from(riskLevel.code),
    riskLabel         = riskLevel.label,
    riskDescription   = riskLevel.description,
    finalScore        = finalScore,
    vtTotalEngines    = vtTotalEngines,
    vtDetectedEngines = vtDetectedEngines,
    xaiFeatures       = xaiFeatures.map { dto ->
        XaiItem(
            title        = dto.title,
            description  = dto.description,
            severity     = dto.severity,
            contribution = dto.contribution,
        )
    },  // 서버에서 이미 contribution 내림차순 정렬, 최대 5개 제공
    scannedAt         = scannedAt,
)
