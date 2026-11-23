package com.qguarder.android.data.remote

import com.qguarder.android.data.local.ScanLogCacheDao
import com.qguarder.android.data.local.ScanLogCacheEntity
import com.qguarder.android.data.local.ScanSummaryCacheEntity
import com.qguarder.android.data.remote.dto.ReportResponse
import com.qguarder.android.data.remote.dto.ScanLogItemDto
import com.qguarder.android.data.remote.dto.ScanLogsResponse
import com.qguarder.android.data.remote.dto.ScanSummaryDto
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.just
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Response

class LogsRepositoryTest {

    private val apiService      = mockk<ApiService>()
    private val scanLogCacheDao = mockk<ScanLogCacheDao>()
    private lateinit var repository: LogsRepository

    @Before
    fun setUp() {
        repository = LogsRepository(apiService, scanLogCacheDao)
    }

    // ── 공통 픽스처 ──────────────────────────────────────────────

    private val fakeSummary = ScanSummaryDto(
        totalScans    = 10,
        securedCount  = 8,
        blockedCount  = 1,
        reportedCount = 1,
    )
    private val fakeLogs = listOf(
        ScanLogItemDto(scanId = "id-1", url = "https://safe.com",  riskLevel = "SECURED", scannedAt = "2025-01-01"),
        ScanLogItemDto(scanId = "id-2", url = "https://evil.com",  riskLevel = "BLOCKED", scannedAt = "2025-01-02"),
    )
    private val fakeCachedLogs = listOf(
        ScanLogCacheEntity(scanId = "c-1", url = "https://cached.com", riskLevel = "SECURED", scannedAt = "2025-01-01"),
    )
    private val fakeCachedSummary = ScanSummaryCacheEntity(
        totalScans = 5, securedCount = 4, blockedCount = 1, reportedCount = 0,
    )

    // ── 서버 성공 ────────────────────────────────────────────────
    @Test
    fun getLogs_serverSuccess_returnsLogsAndCachesLocally() = runTest {
        coEvery { apiService.getScanLogs(any(), any()) } returns
                Response.success(ScanLogsResponse(summary = fakeSummary, logs = fakeLogs))
        coEvery { scanLogCacheDao.replaceAll(any(), any()) } just Runs

        val result = repository.getLogs()

        assertTrue(result.isSuccess)
        val data = result.getOrThrow()
        assertEquals(2, data.logs.size)
        assertEquals("id-1", data.logs[0].scanId)
        assertEquals(fakeSummary.totalScans, data.summary?.totalScans)
        assertFalse(data.fromCache)
        coVerify(exactly = 1) { scanLogCacheDao.replaceAll(any(), any()) }
    }

    // ── 서버 오류 → 캐시 반환 ────────────────────────────────────
    @Test
    fun getLogs_serverError_returnsCachedData() = runTest {
        coEvery { apiService.getScanLogs(any(), any()) } returns
                Response.error(500, "{}".toResponseBody(null))
        coEvery { scanLogCacheDao.getLogs() }    returns fakeCachedLogs
        coEvery { scanLogCacheDao.getSummary() } returns fakeCachedSummary

        val result = repository.getLogs()

        assertTrue(result.isSuccess)
        val data = result.getOrThrow()
        assertEquals(1, data.logs.size)
        assertEquals("c-1", data.logs[0].scanId)
        assertTrue(data.fromCache)
    }

    // ── 네트워크 예외 → 캐시 반환 ───────────────────────────────
    @Test
    fun getLogs_networkException_returnsCachedData() = runTest {
        coEvery { apiService.getScanLogs(any(), any()) } throws Exception("네트워크 오류")
        coEvery { scanLogCacheDao.getLogs() }    returns fakeCachedLogs
        coEvery { scanLogCacheDao.getSummary() } returns null  // summary 없이도 캐시 반환

        val result = repository.getLogs()

        assertTrue(result.isSuccess)
        assertTrue(result.getOrThrow().fromCache)
    }

    // ── 서버 오류 + 캐시 없음 → 실패 ────────────────────────────
    @Test
    fun getLogs_serverError_noCache_returnsFailure() = runTest {
        coEvery { apiService.getScanLogs(any(), any()) } returns
                Response.error(503, "{}".toResponseBody(null))
        coEvery { scanLogCacheDao.getLogs() }    returns emptyList()
        coEvery { scanLogCacheDao.getSummary() } returns null

        val result = repository.getLogs()

        assertTrue(result.isFailure)
    }

    // ── 신고 성공 ────────────────────────────────────────────────
    @Test
    fun report_success_returnsUnit() = runTest {
        coEvery { apiService.report(any()) } returns
                Response.success(ReportResponse(reportId = "r-1", status = "ok", message = "신고 완료"))

        val result = repository.report("scan-1", "https://evil.com", "피싱 의심")

        assertTrue(result.isSuccess)
    }

    // ── 신고 서버 오류 ───────────────────────────────────────────
    @Test
    fun report_serverError_returnsFailureWithCode() = runTest {
        coEvery { apiService.report(any()) } returns
                Response.error(400, "{}".toResponseBody(null))

        val result = repository.report("scan-1", "https://evil.com", "피싱 의심")

        assertTrue(result.isFailure)
        assertEquals(
            "신고 처리에 실패했습니다 (400)",
            result.exceptionOrNull()?.message,
        )
    }

    // ── 신고 네트워크 예외 ───────────────────────────────────────
    @Test
    fun report_networkException_returnsFailure() = runTest {
        coEvery { apiService.report(any()) } throws Exception("연결 불가")

        val result = repository.report("scan-1", "https://evil.com", "피싱 의심")

        assertTrue(result.isFailure)
        assertEquals("서버에 연결할 수 없습니다", result.exceptionOrNull()?.message)
    }
}
