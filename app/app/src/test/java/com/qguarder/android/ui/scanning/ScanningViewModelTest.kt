package com.qguarder.android.ui.scanning

import com.qguarder.android.data.ScanResultStore
import com.qguarder.android.data.remote.UrlRepository
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.domain.model.ScanResult
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ScanningViewModelTest {

    private val urlRepository = mockk<UrlRepository>()
    private val scanResultStore = ScanResultStore()
    private lateinit var viewModel: ScanningViewModel
    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = ScanningViewModel(urlRepository, scanResultStore)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        scanResultStore.clear()
    }

    // ── 테스트용 ScanResult 팩토리 ────────────────────────────────
    private fun fakeScanResult(url: String, riskLevel: RiskLevel, scanId: String = "test-id") =
        ScanResult(
            scanId            = scanId,
            url               = url,
            riskLevel         = riskLevel,
            riskLabel         = riskLevel.name,
            riskDescription   = "",
            finalScore        = 50,
            vtTotalEngines    = 90,
            vtDetectedEngines = 0,
            xaiFeatures       = emptyList(),
            scannedAt         = "2025-01-01T00:00:00Z",
        )

    // ── BLOCKED ───────────────────────────────────────────────────
    @Test
    fun analyze_blocked_setsBlockedStateAndStoresResult() = runTest {
        val result = fakeScanResult("https://evil.com", RiskLevel.BLOCKED, scanId = "block-1")
        coEvery { urlRepository.analyzeUrl("https://evil.com") } returns Result.success(result)

        viewModel.analyze("https://evil.com")
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        val state = viewModel.uiState.value
        assertTrue(state is ScanningUiState.Blocked)
        assertEquals("block-1", (state as ScanningUiState.Blocked).scanId)
        assertEquals(result, scanResultStore.latestBlocked)
    }

    // ── SUSPICIOUS → Warning ─────────────────────────────────────
    @Test
    fun analyze_suspicious_setsWarningStateAndStoresResult() = runTest {
        val result = fakeScanResult("https://suspicious.com", RiskLevel.SUSPICIOUS, scanId = "warn-1")
        coEvery { urlRepository.analyzeUrl("https://suspicious.com") } returns Result.success(result)

        viewModel.analyze("https://suspicious.com")
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        val state = viewModel.uiState.value
        assertTrue(state is ScanningUiState.Warning)
        assertEquals("warn-1", (state as ScanningUiState.Warning).scanId)
        assertEquals(result, scanResultStore.latestSuspicious)
    }

    // ── SECURED ───────────────────────────────────────────────────
    @Test
    fun analyze_secured_setsSecuredStateAndStoresResult() = runTest {
        val result = fakeScanResult("https://safe.com", RiskLevel.SECURED, scanId = "safe-1")
        coEvery { urlRepository.analyzeUrl("https://safe.com") } returns Result.success(result)

        viewModel.analyze("https://safe.com")
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        val state = viewModel.uiState.value
        assertTrue(state is ScanningUiState.Secured)
        assertEquals("safe-1", (state as ScanningUiState.Secured).scanId)
        assertEquals(result, scanResultStore.latestSecured)
    }

    // ── Repository 실패 → Error 상태 ─────────────────────────────
    @Test
    fun analyze_repositoryFailure_setsErrorState() = runTest {
        coEvery { urlRepository.analyzeUrl("https://any.com") } returns
                Result.failure(Exception("서버 오류"))

        viewModel.analyze("https://any.com")
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        val state = viewModel.uiState.value
        assertTrue(state is ScanningUiState.Error)
        assertEquals("서버 오류", (state as ScanningUiState.Error).message)
    }

    // ── 화면 회전 재호출 방지 (analyzeJob guard) ──────────────────
    // ViewModel은 회전 후 재사용되며, Fragment가 다시 analyze()를 호출한다.
    // analyzeJob이 이미 있으면 두 번째 호출은 무시되어야 한다.
    @Test
    fun analyze_secondCall_isIgnored_preventingDuplicateRequest() = runTest {
        val result = fakeScanResult("https://safe.com", RiskLevel.SECURED)
        coEvery { urlRepository.analyzeUrl("https://safe.com") } returns Result.success(result)

        viewModel.analyze("https://safe.com")   // 첫 번째 호출
        viewModel.analyze("https://safe.com")   // 화면 회전 재호출 — 무시 대상
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        // analyzeUrl은 정확히 1번만 호출되어야 함
        coVerify(exactly = 1) { urlRepository.analyzeUrl("https://safe.com") }
    }

    // ── Error 메시지 기본값 ──────────────────────────────────────
    @Test
    fun analyze_exceptionWithNoMessage_usesDefaultMessage() = runTest {
        coEvery { urlRepository.analyzeUrl("https://any.com") } returns
                Result.failure(Exception())  // message == null

        viewModel.analyze("https://any.com")
        advanceUntilIdle()   // 최소 표시 시간(MIN_DISPLAY_MS) delay를 가상 시간으로 통과

        val state = viewModel.uiState.value as ScanningUiState.Error
        assertEquals("분석 실패", state.message)
    }

    // ── ScanResultStore 초기값 확인 (analyze 전) ─────────────────
    @Test
    fun beforeAnalyze_storeIsEmpty() {
        assertNotNull(scanResultStore)
        assertEquals(null, scanResultStore.latestBlocked)
        assertEquals(null, scanResultStore.latestSuspicious)
        assertEquals(null, scanResultStore.latestSecured)
    }
}
