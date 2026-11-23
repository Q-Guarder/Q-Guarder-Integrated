package com.qguarder.android.ui.scan

import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.WhitelistDao
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ScanViewModelTest {

    private val whitelistDao    = mockk<WhitelistDao>()
    private val favoriteCacheDao = mockk<FavoriteCacheDao>()
    private lateinit var viewModel: ScanViewModel
    private val testDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = ScanViewModel(whitelistDao, favoriteCacheDao)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // ── 화이트리스트 히트 ─────────────────────────────────────────
    @Test
    fun analyzeUrl_whitelistHit_navigatesToWhitelistWithWhitelistReason() = runTest {
        coEvery { whitelistDao.isWhitelisted("https://safe.com") } returns true

        viewModel.analyzeUrl("https://safe.com")

        val state = viewModel.uiState.value
        assertTrue(state is ScanUiState.NavigateToWhitelist)
        state as ScanUiState.NavigateToWhitelist
        assertEquals("https://safe.com", state.url)
        assertEquals(WhitelistReason.WHITELIST, state.reason)
    }

    // ── 즐겨찾기 히트 (화이트리스트 미스) ────────────────────────
    @Test
    fun analyzeUrl_favoriteHit_navigatesToWhitelistWithFavoriteReason() = runTest {
        coEvery { whitelistDao.isWhitelisted("https://fav.com") }     returns false
        coEvery { favoriteCacheDao.isFavorited("https://fav.com") }   returns true

        viewModel.analyzeUrl("https://fav.com")

        val state = viewModel.uiState.value
        assertTrue(state is ScanUiState.NavigateToWhitelist)
        state as ScanUiState.NavigateToWhitelist
        assertEquals("https://fav.com", state.url)
        assertEquals(WhitelistReason.FAVORITE, state.reason)
    }

    // ── 캐시 미스 → 서버 분석으로 이동 ───────────────────────────
    @Test
    fun analyzeUrl_noCache_navigatesToScanning() = runTest {
        coEvery { whitelistDao.isWhitelisted("https://unknown.com") }   returns false
        coEvery { favoriteCacheDao.isFavorited("https://unknown.com") } returns false

        viewModel.analyzeUrl("https://unknown.com")

        val state = viewModel.uiState.value
        assertTrue(state is ScanUiState.NavigateToScanning)
        assertEquals("https://unknown.com", (state as ScanUiState.NavigateToScanning).url)
    }

    // ── reset() 이후 Idle 복귀 ────────────────────────────────────
    @Test
    fun reset_setsStateToIdle() = runTest {
        coEvery { whitelistDao.isWhitelisted(any()) }    returns false
        coEvery { favoriteCacheDao.isFavorited(any()) }  returns false

        viewModel.analyzeUrl("https://any.com")
        // NavigateToScanning 상태임을 확인
        assertTrue(viewModel.uiState.value is ScanUiState.NavigateToScanning)

        viewModel.reset()
        assertEquals(ScanUiState.Idle, viewModel.uiState.value)
    }

    // ── 화이트리스트가 즐겨찾기보다 우선순위가 높음 ───────────────
    @Test
    fun analyzeUrl_whitelist_takesPriorityOverFavorite() = runTest {
        // 둘 다 히트 → WHITELIST 이유가 반환되어야 함
        coEvery { whitelistDao.isWhitelisted("https://both.com") }    returns true
        // favoriteCacheDao.isFavorited는 호출 자체가 안 됨

        viewModel.analyzeUrl("https://both.com")

        val state = viewModel.uiState.value as ScanUiState.NavigateToWhitelist
        assertEquals(WhitelistReason.WHITELIST, state.reason)
    }
}
