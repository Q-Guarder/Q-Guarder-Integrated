package com.qguarder.android.ui.scan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.WhitelistDao
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

/** 화이트리스트/즐겨찾기 히트 구분 */
enum class WhitelistReason { WHITELIST, FAVORITE }

sealed class ScanUiState {
    object Idle                                        : ScanUiState()
    object Scanning                                    : ScanUiState()
    data class NavigateToScanning(val url: String)     : ScanUiState()
    data class NavigateToWhitelist(
        val url: String,
        val reason: WhitelistReason
    )                                                  : ScanUiState()
    data class Error(val message: String)              : ScanUiState()
}

@HiltViewModel
class ScanViewModel @Inject constructor(
    private val whitelistDao: WhitelistDao,
    private val favoriteCacheDao: FavoriteCacheDao
) : ViewModel() {

    private val _uiState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    fun analyzeUrl(url: String) {
        viewModelScope.launch {
            _uiState.value = ScanUiState.Scanning

            // 1순위 — Whitelist 캐시 히트
            if (whitelistDao.isWhitelisted(url)) {
                _uiState.value = ScanUiState.NavigateToWhitelist(
                    url    = url,
                    reason = WhitelistReason.WHITELIST  // ← 이유 구분
                )
                return@launch
            }

            // 2순위 — Favorites 캐시 히트
            if (favoriteCacheDao.isFavorited(url)) {
                _uiState.value = ScanUiState.NavigateToWhitelist(
                    url    = url,
                    reason = WhitelistReason.FAVORITE   // ← 이유 구분
                )
                return@launch
            }

            // 3순위 — 서버 분석
            _uiState.value = ScanUiState.NavigateToScanning(url)
        }
    }

    fun reset() { _uiState.value = ScanUiState.Idle }
}