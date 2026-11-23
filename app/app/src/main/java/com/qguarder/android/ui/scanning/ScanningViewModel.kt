package com.qguarder.android.ui.scanning

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.ScanResultStore
import com.qguarder.android.data.remote.UrlRepository
import com.qguarder.android.domain.model.RiskLevel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class ScanningUiState {
    object Loading                                : ScanningUiState()
    data class Secured(val scanId: String)        : ScanningUiState()
    data class Warning(val scanId: String)        : ScanningUiState()
    data class Blocked(val scanId: String)        : ScanningUiState()
    data class Error(val message: String)         : ScanningUiState()
}

@HiltViewModel
class ScanningViewModel @Inject constructor(
    private val urlRepository: UrlRepository,
    private val scanResultStore: ScanResultStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ScanningUiState>(ScanningUiState.Loading)
    val uiState: StateFlow<ScanningUiState> = _uiState.asStateFlow()

    // 화면 회전 시 Fragment가 재생성되어 analyze()가 재호출되는 것을 방지
    private var analyzeJob: Job? = null

    fun analyze(url: String) {
        if (analyzeJob != null) return
        performAnalysis(url)
    }

    /** 에러 후 재시도 — analyzeJob을 리셋하고 다시 분석 */
    fun retry(url: String) {
        analyzeJob?.cancel()
        analyzeJob = null
        _uiState.value = ScanningUiState.Loading
        performAnalysis(url)
    }

    companion object {
        // 스캐닝 애니메이션 최소 표시 시간 — 응답이 빨라도 분석 과정을 인지할 수 있도록 유지
        private const val MIN_DISPLAY_MS = 4_000L
    }

    private fun performAnalysis(url: String) {
        analyzeJob = viewModelScope.launch {
            val startTime = System.currentTimeMillis()

            val analysisResult = urlRepository.analyzeUrl(url)

            // 페이즈 애니메이션이 충분히 보이도록 최소 대기
            val elapsed = System.currentTimeMillis() - startTime
            val remaining = MIN_DISPLAY_MS - elapsed
            if (remaining > 0) delay(remaining)

            analysisResult.fold(
                onSuccess = { result ->
                    when (result.riskLevel) {
                        RiskLevel.BLOCKED -> {
                            scanResultStore.latestBlocked = result
                            _uiState.value = ScanningUiState.Blocked(result.scanId)
                        }
                        RiskLevel.SUSPICIOUS -> {
                            scanResultStore.latestSuspicious = result
                            _uiState.value = ScanningUiState.Warning(result.scanId)
                        }
                        else -> {
                            scanResultStore.latestSecured = result
                            _uiState.value = ScanningUiState.Secured(result.scanId)
                        }
                    }
                },
                onFailure = { _uiState.value = ScanningUiState.Error(it.message ?: "분석 실패") }
            )
        }
    }
}