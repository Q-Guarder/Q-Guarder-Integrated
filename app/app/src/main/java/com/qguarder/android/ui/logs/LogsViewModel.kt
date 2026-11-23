package com.qguarder.android.ui.logs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.local.UserPreferences
import com.qguarder.android.data.remote.LogsRepository
import com.qguarder.android.data.remote.dto.ScanLogItemDto
import com.qguarder.android.data.remote.dto.ScanSummaryDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.time.OffsetDateTime
import javax.inject.Inject

enum class LogFilter { ALL, SECURED, BLOCKED, SUSPICIOUS }

@HiltViewModel
class LogsViewModel @Inject constructor(
    private val logsRepository:  LogsRepository,
    private val userPreferences: UserPreferences,
) : ViewModel() {

    companion object {
        private const val PAGE_SIZE = 20
    }

    /** 전체(필터 전) 목록 — 필터 변경 시 재요청 없이 재필터링 */
    private val _allItems = MutableStateFlow<List<LogListItem>>(emptyList())

    /** 현재 선택된 필터 */
    private val _filter = MutableStateFlow(LogFilter.ALL)

    /** 필터 적용된 목록 — UI가 관찰 (보관 기간 + 위험도 필터 동시 적용) */
    val logItems = combine(
        _allItems,
        _filter,
        userPreferences.historyRetentionDays,
    ) { items, filter, retentionDays ->
        // 1) 보관 기간 필터 (클라이언트 전용 — 서버 데이터는 유지됨)
        val cutoffEpochSec: Long = if (retentionDays == UserPreferences.RETENTION_ALL) {
            0L
        } else {
            (System.currentTimeMillis() / 1000) - retentionDays.toLong() * 24 * 60 * 60
        }
        val retained = if (cutoffEpochSec == 0L) items
        else items.filter { parseEpoch(it.timestamp) >= cutoffEpochSec }

        // 2) 위험도 필터
        if (filter == LogFilter.ALL) retained
        else retained.filter { it.matchesFilter(filter) }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _stats = MutableStateFlow<ScanSummaryDto?>(null)
    val stats = _stats.asStateFlow()

    private val _error = MutableSharedFlow<String>()
    val error: SharedFlow<String> = _error

    private val _isLoading = MutableStateFlow(false)
    val isLoading = _isLoading.asStateFlow()

    private val _isLoadingMore = MutableStateFlow(false)
    val isLoadingMore = _isLoadingMore.asStateFlow()

    // 페이지네이션 상태
    private var currentPage = 1
    private var hasMorePages = true

    init { loadLogs() }

    /**
     * 첫 페이지 로드 (새로고침 시에도 호출)
     */
    fun loadLogs() {
        currentPage = 1
        hasMorePages = true

        viewModelScope.launch {
            _isLoading.value = true

            // 두 API를 병렬로 호출해 총 대기 시간 단축
            val logsDeferred   = async { logsRepository.getLogs(page = 1, size = PAGE_SIZE) }
            val visitsDeferred = async { logsRepository.getVisits(page = 1, size = PAGE_SIZE) }

            val logsResult   = logsDeferred.await()
            val visitsResult = visitsDeferred.await()

            logsResult.fold(
                onSuccess = { data ->
                    _stats.value = data.summary
                    if (data.fromCache) {
                        _error.emit("오프라인 상태 — 마지막 저장 데이터를 표시합니다")
                    }

                    val scanItems = data.logs.map { LogListItem.ScanLog(it) }
                    val visitItems = visitsResult
                        .getOrElse { emptyList() }
                        .map { LogListItem.VisitLog(it.url, it.riskLevel, it.visitedAt) }

                    _allItems.value = (scanItems + visitItems)
                        .sortedByDescending { parseEpoch(it.timestamp) }

                    // 다음 페이지 존재 여부 판단
                    hasMorePages = data.logs.size >= PAGE_SIZE
                },
                onFailure = { e ->
                    _error.emit(e.message ?: "데이터를 불러올 수 없습니다")
                }
            )
            _isLoading.value = false
        }
    }

    /**
     * 다음 페이지 로드 (무한 스크롤)
     */
    fun loadMore() {
        if (_isLoadingMore.value || !hasMorePages) return

        viewModelScope.launch {
            _isLoadingMore.value = true
            val nextPage = currentPage + 1

            logsRepository.getLogs(page = nextPage, size = PAGE_SIZE).fold(
                onSuccess = { data ->
                    if (data.logs.isEmpty()) {
                        hasMorePages = false
                    } else {
                        currentPage = nextPage
                        hasMorePages = data.logs.size >= PAGE_SIZE

                        val newScanItems = data.logs.map { LogListItem.ScanLog(it) }
                        _allItems.value = (_allItems.value + newScanItems)
                            .sortedByDescending { parseEpoch(it.timestamp) }
                    }
                },
                onFailure = { e ->
                    _error.emit(e.message ?: "추가 데이터를 불러올 수 없습니다")
                }
            )
            _isLoadingMore.value = false
        }
    }

    /** 신고 처리 — 로컬 목록의 해당 항목을 REPORTED로 즉시 갱신 */
    fun report(item: ScanLogItemDto, reason: String) {
        viewModelScope.launch {
            logsRepository.report(scanLogId = item.scanId, url = item.url, reason = reason).fold(
                onSuccess = {
                    _allItems.value = _allItems.value.map { logItem ->
                        if (logItem is LogListItem.ScanLog && logItem.dto.scanId == item.scanId)
                            LogListItem.ScanLog(logItem.dto.copy(riskLevel = "REPORTED"))
                        else logItem
                    }
                },
                onFailure = { e ->
                    _error.emit(e.message ?: "신고에 실패했습니다")
                }
            )
        }
    }

    fun setFilter(filter: LogFilter) {
        _filter.value = filter
    }

    // ── 내부 유틸 ────────────────────────────────────────────────────

    private fun LogListItem.matchesFilter(filter: LogFilter): Boolean {
        val risk = when (this) {
            is LogListItem.ScanLog  -> dto.riskLevel
            is LogListItem.VisitLog -> riskLevel
        }
        return when (filter) {
            LogFilter.ALL        -> true
            LogFilter.SECURED    -> risk == "SECURED"
            LogFilter.BLOCKED    -> risk == "BLOCKED" || risk == "REPORTED"
            LogFilter.SUSPICIOUS -> risk == "SUSPICIOUS"
        }
    }

    /** 아이템 타입에 관계없이 시간 문자열을 꺼내는 확장 프로퍼티 */
    private val LogListItem.timestamp: String
        get() = when (this) {
            is LogListItem.ScanLog  -> dto.scannedAt
            is LogListItem.VisitLog -> visitedAt
        }

    /** ISO 8601 → epoch second. 파싱 실패 시 0 (가장 오래된 항목으로 처리) */
    private fun parseEpoch(ts: String): Long = try {
        OffsetDateTime.parse(ts).toEpochSecond()
    } catch (_: Exception) { 0L }
}
