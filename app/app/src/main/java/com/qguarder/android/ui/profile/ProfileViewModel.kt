package com.qguarder.android.ui.profile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.local.TokenManager
import com.qguarder.android.data.local.UserPreferences
import com.qguarder.android.data.remote.AuthRepository
import com.qguarder.android.data.remote.LogsRepository
import com.qguarder.android.data.remote.dto.ScanSummaryDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class ProfileUiState {
    object Idle    : ProfileUiState()
    object Loading : ProfileUiState()
    data class Error(val message: String) : ProfileUiState()
}

@HiltViewModel
class ProfileViewModel @Inject constructor(
    private val authRepository:  AuthRepository,
    private val logsRepository:  LogsRepository,
    private val tokenManager:    TokenManager,
    private val userPreferences: UserPreferences,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ProfileUiState>(ProfileUiState.Idle)
    val uiState: StateFlow<ProfileUiState> = _uiState.asStateFlow()

    // 일회성 이벤트 — SharedFlow (extraBufferCapacity=1: emit 손실 방지)
    private val _logoutSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val logoutSuccess: SharedFlow<Unit> = _logoutSuccess

    private val _nicknameUpdateSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val nicknameUpdateSuccess: SharedFlow<Unit> = _nicknameUpdateSuccess

    private val _passwordChangeSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val passwordChangeSuccess: SharedFlow<Unit> = _passwordChangeSuccess

    private val _accountDeleteSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val accountDeleteSuccess: SharedFlow<Unit> = _accountDeleteSuccess

    /** 인라인 에러 이벤트 — BottomSheet 내부 tv_error에 표시 */
    private val _errorEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val errorEvent: SharedFlow<String> = _errorEvent

    // 반응형 프로필 정보
    private val _nickname = MutableStateFlow(tokenManager.getNickname() ?: "사용자")
    val nickname: StateFlow<String> = _nickname.asStateFlow()

    private val _email = MutableStateFlow(tokenManager.getEmail() ?: "")
    val email: StateFlow<String> = _email.asStateFlow()

    val avatarLetter: String get() = _nickname.value.firstOrNull()?.uppercaseChar()?.toString() ?: "Q"

    // 사용자 환경설정 (UserPreferences → StateFlow)
    val darkModeEnabled: StateFlow<Boolean>  = userPreferences.darkModeEnabled
    val historyRetentionDays: StateFlow<Int> = userPreferences.historyRetentionDays

    // 스캔 요약 통계
    private val _scanStats = MutableStateFlow<ScanSummaryDto?>(null)
    val scanStats: StateFlow<ScanSummaryDto?> = _scanStats.asStateFlow()

    init {
        syncProfile()
        loadScanStats()
    }

    /** 스캔 요약 통계 로드 (페이지 크기 1 — summary만 필요) */
    private fun loadScanStats() {
        viewModelScope.launch {
            logsRepository.getLogs(page = 1, size = 1)
                .onSuccess { data -> _scanStats.value = data.summary }
        }
    }

    /** 서버에서 최신 프로필 동기화 */
    private fun syncProfile() {
        viewModelScope.launch {
            authRepository.fetchAndSaveProfile()
                .onSuccess {
                    _nickname.value = tokenManager.getNickname() ?: "사용자"
                    _email.value    = tokenManager.getEmail()    ?: ""
                }
        }
    }

    fun logout() {
        viewModelScope.launch {
            _uiState.value = ProfileUiState.Loading
            authRepository.logout()
            _uiState.value = ProfileUiState.Idle
            _logoutSuccess.emit(Unit)
        }
    }

    /** 닉네임 변경 */
    fun updateNickname(nickname: String) {
        if (nickname.length < 2 || nickname.length > 20) {
            viewModelScope.launch { _errorEvent.emit("닉네임은 2자 이상 20자 이하여야 합니다") }
            return
        }
        viewModelScope.launch {
            _uiState.value = ProfileUiState.Loading
            authRepository.updateNickname(nickname)
                .onSuccess {
                    // 서버가 성공을 확인했으므로 서버 응답값 대신 입력값으로 즉시 반영
                    // (목 서버가 구 닉네임을 그대로 돌려줘도 UI가 항상 최신값을 표시)
                    _nickname.value = nickname
                    _uiState.value  = ProfileUiState.Idle
                    _nicknameUpdateSuccess.emit(Unit)
                }
                .onFailure { e ->
                    _uiState.value = ProfileUiState.Idle
                    _errorEvent.emit(e.message ?: "닉네임 변경에 실패했습니다")
                }
        }
    }

    /** 비밀번호 변경 (성공 시 로그아웃 필요) */
    fun updatePassword(currentPassword: String, newPassword: String, confirmPassword: String) {
        when {
            currentPassword.isBlank() -> {
                viewModelScope.launch { _errorEvent.emit("현재 비밀번호를 입력해주세요") }
                return
            }
            newPassword.length < 8 -> {
                viewModelScope.launch { _errorEvent.emit("새 비밀번호는 8자 이상이어야 합니다") }
                return
            }
            newPassword != confirmPassword -> {
                viewModelScope.launch { _errorEvent.emit("새 비밀번호가 일치하지 않습니다") }
                return
            }
        }
        viewModelScope.launch {
            _uiState.value = ProfileUiState.Loading
            authRepository.updatePassword(currentPassword, newPassword)
                .onSuccess {
                    // 비밀번호 변경 후 서버 토큰 무효화 → 로컬 세션도 삭제 후 재로그인 유도
                    authRepository.logout()
                    _uiState.value = ProfileUiState.Idle
                    _passwordChangeSuccess.emit(Unit)
                }
                .onFailure { e ->
                    _uiState.value = ProfileUiState.Idle
                    _errorEvent.emit(e.message ?: "비밀번호 변경에 실패했습니다")
                }
        }
    }

    /** 회원 탈퇴 */
    fun deleteAccount(password: String) {
        if (password.isBlank()) {
            viewModelScope.launch { _errorEvent.emit("비밀번호를 입력해주세요") }
            return
        }
        viewModelScope.launch {
            _uiState.value = ProfileUiState.Loading
            authRepository.deleteAccount(password)
                .onSuccess {
                    _uiState.value = ProfileUiState.Idle
                    _accountDeleteSuccess.emit(Unit)
                }
                .onFailure { e ->
                    _uiState.value = ProfileUiState.Idle
                    _errorEvent.emit(e.message ?: "회원 탈퇴에 실패했습니다")
                }
        }
    }

    /** 다크모드 토글 */
    fun setDarkMode(enabled: Boolean) {
        userPreferences.setDarkMode(enabled)
    }

    /** 히스토리 보관 기간 설정 */
    fun setHistoryRetention(days: Int) {
        userPreferences.setHistoryRetention(days)
    }
}
