package com.qguarder.android.ui.register

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.remote.AuthRepository
import com.qguarder.android.util.ValidationUtils
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed class RegisterUiState {
    object Idle    : RegisterUiState()
    object Loading : RegisterUiState()
    data class Error(val message: String) : RegisterUiState()
    // Success는 StateFlow 재방출 방지를 위해 SharedFlow로 분리
}

@HiltViewModel
class RegisterViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow<RegisterUiState>(RegisterUiState.Idle)
    val uiState: StateFlow<RegisterUiState> = _uiState.asStateFlow()

    // 일회성 회원가입 성공 이벤트
    private val _registerSuccess = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val registerSuccess: SharedFlow<Unit> = _registerSuccess

    fun register(email: String, password: String, nickname: String) {
        // 로딩 중 중복 호출 방어
        if (_uiState.value is RegisterUiState.Loading) return

        // 입력값 검증
        if (email.isBlank()) {
            _uiState.value = RegisterUiState.Error("이메일을 입력해주세요")
            return
        }
        if (!ValidationUtils.isValidEmail(email.trim())) {
            _uiState.value = RegisterUiState.Error("올바른 이메일 형식이 아닙니다")
            return
        }
        if (password.length < 8) {
            _uiState.value = RegisterUiState.Error("비밀번호는 8자 이상 입력해주세요")
            return
        }
        if (nickname.isBlank()) {
            _uiState.value = RegisterUiState.Error("닉네임을 입력해주세요")
            return
        }
        if (nickname.trim().length > 20) {
            _uiState.value = RegisterUiState.Error("닉네임은 20자 이하로 입력해주세요")
            return
        }

        viewModelScope.launch {
            _uiState.value = RegisterUiState.Loading
            authRepository.register(email.trim(), password, nickname.trim()).fold(
                onSuccess = {
                    _uiState.value = RegisterUiState.Idle
                    _registerSuccess.emit(Unit)
                },
                onFailure = { _uiState.value = RegisterUiState.Error(it.message ?: "회원가입 실패") }
            )
        }
    }
}
